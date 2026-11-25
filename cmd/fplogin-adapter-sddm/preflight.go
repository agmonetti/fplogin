package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

const themeDropIn = "/etc/sddm.conf.d/90-fplogin.conf"
const sddmUnit = "sddm.service"

func loadFacts(req adapterv1.Request) (adapterv1.PreflightFacts, error) {
	var facts adapterv1.PreflightFacts
	if os.Getuid() == 0 || os.Geteuid() == 0 || req.Context.Elevated || req.Context.Root != "/" || string(req.Context.Platform["distribution"]) != `"arch"` || req.Context.Architecture != "x86_64" {
		return facts, fmt.Errorf("SDDM adapter requires read-only Arch x86_64 host context")
	}
	err := protocol.DecodeStrict(req.Context.Platform["inventory"], &facts, "packages", "services")
	if err != nil || facts.Packages == nil || facts.Services == nil {
		return facts, fmt.Errorf("unknown package or service inventory: %v", err)
	}
	return facts, nil
}

func detectSDDM(facts adapterv1.PreflightFacts) adapterv1.DetectedTarget {
	t := adapterv1.DetectedTarget{InstanceID: "sddm-local", DMID: "sddm", DisplayName: "SDDM (new installation)", Compatibility: "compatible", Confidence: "confirmed", Evidence: []json.RawMessage{}}
	stock, patched, unit := false, false, false
	for _, s := range facts.Services {
		if s.ServiceReference == sddmUnit {
			unit = true
			t.ServiceReferences = []string{sddmUnit}
		}
	}
	for _, p := range facts.Packages {
		if p.PackageReference != "sddm" && p.PackageReference != "sddm-fplogin" {
			continue
		}
		data, _ := json.Marshal(p)
		t.Evidence = append(t.Evidence, data)
		if p.Installed != "yes" {
			continue
		}
		t.PackageReferences = append(t.PackageReferences, p.PackageReference)
		stock = stock || p.PackageReference == "sddm"
		patched = patched || p.PackageReference == "sddm-fplogin"
		_ = json.Unmarshal(p.Version, &t.UpstreamVersion)
	}
	if stock || patched || unit {
		t.DisplayName = "SDDM"
	}
	if unit != (stock || patched) || stock && patched {
		t.Compatibility, t.Confidence = "unknown", "unknown"
	} else if patched || stock && !strings.HasPrefix(t.UpstreamVersion, "0.21.0-") {
		t.Compatibility = "incompatible"
	}
	return t
}

func targetState(facts adapterv1.PreflightFacts) adapterv1.DisplayManagerState {
	r := adapterv1.DisplayManagerState{Active: "no", Enabled: "no", Configurable: "yes"}
	for _, service := range facts.Services {
		if service.ServiceReference == sddmUnit {
			r.Active, r.Enabled, r.Configurable = service.Active, service.Enabled, service.Configurable
		} else if service.Enabled == "yes" || service.Active == "yes" {
			r.ConflictingInstances = append(r.ConflictingInstances, service.ServiceReference)
		}
	}
	return r
}

func prerequisites(facts adapterv1.PreflightFacts) (adapterv1.PrerequisiteReport, error) {
	for _, p := range facts.Packages {
		if p.PackageReference == "fprintd" && protocol.OneOf(p.Installed, "yes", "no") {
			status := "satisfied"
			if p.Installed == "no" {
				status = "missing"
			}
			return adapterv1.PrerequisiteReport{Findings: []adapterv1.PrerequisiteFinding{
				{PrerequisiteID: "package.fprintd", Status: status, Severity: "required", Evidence: p.Evidence, Remediation: protocol.Object{"package": json.RawMessage(`"fprintd"`)}},
				{PrerequisiteID: "hardware.fingerprint_reader", Status: "unknown", Severity: "required", Evidence: []protocol.Evidence{}, Remediation: protocol.Object{"message": json.RawMessage(`"Verify compatible reader and existing enrollment separately; preflight does not access hardware."`)}},
			}}, nil
		}
	}
	return adapterv1.PrerequisiteReport{}, fmt.Errorf("fprintd package state is unknown")
}

func planPreview(facts adapterv1.PreflightFacts, target adapterv1.DetectedTarget) (adapterv1.InstallPreview, error) {
	plan := adapterv1.InstallPreview{TargetInstanceID: target.InstanceID, Changes: []adapterv1.PreviewChange{}, Replacement: []string{}, Limitations: []string{
		"Preview only: artifact trust, the full dependency closure, and matching stock rollback package are not verified.",
		"Only packaged/recognized display managers and standard systemd graphical entry points are inspected; custom launch arrangements are not covered.",
		"Existing SDDM configuration and global PAM files must be preserved; verify package contents and effective theme precedence before activation.",
	}}
	state := targetState(facts)
	if state.Configurable != "yes" {
		return plan, fmt.Errorf("SDDM unit cannot be configured safely")
	}
	parent := filepath.Dir(themeDropIn)
	dir, err := os.Lstat(parent)
	if err != nil && !os.IsNotExist(err) || dir != nil && !dir.IsDir() {
		return plan, fmt.Errorf("unknown or unsafe theme directory %s: %v", parent, err)
	}
	if _, err := os.Lstat(themeDropIn); !os.IsNotExist(err) {
		return plan, fmt.Errorf("theme drop-in is occupied or unreadable: %s (%v)", themeDropIn, err)
	}
	add := func(action, name, detail string) {
		plan.Changes = append(plan.Changes, adapterv1.PreviewChange{Action: action, Resource: name, Detail: detail})
	}
	for _, p := range facts.Packages {
		if p.PackageReference == "fprintd" && p.Installed == "no" {
			add("install_package", "fprintd", "required dependency")
		}
	}
	detail := "private Sprint 3 build 0.21.0-3.1 (not staged)"
	if len(target.PackageReferences) != 0 {
		detail += "; replaces stock sddm " + target.UpstreamVersion
	}
	add("install_package", "sddm-fplogin", detail)
	if dir == nil {
		add("create_directory", parent, "root:root 0755")
	}
	add("create_file", themeDropIn, "[General]\nAutoFingerprintForLegacyThemes=true\n")
	for _, service := range facts.Services {
		if service.ServiceReference == sddmUnit {
			continue
		}
		if service.Enabled == "yes" || service.Active == "yes" {
			plan.Replacement = append(plan.Replacement, service.ServiceReference)
		}
		if service.Active == "yes" {
			add("stop_service", service.ServiceReference, "")
		}
		if service.Enabled == "yes" {
			add("disable_service", service.ServiceReference, "")
		}
	}
	if state.Enabled == "no" {
		add("enable_service", sddmUnit, "")
	}
	if state.Active == "yes" {
		add("restart_service", sddmUnit, "after package and configuration verification")
	} else {
		add("start_service", sddmUnit, "after package and configuration verification")
	}
	return plan, nil
}

func preflight(req adapterv1.Request) (json.RawMessage, error) {
	facts, err := loadFacts(req)
	if err != nil {
		return nil, err
	}
	t := detectSDDM(facts)
	if !req.Context.DryRun {
		t = detectSDDMLive(facts)
	}
	if req.Operation == "Detect" {
		return json.Marshal(adapterv1.DetectionReport{Targets: []adapterv1.DetectedTarget{t}})
	}
	var selected struct {
		Target adapterv1.DetectedTarget `json:"target"`
	}
	if err := json.Unmarshal(req.Payload, &selected); err != nil {
		return nil, err
	}
	if selected.Target.InstanceID != t.InstanceID || t.Compatibility != "compatible" {
		return nil, fmt.Errorf("selected SDDM target is not compatible with observed state")
	}
	switch req.Operation {
	case "InspectState":
		return json.Marshal(targetState(facts))
	case "CheckPrerequisites":
		r, err := prerequisitesForMode(facts, req.Context.DryRun)
		if err != nil {
			return nil, err
		}
		return json.Marshal(r)
	case "PlanInstall":
		var payload adapterv1.PlanInstallPayload
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return nil, err
		}
		if req.Context.DryRun {
			if len(payload.RequestedCapabilities) != 1 || payload.RequestedCapabilities[0] != "install.preview" {
				return nil, fmt.Errorf("only install.preview is supported in dry-run")
			}
			r, err := planPreview(facts, t)
			if err != nil {
				return nil, err
			}
			return json.Marshal(r)
		}
		r, err := planExecutableInstall(req, facts, t, payload)
		if err != nil {
			return nil, err
		}
		return json.Marshal(r)
	default:
		return nil, fmt.Errorf("unsupported preflight operation %q", req.Operation)
	}
}
