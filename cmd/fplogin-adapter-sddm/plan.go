package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

const (
	themeDropInContent = "[General]\nAutoFingerprintForLegacyThemes=true\n"
	pamFingerprintPath = "/etc/pam.d/sddm-fingerprint"
	canonicalPlanTime  = "2026-01-01T00:00:00Z"
)

func genericPAMFingerprintContent() []byte {
	// Reuse the host's /etc/pam.d/sddm non-auth stacks when readable so the
	// generated sddm-fingerprint PAM service matches Debian, Ubuntu, Fedora,
	// openSUSE, or Arch conventions without distro-specific hardcoding.
	if data, err := os.ReadFile("/etc/pam.d/sddm"); err == nil {
		var lines []string
		lines = append(lines, "#%PAM-1.0", "auth       required   pam_fprintd.so")
		for _, raw := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "auth") {
				continue
			}
			lines = append(lines, raw)
		}
		if len(lines) > 2 {
			return []byte(strings.Join(lines, "\n") + "\n")
		}
	}
	return []byte("#%PAM-1.0\nauth       required   pam_fprintd.so\naccount    include    system-login\npassword   include    system-login\nsession    include    system-login\n")
}

type artifactMeta struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

func detectSDDMLive(facts adapterv1.PreflightFacts) adapterv1.DetectedTarget {
	t := detectSDDM(facts)
	hasPatched := false
	hasStock := false
	for _, ref := range t.PackageReferences {
		if ref == "sddm-fplogin" {
			hasPatched = true
		}
		if ref == "sddm" {
			hasStock = true
		}
	}
	if hasPatched && !hasStock && t.Confidence == "confirmed" &&
		(strings.HasPrefix(t.UpstreamVersion, "0.21.0-") || t.UpstreamVersion == "compatible") {
		t.DisplayName = "SDDM (fplogin)"
		t.Compatibility = "compatible"
	}
	return t
}

func prerequisitesForMode(facts adapterv1.PreflightFacts, dryRun bool) (adapterv1.PrerequisiteReport, error) {
	r, err := prerequisites(facts)
	if err != nil || dryRun {
		return r, err
	}
	for i := range r.Findings {
		if r.Findings[i].PrerequisiteID == "hardware.fingerprint_reader" {
			// Hardware is not probed at install time; password login remains
			// usable even when no fingerprint sensor is attached yet.
			r.Findings[i].Severity = "optional"
		}
	}
	return r, nil
}

// qt5DepPriority puts Qt5 runtime dependencies in pacman offline install order.
var qt5DepPriority = map[string]int{
	"qt5-translations":   1,
	"qt5-base":           2,
	"qt5-declarative":    3,
	"qt5-quickcontrols2": 4,
	"qt5-svg":            5,
}

func planExecutableInstall(req adapterv1.Request, facts adapterv1.PreflightFacts, target adapterv1.DetectedTarget, payload adapterv1.PlanInstallPayload) (adapterv1.ChangePlan, error) {
	var zero adapterv1.ChangePlan
	state := targetState(facts)
	if state.Configurable != "yes" {
		return zero, fmt.Errorf("SDDM unit cannot be configured safely")
	}

	activate := false
	if raw := req.Context.Platform["activate"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &activate); err != nil {
			return zero, fmt.Errorf("invalid activate context: %w", err)
		}
	}

	if isGenericLinux(req) {
		return planGenericLinuxInstall(req, facts, target, state, payload, activate)
	}

	var artifacts []artifactMeta
	if err := json.Unmarshal(req.Context.Platform["artifacts"], &artifacts); err != nil || len(artifacts) == 0 {
		return zero, fmt.Errorf("executable install requires offline signed artifacts metadata")
	}
	installedPkgs := map[string]string{}
	if raw := req.Context.Platform["installed_packages"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &installedPkgs); err != nil {
			return zero, fmt.Errorf("invalid installed_packages context: %w", err)
		}
	}

	byPkg := make(map[string]artifactMeta, len(artifacts))
	for _, a := range artifacts {
		if a.Package == "" || a.Version == "" || a.Size <= 0 || protocol.ValidDigest(a.SHA256) != nil {
			return zero, fmt.Errorf("invalid artifact metadata for %q", a.Package)
		}
		if _, dup := byPkg[a.Package]; dup {
			return zero, fmt.Errorf("duplicate artifact for package %q", a.Package)
		}
		if a.MediaType == "" {
			a.MediaType = "application/octet-stream"
		}
		byPkg[a.Package] = a
	}

	cand, hasCand := byPkg["sddm-fplogin"]
	if !hasCand {
		return zero, fmt.Errorf("missing sddm-fplogin artifact")
	}

	parent := filepath.Dir(themeDropIn)
	if st, err := os.Lstat(parent); err != nil || !st.IsDir() {
		return zero, fmt.Errorf("theme drop-in directory %s is missing or unsafe: %v", parent, err)
	}

	stockInstalledVer, hasStock := installedPkgs["sddm"]
	patchedInstalledVer, hasPatched := installedPkgs["sddm-fplogin"]
	for _, p := range facts.Packages {
		if p.PackageReference == "sddm" && p.Installed == "yes" {
			hasStock = true
			_ = json.Unmarshal(p.Version, &stockInstalledVer)
		}
		if p.PackageReference == "sddm-fplogin" && p.Installed == "yes" {
			hasPatched = true
			_ = json.Unmarshal(p.Version, &patchedInstalledVer)
		}
	}

	var stockArt artifactMeta
	if hasStock {
		var ok bool
		stockArt, ok = byPkg["sddm"]
		if !ok || (stockInstalledVer != "" && stockArt.Version != stockInstalledVer) {
			return zero, fmt.Errorf("stock sddm %q replacement requires matching signed sddm rollback archive", stockInstalledVer)
		}
	}

	// Order dependency packages deterministically before sddm-fplogin.
	var deps []artifactMeta
	for name, meta := range byPkg {
		if name == "sddm" || name == "sddm-fplogin" {
			continue
		}
		deps = append(deps, meta)
	}
	sort.Slice(deps, func(i, j int) bool {
		pi, pj := qt5DepPriority[deps[i].Package], qt5DepPriority[deps[j].Package]
		if pi != pj {
			if pi == 0 {
				return false
			}
			if pj == 0 {
				return true
			}
			return pi < pj
		}
		return deps[i].Package < deps[j].Package
	})

	var refs []adapterv1.ArtifactReference
	var ops []protocol.Operation
	for _, dep := range deps {
		role := "package"
		if strings.HasPrefix(dep.Package, "qt5-") {
			role = "shared_dependency"
		}
		refs = append(refs, adapterv1.ArtifactReference{
			ArtifactID:    dep.Package,
			Role:          role,
			SHA256:        dep.SHA256,
			Size:          dep.Size,
			CanonicalPath: "/staged/" + dep.SHA256,
			MediaType:     dep.MediaType,
		})
		preInstalled := installedPkgs[dep.Package] == dep.Version
		ops = append(ops, protocol.Operation{
			OperationID:    "pkg-" + dep.Package,
			Kind:           protocol.InstallPackageArtifact,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"installed": json.RawMessage(fmt.Sprintf("%t", preInstalled))},
			ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`true`)},
			Parameters:     json.RawMessage(fmt.Sprintf(`{"package_reference":%q,"artifact_id":%q,"sha256":%q}`, dep.Package, dep.Package, dep.SHA256)),
			Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"remove_package","package_reference":%q}`, dep.Package)),
		})
	}

	refs = append(refs, adapterv1.ArtifactReference{
		ArtifactID:    "sddm-fplogin",
		Role:          "display_manager_package",
		SHA256:        cand.SHA256,
		Size:          cand.Size,
		CanonicalPath: "/staged/" + cand.SHA256,
		MediaType:     cand.MediaType,
	})
	if hasStock {
		refs = append(refs, adapterv1.ArtifactReference{
			ArtifactID:    "sddm",
			Role:          "rollback_package",
			SHA256:        stockArt.SHA256,
			Size:          stockArt.Size,
			CanonicalPath: "/staged/" + stockArt.SHA256,
			MediaType:     stockArt.MediaType,
		})
	}

	candPreInstalled := hasPatched && patchedInstalledVer == cand.Version
	candVerJSON, _ := json.Marshal(cand.Version)
	candComp := json.RawMessage(`{"kind":"remove_package","package_reference":"sddm-fplogin"}`)
	if hasStock {
		candComp = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"sddm","artifact_id":"sddm","sha256":%q}`, stockArt.SHA256))
	}
	ops = append(ops, protocol.Operation{
		OperationID:    "pkg-sddm-fplogin",
		Kind:           protocol.InstallPackageArtifact,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"installed": json.RawMessage(fmt.Sprintf("%t", candPreInstalled))},
		ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`true`), "version": candVerJSON},
		Parameters:     json.RawMessage(fmt.Sprintf(`{"package_reference":"sddm-fplogin","artifact_id":"sddm-fplogin","sha256":%q}`, cand.SHA256)),
		Compensation:   candComp,
	})

	themeBytes := []byte(themeDropInContent)
	ops = append(ops, protocol.Operation{
		OperationID:    "write-theme",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{},
		ExpectedAfter:  protocol.Object{},
		Parameters: json.RawMessage(fmt.Sprintf(
			`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
			themeDropIn, base64.StdEncoding.EncodeToString(themeBytes), calcSHA256(themeBytes),
		)),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"remove_file","path":%q}`, themeDropIn)),
	})

	// Service operations strictly follow all package and file operations.
	var conflicting []platformv1.ServiceCandidate
	for _, svc := range facts.Services {
		if svc.ServiceReference == sddmUnit {
			continue
		}
		if svc.Enabled == "yes" || svc.Active == "yes" {
			conflicting = append(conflicting, svc)
		}
	}
	sort.Slice(conflicting, func(i, j int) bool {
		return conflicting[i].ServiceReference < conflicting[j].ServiceReference
	})
	approvals := []adapterv1.Approval{}
	for _, svc := range conflicting {
		approvals = append(approvals, adapterv1.Approval{
			ID:        "replace-dm-" + svc.ServiceReference,
			Statement: fmt.Sprintf("Disable conflicting display manager %s before enabling %s", svc.ServiceReference, sddmUnit),
			RiskLevel: "high",
		})
		if activate && svc.Active == "yes" {
			ops = append(ops, protocol.Operation{
				OperationID:    "stop-" + svc.ServiceReference,
				Kind:           protocol.SetServiceActive,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"active": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"active": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(fmt.Sprintf(`{"service_reference":%q,"active":false}`, svc.ServiceReference)),
				Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_active","service_reference":%q,"active":true}`, svc.ServiceReference)),
			})
		}
		if svc.Enabled == "yes" {
			ops = append(ops, protocol.Operation{
				OperationID:    "disable-" + svc.ServiceReference,
				Kind:           protocol.SetServiceEnabled,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(fmt.Sprintf(`{"service_reference":%q,"enabled":false}`, svc.ServiceReference)),
				Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_enabled","service_reference":%q,"enabled":true}`, svc.ServiceReference)),
			})
		}
	}

	sddmEnabled := state.Enabled == "yes"
	ops = append(ops, protocol.Operation{
		OperationID:    "enable-sddm",
		Kind:           protocol.SetServiceEnabled,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", sddmEnabled))},
		ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`true`)},
		Parameters:     json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`),
		Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":%t}`, sddmEnabled)),
	})
	if activate {
		sddmActive := state.Active == "yes"
		ops = append(ops, protocol.Operation{
			OperationID:    "start-sddm",
			Kind:           protocol.SetServiceActive,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"active": json.RawMessage(fmt.Sprintf("%t", sddmActive))},
			ExpectedAfter:  protocol.Object{"active": json.RawMessage(`true`)},
			Parameters:     json.RawMessage(`{"service_reference":"sddm.service","active":true}`),
			Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_active","service_reference":"sddm.service","active":%t}`, sddmActive)),
		})
	}

	mode := payload.Mode
	if mode == "" {
		mode = "fresh_install"
	}

	type normPkg struct {
		Ref       string          `json:"ref"`
		Installed string          `json:"installed"`
		Version   json.RawMessage `json:"version"`
	}
	type normSvc struct {
		Ref          string   `json:"ref"`
		Enabled      string   `json:"enabled"`
		Active       string   `json:"active"`
		Configurable string   `json:"configurable"`
		Packages     []string `json:"packages,omitempty"`
	}
	normPkgs := make([]normPkg, 0, len(facts.Packages))
	for _, p := range facts.Packages {
		normPkgs = append(normPkgs, normPkg{Ref: p.PackageReference, Installed: p.Installed, Version: p.Version})
	}
	normSvcs := make([]normSvc, 0, len(facts.Services))
	for _, s := range facts.Services {
		normSvcs = append(normSvcs, normSvc{Ref: s.ServiceReference, Enabled: s.Enabled, Active: s.Active, Configurable: s.Configurable, Packages: s.PackageReferences})
	}

	inputRaw, _ := json.Marshal(struct {
		Packages  []normPkg      `json:"packages"`
		Services  []normSvc      `json:"services"`
		Artifacts []artifactMeta `json:"artifacts"`
		Target    string         `json:"target"`
		Mode      string         `json:"mode"`
		Activate  bool           `json:"activate"`
	}{normPkgs, normSvcs, artifacts, target.InstanceID, mode, activate})
	inputHash := calcSHA256(inputRaw)

	canonicalRaw, _ := json.Marshal(struct {
		Refs []adapterv1.ArtifactReference `json:"refs"`
		Ops  []protocol.Operation          `json:"ops"`
		Mode string                        `json:"mode"`
	}{refs, ops, mode})
	canonicalDigest := calcSHA256(canonicalRaw)

	plan := adapterv1.ChangePlan{
		PlanID:               "sddm-" + canonicalDigest[:16],
		AdapterID:            "org.fplogin.adapter.sddm",
		AdapterVersion:       "0.1.0",
		ProtocolVersion:      req.ProtocolVersion,
		TargetInstanceID:     target.InstanceID,
		Mode:                 mode,
		CreatedAt:            canonicalPlanTime,
		InputHash:            inputHash,
		CanonicalPlanDigest:  canonicalDigest,
		Approvals:            approvals,
		Preconditions:        []adapterv1.Condition{},
		Postconditions:       []adapterv1.Condition{},
		ArtifactReferences:   refs,
		Operations:           ops,
		ExpectedCapabilities: []string{"biometric_auth"},
	}
	if err := plan.Validate(); err != nil {
		return zero, fmt.Errorf("invalid generated change plan: %w", err)
	}
	return plan, nil
}

func planGenericLinuxInstall(
	req adapterv1.Request,
	facts adapterv1.PreflightFacts,
	target adapterv1.DetectedTarget,
	state adapterv1.DisplayManagerState,
	payload adapterv1.PlanInstallPayload,
	activate bool,
) (adapterv1.ChangePlan, error) {
	var zero adapterv1.ChangePlan
	hasCompatible := false
	for _, p := range facts.Packages {
		if p.PackageReference == "sddm-fplogin" && p.Installed == "yes" {
			hasCompatible = true
		}
	}
	if !hasCompatible {
		return zero, fmt.Errorf("no fingerprint-capable SDDM binary detected; install a patched/upstream SDDM build first")
	}

	var ops []protocol.Operation
	themeBytes := []byte(themeDropInContent)
	ops = append(ops, protocol.Operation{
		OperationID:    "write-theme",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{},
		ExpectedAfter:  protocol.Object{},
		Parameters: json.RawMessage(fmt.Sprintf(
			`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
			themeDropIn, base64.StdEncoding.EncodeToString(themeBytes), calcSHA256(themeBytes),
		)),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"remove_file","path":%q}`, themeDropIn)),
	})

	pamBytes := genericPAMFingerprintContent()
	ops = append(ops, protocol.Operation{
		OperationID:    "write-pam-sddm-fingerprint",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{},
		ExpectedAfter:  protocol.Object{},
		Parameters: json.RawMessage(fmt.Sprintf(
			`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
			pamFingerprintPath, base64.StdEncoding.EncodeToString(pamBytes), calcSHA256(pamBytes),
		)),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"remove_file","path":%q}`, pamFingerprintPath)),
	})

	var conflicting []platformv1.ServiceCandidate
	for _, svc := range facts.Services {
		if svc.ServiceReference == sddmUnit {
			continue
		}
		if svc.Enabled == "yes" || svc.Active == "yes" {
			conflicting = append(conflicting, svc)
		}
	}
	sort.Slice(conflicting, func(i, j int) bool {
		return conflicting[i].ServiceReference < conflicting[j].ServiceReference
	})
	approvals := []adapterv1.Approval{}
	for _, svc := range conflicting {
		approvals = append(approvals, adapterv1.Approval{
			ID:        "replace-dm-" + svc.ServiceReference,
			Statement: fmt.Sprintf("Disable conflicting display manager %s before enabling %s", svc.ServiceReference, sddmUnit),
			RiskLevel: "high",
		})
		if activate && svc.Active == "yes" {
			ops = append(ops, protocol.Operation{
				OperationID:    "stop-" + svc.ServiceReference,
				Kind:           protocol.SetServiceActive,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"active": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"active": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(fmt.Sprintf(`{"service_reference":%q,"active":false}`, svc.ServiceReference)),
				Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_active","service_reference":%q,"active":true}`, svc.ServiceReference)),
			})
		}
		if svc.Enabled == "yes" {
			ops = append(ops, protocol.Operation{
				OperationID:    "disable-" + svc.ServiceReference,
				Kind:           protocol.SetServiceEnabled,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(fmt.Sprintf(`{"service_reference":%q,"enabled":false}`, svc.ServiceReference)),
				Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_enabled","service_reference":%q,"enabled":true}`, svc.ServiceReference)),
			})
		}
	}

	sddmEnabled := state.Enabled == "yes"
	ops = append(ops, protocol.Operation{
		OperationID:    "enable-sddm",
		Kind:           protocol.SetServiceEnabled,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", sddmEnabled))},
		ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`true`)},
		Parameters:     json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`),
		Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":%t}`, sddmEnabled)),
	})
	if activate {
		sddmActive := state.Active == "yes"
		ops = append(ops, protocol.Operation{
			OperationID:    "start-sddm",
			Kind:           protocol.SetServiceActive,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"active": json.RawMessage(fmt.Sprintf("%t", sddmActive))},
			ExpectedAfter:  protocol.Object{"active": json.RawMessage(`true`)},
			Parameters:     json.RawMessage(`{"service_reference":"sddm.service","active":true}`),
			Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"set_service_active","service_reference":"sddm.service","active":%t}`, sddmActive)),
		})
	}

	mode := payload.Mode
	if mode == "" {
		mode = "fresh_install"
	}
	refs := []adapterv1.ArtifactReference{}
	inputRaw, _ := json.Marshal(struct {
		Target   string `json:"target"`
		Mode     string `json:"mode"`
		Activate bool   `json:"activate"`
		Dist     string `json:"dist"`
	}{target.InstanceID, mode, activate, "linux"})
	canonicalRaw, _ := json.Marshal(struct {
		Refs []adapterv1.ArtifactReference `json:"refs"`
		Ops  []protocol.Operation          `json:"ops"`
		Mode string                        `json:"mode"`
	}{refs, ops, mode})
	canonicalDigest := calcSHA256(canonicalRaw)

	plan := adapterv1.ChangePlan{
		PlanID:               "sddm-linux-" + canonicalDigest[:16],
		AdapterID:            "org.fplogin.adapter.sddm",
		AdapterVersion:       "0.1.0",
		ProtocolVersion:      req.ProtocolVersion,
		TargetInstanceID:     target.InstanceID,
		Mode:                 mode,
		CreatedAt:            canonicalPlanTime,
		InputHash:            calcSHA256(inputRaw),
		CanonicalPlanDigest:  canonicalDigest,
		Approvals:            approvals,
		Preconditions:        []adapterv1.Condition{},
		Postconditions:       []adapterv1.Condition{},
		ArtifactReferences:   refs,
		Operations:           ops,
		ExpectedCapabilities: []string{"biometric_auth"},
	}
	if err := plan.Validate(); err != nil {
		return zero, fmt.Errorf("invalid generated change plan: %w", err)
	}
	return plan, nil
}

func verifyInstall(req adapterv1.Request) (json.RawMessage, error) {
	if os.Getuid() == 0 || os.Geteuid() == 0 || req.Context.Elevated || req.Context.Root != "/" {
		return nil, fmt.Errorf("SDDM Verify requires unprivileged context on canonical root /")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	checks := []adapterv1.VerificationCheck{}

	// 1. Verify patched SDDM is installed (via pacman on Arch, or binary check on generic Linux).
	pkgCheck := adapterv1.VerificationCheck{
		CheckID:  "pkg.sddm_fplogin",
		Severity: "required",
		Status:   "failed",
		Evidence: []protocol.Evidence{},
	}
	if isGenericLinux(req) {
		for _, p := range []string{"/usr/bin/sddm", "/usr/sbin/sddm", "/usr/local/bin/sddm"} {
			if data, err := os.ReadFile(p); err == nil && bytes.Contains(data, []byte("AutoFingerprintForLegacyThemes")) {
				pkgCheck.Status = "passed"
				pkgCheck.Evidence = append(pkgCheck.Evidence, protocol.Evidence{
					Source: "adapter", Kind: "binary", Subject: p,
					Timestamp: now, ObservedValue: "AutoFingerprintForLegacyThemes",
				})
				break
			}
		}
	} else {
		c := exec.Command("/usr/bin/pacman", "--config", "/dev/null", "-Q")
		c.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
		out, err := c.Output()
		if err == nil {
			lines := "\n" + strings.TrimSpace(string(out)) + "\n"
			hasCand := strings.Contains(lines, "\nsddm-fplogin ")
			hasStock := strings.Contains(lines, "\nsddm ")
			if hasCand && !hasStock {
				pkgCheck.Status = "passed"
				pkgCheck.Evidence = append(pkgCheck.Evidence, protocol.Evidence{
					Source: "adapter", Kind: "package", Subject: "sddm-fplogin",
					Timestamp: now, ObservedValue: "installed",
				})
			} else {
				pkgCheck.Evidence = append(pkgCheck.Evidence, protocol.Evidence{
					Source: "adapter", Kind: "package", Subject: "sddm-fplogin",
					Timestamp: now, ObservedValue: fmt.Sprintf("sddm-fplogin=%t sddm=%t", hasCand, hasStock),
				})
			}
		}
	}
	checks = append(checks, pkgCheck)

	// 2. Verify theme drop-in file exists with exact canonical content.
	themeCheck := adapterv1.VerificationCheck{
		CheckID:  "file.theme_dropin",
		Severity: "required",
		Status:   "failed",
		Evidence: []protocol.Evidence{},
	}
	if f, err := os.OpenFile(themeDropIn, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0); err == nil {
		st, statErr := f.Stat()
		var buf bytes.Buffer
		if statErr == nil && st.Mode().IsRegular() && st.Size() <= 4096 {
			_, _ = buf.ReadFrom(f)
		}
		f.Close()
		if buf.String() == themeDropInContent {
			themeCheck.Status = "passed"
			themeCheck.Evidence = append(themeCheck.Evidence, protocol.Evidence{
				Source: "adapter", Kind: "path", Subject: themeDropIn,
				Timestamp: now, ObservedValue: "canonical",
			})
		}
	}
	checks = append(checks, themeCheck)

	// 3. Verify required SDDM artifacts exist.
	requiredPaths := []string{
		"/usr/bin/sddm",
		"/usr/lib/sddm/sddm-helper",
		"/etc/pam.d/sddm-fingerprint",
		"/usr/share/sddm/themes/fplogin/metadata.desktop",
	}
	if isGenericLinux(req) {
		requiredPaths = []string{pamFingerprintPath, themeDropIn}
	}
	artCheck := adapterv1.VerificationCheck{
		CheckID:  "file.sddm_artifacts",
		Severity: "required",
		Status:   "passed",
		Evidence: []protocol.Evidence{},
	}
	for _, p := range requiredPaths {
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			artCheck.Status = "failed"
			artCheck.Evidence = append(artCheck.Evidence, protocol.Evidence{
				Source: "adapter", Kind: "path", Subject: p,
				Timestamp: now, ObservedValue: "missing_or_invalid",
			})
		} else {
			artCheck.Evidence = append(artCheck.Evidence, protocol.Evidence{
				Source: "adapter", Kind: "path", Subject: p,
				Timestamp: now, ObservedValue: "present",
			})
		}
	}
	checks = append(checks, artCheck)

	report := adapterv1.VerificationReport{
		ReportID:   "sddm-verify-" + req.RequestID,
		VerifiedAt: now,
		Checks:     checks,
	}
	return json.Marshal(report)
}
