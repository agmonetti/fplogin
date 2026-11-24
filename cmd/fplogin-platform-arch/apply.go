package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fplogin/internal/protocol"
	v1 "fplogin/internal/protocol/platform/v1"
)

func applyLab(req v1.Request) (json.RawMessage, error) {
	trust, err := resolveTrust(req.Operation)
	if err != nil {
		return nil, err
	}
	if req.Context.Root != "/" || os.Geteuid() != 0 {
		return nil, &opError{code: "mutation_failed", message: "platform apply requires root on canonical root /"}
	}
	var p v1.ApplyOperationPayload
	if err := json.Unmarshal(req.Payload, &p); err != nil {
		return nil, &opError{code: "invalid_request", message: err.Error()}
	}
	if err := p.Operation.Validate(); err != nil {
		return nil, &opError{code: "invalid_request", message: err.Error()}
	}
	startedAt := time.Now().UTC().Format(time.RFC3339)

	var receipt v1.OperationReceipt
	switch p.Operation.Kind {
	case protocol.InstallPackageArtifact:
		receipt, err = applyInstallPackage(trust, p, startedAt)
	case protocol.RemoveOwnedPackage:
		receipt, err = applyRemovePackage(trust, p, startedAt)
	case protocol.SetServiceEnabled:
		receipt, err = applySetServiceEnabled(p, startedAt)
	case protocol.SetServiceActive:
		receipt, err = applySetServiceActive(p, startedAt)
	case protocol.RestoreServiceState:
		receipt, err = applyRestoreServiceState(p, startedAt)
	default:
		return nil, notImplemented(string(p.Operation.Kind))
	}
	if err != nil {
		return nil, &opError{code: "mutation_failed", message: err.Error()}
	}
	receipt.OperationID = p.Operation.OperationID
	receipt.Kind = p.Operation.Kind
	receipt.StartedAt = startedAt
	receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	receipt.Status = "success"
	receipt.Compensation = toObject(p.Operation.Compensation)
	return json.Marshal(receipt)
}

func labCombined(path string, args ...string) (string, error) {
	c := exec.Command(path, args...)
	c.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
	b, err := c.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func queryInstalledPackage(pkgName string) (bool, string, error) {
	// Query full local inventory instead of -Q <name>: pacman -Q <name> matches
	// virtual provides (e.g., sddm-fplogin provides sddm).
	out, err := labOutput("/usr/bin/pacman", "--config", "/dev/null", "-Q")
	if err != nil {
		return false, "", fmt.Errorf("pacman -Q: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		name, ver, ok := strings.Cut(line, " ")
		if ok && name == pkgName {
			if ver == "" {
				return false, "", fmt.Errorf("empty version for %s", pkgName)
			}
			return true, ver, nil
		}
	}
	return false, "", nil
}

func packageStateObject(installed bool, ver string) protocol.Object {
	obj := protocol.Object{
		"installed": json.RawMessage(fmt.Sprintf("%t", installed)),
	}
	if installed {
		encoded, _ := json.Marshal(ver)
		obj["version"] = encoded
	}
	return obj
}

func applyInstallPackage(trust trustConfig, p v1.ApplyOperationPayload, _ string) (v1.OperationReceipt, error) {
	var params protocol.PackageArtifactParameters
	if err := json.Unmarshal(p.Operation.Parameters, &params); err != nil {
		return v1.OperationReceipt{}, err
	}
	var ref struct {
		CanonicalPath string `json:"canonical_path"`
		SHA256        string `json:"sha256,omitempty"`
	}
	if len(p.PreparedArtifactReference) == 0 || json.Unmarshal(p.PreparedArtifactReference, &ref) != nil {
		return v1.OperationReceipt{}, fmt.Errorf("missing prepared_artifact_reference for %s", params.PackageReference)
	}
	if ref.SHA256 != "" && ref.SHA256 != params.SHA256 {
		return v1.OperationReceipt{}, fmt.Errorf("prepared_artifact_reference digest mismatch for %s", params.PackageReference)
	}
	pkgNameVer, err := verifyStagedArchive(trust, ref.CanonicalPath, params.SHA256)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	pkgName, pkgVer, ok := strings.Cut(pkgNameVer, " ")
	if !ok || params.PackageReference != pkgName {
		return v1.OperationReceipt{}, fmt.Errorf("package_reference %q does not match verified archive %q", params.PackageReference, pkgNameVer)
	}
	beforeInstalled, beforeVer, err := queryInstalledPackage(pkgName)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	beforeState := packageStateObject(beforeInstalled, beforeVer)
	if beforeInstalled && beforeVer == pkgVer {
		if pkgName == "sddm" {
			if err := checkStockFiles(); err != nil {
				return v1.OperationReceipt{}, err
			}
		}
		return v1.OperationReceipt{
			BeforeState: beforeState,
			AfterState:  beforeState,
			Evidence:    []protocol.Evidence{evidence("package", pkgName, pkgVer)},
		}, nil
	}
	if pkgName == "sddm-fplogin" {
		stockInstalled, _, err := queryInstalledPackage("sddm")
		if err != nil {
			return v1.OperationReceipt{}, err
		}
		if stockInstalled || beforeInstalled {
			if err := checkStockFiles(); err != nil {
				return v1.OperationReceipt{}, err
			}
		} else {
			if err := checkStockFilesAbsentOrIntact(); err != nil {
				return v1.OperationReceipt{}, err
			}
		}
	}
	out, err := labCombined("/usr/bin/pacman", "--config", filepath.Join(trust.dir, "pacman.conf"), "--gpgdir", filepath.Join(trust.dir, "public"), "-U", "--noconfirm", "--ask=4", "--", ref.CanonicalPath)
	if err != nil {
		return v1.OperationReceipt{}, fmt.Errorf("pacman -U %s failed: %v: %s", pkgName, err, out)
	}
	afterInstalled, afterVer, err := queryInstalledPackage(pkgName)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	if !afterInstalled || afterVer != pkgVer {
		return v1.OperationReceipt{}, fmt.Errorf("post-install check failed for %s: installed=%t version=%q", pkgName, afterInstalled, afterVer)
	}
	if pkgName == "sddm-fplogin" {
		if stockStill, _, err := queryInstalledPackage("sddm"); err != nil || stockStill {
			return v1.OperationReceipt{}, fmt.Errorf("stock sddm still present after installing %s", pkgName)
		}
		if err := checkStockFiles(); err != nil {
			return v1.OperationReceipt{}, fmt.Errorf("stock backup files changed during replacement: %w", err)
		}
	}
	if pkgName == "sddm" {
		if candStill, _, err := queryInstalledPackage("sddm-fplogin"); err != nil || candStill {
			return v1.OperationReceipt{}, fmt.Errorf("sddm-fplogin still present after restoring stock sddm")
		}
		if err := checkStockFiles(); err != nil {
			return v1.OperationReceipt{}, fmt.Errorf("stock backup files do not match after rollback: %w", err)
		}
	}
	return v1.OperationReceipt{
		BeforeState: beforeState,
		AfterState:  packageStateObject(afterInstalled, afterVer),
		Evidence:    []protocol.Evidence{evidence("package", pkgName, afterVer)},
	}, nil
}

func isOwnedRemovablePackage(pkgName string) bool {
	if pkgName == "sddm" {
		return false
	}
	for _, nameVer := range baselinePackages {
		if name, _, ok := strings.Cut(nameVer, " "); ok && name == pkgName {
			return true
		}
	}
	return false
}

func applyRemovePackage(trust trustConfig, p v1.ApplyOperationPayload, _ string) (v1.OperationReceipt, error) {
	var params struct {
		PackageReference string `json:"package_reference"`
	}
	if err := json.Unmarshal(p.Operation.Parameters, &params); err != nil {
		return v1.OperationReceipt{}, err
	}
	if !isOwnedRemovablePackage(params.PackageReference) {
		return v1.OperationReceipt{}, fmt.Errorf("package %q is not an owned removable package", params.PackageReference)
	}
	beforeInstalled, beforeVer, err := queryInstalledPackage(params.PackageReference)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	beforeState := packageStateObject(beforeInstalled, beforeVer)
	if !beforeInstalled {
		return v1.OperationReceipt{
			BeforeState: beforeState,
			AfterState:  beforeState,
			Evidence:    []protocol.Evidence{evidence("package", params.PackageReference, "absent")},
		}, nil
	}
	out, err := labCombined("/usr/bin/pacman", "--config", filepath.Join(trust.dir, "pacman.conf"), "-R", "--noconfirm", "--", params.PackageReference)
	if err != nil {
		return v1.OperationReceipt{}, fmt.Errorf("pacman -R %s failed: %v: %s", params.PackageReference, err, out)
	}
	afterInstalled, afterVer, err := queryInstalledPackage(params.PackageReference)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	if afterInstalled {
		return v1.OperationReceipt{}, fmt.Errorf("package %s (%s) still installed after removal", params.PackageReference, afterVer)
	}
	return v1.OperationReceipt{
		BeforeState: beforeState,
		AfterState:  packageStateObject(false, ""),
		Evidence:    []protocol.Evidence{evidence("package", params.PackageReference, "removed")},
	}, nil
}

func queryServiceEnabled(service string) (bool, error) {
	c := exec.Command("/usr/bin/systemctl", "is-enabled", "--", service)
	c.Env = []string{"LC_ALL=C", "PATH=/usr/bin", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	state := strings.TrimSpace(stdout.String())
	if err == nil && state == "enabled" {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && state == "disabled" {
		return false, nil
	}
	return false, fmt.Errorf("systemctl is-enabled %s: state=%q err=%v stderr=%q", service, state, err, strings.TrimSpace(stderr.String()))
}

func isAllowedDMService(unit string) bool {
	for _, known := range dmUnits {
		if unit == known {
			return true
		}
	}
	return false
}

func applySetServiceEnabled(p v1.ApplyOperationPayload, _ string) (v1.OperationReceipt, error) {
	var params struct {
		ServiceReference string `json:"service_reference"`
		Enabled          *bool  `json:"enabled"`
	}
	if err := json.Unmarshal(p.Operation.Parameters, &params); err != nil {
		return v1.OperationReceipt{}, err
	}
	if !isAllowedDMService(params.ServiceReference) || params.Enabled == nil {
		return v1.OperationReceipt{}, fmt.Errorf("unsupported service_reference %q", params.ServiceReference)
	}
	beforeEnabled, err := queryServiceEnabled(params.ServiceReference)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	if beforeEnabled != *params.Enabled {
		action := "disable"
		if *params.Enabled {
			action = "enable"
		}
		if out, err := labCombined("/usr/bin/systemctl", action, "--", params.ServiceReference); err != nil {
			return v1.OperationReceipt{}, fmt.Errorf("systemctl %s %s failed: %v: %s", action, params.ServiceReference, err, out)
		}
	}
	afterEnabled, err := queryServiceEnabled(params.ServiceReference)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	if afterEnabled != *params.Enabled {
		return v1.OperationReceipt{}, fmt.Errorf("service %s enabled state=%t, want %t", params.ServiceReference, afterEnabled, *params.Enabled)
	}
	return v1.OperationReceipt{
		BeforeState: protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", beforeEnabled))},
		AfterState:  protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", afterEnabled))},
		Evidence:    []protocol.Evidence{evidence("service", params.ServiceReference, fmt.Sprintf("enabled=%t", afterEnabled))},
	}, nil
}

func queryServiceActive(service string) (bool, error) {
	c := exec.Command("/usr/bin/systemctl", "is-active", "--", service)
	c.Env = []string{"LC_ALL=C", "PATH=/usr/bin", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	state := strings.TrimSpace(stdout.String())
	if err == nil && state == "active" {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 && state == "inactive" && strings.TrimSpace(stderr.String()) == "" {
		return false, nil
	}
	return false, fmt.Errorf("systemctl is-active %s: state=%q err=%v stderr=%q", service, state, err, strings.TrimSpace(stderr.String()))
}

func applySetServiceActive(p v1.ApplyOperationPayload, _ string) (v1.OperationReceipt, error) {
	var params struct {
		ServiceReference string `json:"service_reference"`
		Active           *bool  `json:"active"`
	}
	if err := json.Unmarshal(p.Operation.Parameters, &params); err != nil {
		return v1.OperationReceipt{}, err
	}
	if !isAllowedDMService(params.ServiceReference) || params.Active == nil {
		return v1.OperationReceipt{}, fmt.Errorf("unsupported service_reference %q", params.ServiceReference)
	}
	beforeActive, err := queryServiceActive(params.ServiceReference)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	if beforeActive != *params.Active {
		action := "stop"
		if *params.Active {
			action = "start"
		}
		if out, err := labCombined("/usr/bin/systemctl", action, "--", params.ServiceReference); err != nil {
			return v1.OperationReceipt{}, fmt.Errorf("systemctl %s %s failed: %v: %s", action, params.ServiceReference, err, out)
		}
	}
	afterActive, err := queryServiceActive(params.ServiceReference)
	if err != nil {
		return v1.OperationReceipt{}, err
	}
	if afterActive != *params.Active {
		return v1.OperationReceipt{}, fmt.Errorf("service %s active state=%t, want %t", params.ServiceReference, afterActive, *params.Active)
	}
	return v1.OperationReceipt{
		BeforeState: protocol.Object{"active": json.RawMessage(fmt.Sprintf("%t", beforeActive))},
		AfterState:  protocol.Object{"active": json.RawMessage(fmt.Sprintf("%t", afterActive))},
		Evidence:    []protocol.Evidence{evidence("service", params.ServiceReference, fmt.Sprintf("active=%t", afterActive))},
	}, nil
}

func triStateBool(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func applyRestoreServiceState(p v1.ApplyOperationPayload, _ string) (v1.OperationReceipt, error) {
	var params struct {
		ServiceReference string `json:"service_reference"`
		Enabled          string `json:"enabled"`
		Active           string `json:"active"`
	}
	if err := json.Unmarshal(p.Operation.Parameters, &params); err != nil {
		return v1.OperationReceipt{}, err
	}
	if !isAllowedDMService(params.ServiceReference) {
		return v1.OperationReceipt{}, fmt.Errorf("unsupported service_reference %q", params.ServiceReference)
	}

	beforeObj := protocol.Object{}
	afterObj := protocol.Object{}
	var ev []protocol.Evidence

	if params.Enabled == "yes" || params.Enabled == "no" {
		wantEnabled := params.Enabled == "yes"
		beforeEnabled, err := queryServiceEnabled(params.ServiceReference)
		if err != nil {
			return v1.OperationReceipt{}, err
		}
		beforeObj["enabled"] = json.RawMessage(fmt.Sprintf("%q", triStateBool(beforeEnabled)))
		if beforeEnabled != wantEnabled {
			action := "disable"
			if wantEnabled {
				action = "enable"
			}
			if out, err := labCombined("/usr/bin/systemctl", action, "--", params.ServiceReference); err != nil {
				return v1.OperationReceipt{}, fmt.Errorf("systemctl %s %s failed: %v: %s", action, params.ServiceReference, err, out)
			}
		}
		afterEnabled, err := queryServiceEnabled(params.ServiceReference)
		if err != nil {
			return v1.OperationReceipt{}, err
		}
		if afterEnabled != wantEnabled {
			return v1.OperationReceipt{}, fmt.Errorf("service %s enabled=%t, want %t", params.ServiceReference, afterEnabled, wantEnabled)
		}
		afterObj["enabled"] = json.RawMessage(fmt.Sprintf("%q", triStateBool(afterEnabled)))
		ev = append(ev, evidence("service", params.ServiceReference, fmt.Sprintf("enabled=%s", params.Enabled)))
	}

	if params.Active == "yes" || params.Active == "no" {
		wantActive := params.Active == "yes"
		beforeActive, err := queryServiceActive(params.ServiceReference)
		if err != nil {
			return v1.OperationReceipt{}, err
		}
		beforeObj["active"] = json.RawMessage(fmt.Sprintf("%q", triStateBool(beforeActive)))
		if beforeActive != wantActive {
			action := "stop"
			if wantActive {
				action = "start"
			}
			if out, err := labCombined("/usr/bin/systemctl", action, "--", params.ServiceReference); err != nil {
				return v1.OperationReceipt{}, fmt.Errorf("systemctl %s %s failed: %v: %s", action, params.ServiceReference, err, out)
			}
		}
		afterActive, err := queryServiceActive(params.ServiceReference)
		if err != nil {
			return v1.OperationReceipt{}, err
		}
		if afterActive != wantActive {
			return v1.OperationReceipt{}, fmt.Errorf("service %s active=%t, want %t", params.ServiceReference, afterActive, wantActive)
		}
		afterObj["active"] = json.RawMessage(fmt.Sprintf("%q", triStateBool(afterActive)))
		ev = append(ev, evidence("service", params.ServiceReference, fmt.Sprintf("active=%s", params.Active)))
	}

	return v1.OperationReceipt{
		BeforeState: beforeObj,
		AfterState:  afterObj,
		Evidence:    ev,
	}, nil
}
