// Binary fplogin-platform-linux implements a distro-agnostic Linux (systemd)
// Platform Provider following protocol/platform/v1. It has zero package-manager
// dependency (no pacman/apt/dnf) and works on any systemd Linux distribution
// with fprintd and a fingerprint-capable SDDM installation.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

const staticPlatformDescriptor = `{
  "descriptor_schema_version": "1.0",
  "platform_id": "org.fplogin.platform.linux",
  "platform_version": "0.1.0",
  "protocol_versions": [
    {
      "major": 1,
      "minor": 0
    }
  ],
  "minimum_core_version": "0.1.0",
  "name": "Generic Linux (systemd) Platform Provider",
  "vendor": "fplogin",
  "executable": "bin/fplogin-platform-linux",
  "supported_platforms": [
    {
      "distribution": "linux",
      "architecture": "x86_64"
    },
    {
      "distribution": "linux",
      "architecture": "aarch64"
    }
  ],
  "capabilities": [
    {
      "id": "host.inspect",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "os_release"
      ]
    },
    {
      "id": "package.query",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "binary_probe"
      ]
    },
    {
      "id": "service.query",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "systemd"
      ]
    },
    {
      "id": "analyzer.facts",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "binary_probe",
        "systemd"
      ]
    }
  ],
  "operation_kinds": [
    "set_service_enabled",
    "set_service_active",
    "restore_service_state"
  ],
  "package_formats": [],
  "service_manager": {
    "kind": "systemd",
    "capabilities": [
      "status",
      "alias"
    ]
  },
  "asset_root": "assets"
}`

var (
	sddmBinaryPaths = []string{
		"/usr/bin/sddm",
		"/usr/sbin/sddm",
		"/usr/local/bin/sddm",
	}
	fprintdBinaryPaths = []string{
		"/usr/bin/fprintd-list",
		"/usr/libexec/fprintd",
		"/usr/lib/fprintd/fprintd",
		"/usr/lib/x86_64-linux-gnu/fprintd",
		"/usr/lib/aarch64-linux-gnu/fprintd",
	}
	pamFprintdPaths = []string{
		"/usr/lib/security/pam_fprintd.so",
		"/usr/lib64/security/pam_fprintd.so",
		"/usr/lib/x86_64-linux-gnu/security/pam_fprintd.so",
		"/usr/lib/aarch64-linux-gnu/security/pam_fprintd.so",
		"/lib/x86_64-linux-gnu/security/pam_fprintd.so",
		"/lib/aarch64-linux-gnu/security/pam_fprintd.so",
		"/lib64/security/pam_fprintd.so",
	}
	knownDMUnits = []string{
		"sddm.service",
		"gdm.service",
		"gdm3.service",
		"lightdm.service",
		"greetd.service",
		"lxdm.service",
		"xdm.service",
		"ly.service",
	}
)

const sddmFingerprintMarker = "AutoFingerprintForLegacyThemes"

type opError struct {
	code    string
	message string
}

func (e *opError) Error() string { return e.message }

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		emitError("00000000-0000-0000-0000-000000000000", protocol.Version{Major: 1, Minor: 0}, "internal_error", err.Error())
		os.Exit(1)
	}
	req, err := platformv1.DecodeRequest(input)
	if err != nil {
		emitError("00000000-0000-0000-0000-000000000000", protocol.Version{Major: 1, Minor: 0}, "invalid_request", err.Error())
		os.Exit(1)
	}
	res, err := handleRequest(req)
	if err != nil {
		code := "internal_error"
		var known *opError
		if errors.As(err, &known) {
			code = known.code
		}
		emitError(req.RequestID, req.ProtocolVersion, code, err.Error())
		os.Exit(0)
	}
	emitSuccess(req.RequestID, req.ProtocolVersion, res)
}

func handleRequest(req platformv1.Request) (json.RawMessage, error) {
	switch req.Operation {
	case "Describe":
		return json.RawMessage(staticPlatformDescriptor), nil
	case "InspectHost":
		report, err := inspectHost()
		if err != nil {
			return nil, &opError{code: "host_read_failed", message: err.Error()}
		}
		return json.Marshal(report)
	case "ListPackageCandidates":
		return listBinaryCandidates("/")
	case "ListServiceCandidates":
		return listServiceCandidates(context.Background())
	case "CollectAnalyzerFacts":
		return collectAnalyzerFacts(req)
	case "ApplyOperation":
		return applyServiceOperation(req)
	case "VerifyOperation":
		return json.Marshal(map[string]any{"verified": true, "evidence": []protocol.Evidence{}})
	default:
		return nil, &opError{code: "unsupported_operation", message: fmt.Sprintf("operation %q is not supported by generic linux provider", req.Operation)}
	}
}

func osReleaseID(paths ...string) string {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ID="); ok {
				return strings.Trim(value, `"'`)
			}
		}
	}
	return "linux"
}

func evidence(kind, subject, observed string) protocol.Evidence {
	return protocol.Evidence{
		Source:        "platform",
		Kind:          kind,
		Subject:       subject,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		ObservedValue: observed,
	}
}

func inspectHost() (platformv1.PlatformHostReport, error) {
	osID := osReleaseID("/etc/os-release", "/usr/lib/os-release")
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	}
	encodedDist, _ := json.Marshal("linux")
	encodedOSID, _ := json.Marshal(osID)
	return platformv1.PlatformHostReport{
		Architecture:     arch,
		Platform:         protocol.Object{"distribution": encodedDist, "os_id": encodedOSID},
		PackageManager:   json.RawMessage(`{"kind":"none"}`),
		ServiceManager:   json.RawMessage(`{"kind":"systemd"}`),
		FilesystemPolicy: protocol.Object{},
		Packages:         []platformv1.PackageCandidate{},
		Services:         []platformv1.ServiceCandidate{},
		Evidence:         []protocol.Evidence{evidence("path", "os-release", osID)},
	}, nil
}

func firstExistingPath(root string, candidates []string) string {
	for _, p := range candidates {
		full := p
		if root != "" && root != "/" {
			full = filepath.Join(root, strings.TrimPrefix(p, "/"))
		}
		if st, err := os.Stat(full); err == nil && !st.IsDir() {
			return full
		}
	}
	return ""
}

// binaryContainsMarker scans a binary up to 32 MiB for a literal ASCII marker
// without invoking external tools like strings(1).
func binaryContainsMarker(path string, marker []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	const maxScan = 32 << 20
	const chunkSize = 256 * 1024
	overlap := len(marker) - 1
	buf := make([]byte, chunkSize+overlap)
	carry := 0
	var total int64
	for total < maxScan {
		n, err := f.Read(buf[carry:])
		if n > 0 {
			window := buf[:carry+n]
			if bytes.Contains(window, marker) {
				return true
			}
			total += int64(n)
			if len(window) >= overlap {
				copy(buf[:overlap], window[len(window)-overlap:])
				carry = overlap
			} else {
				copy(buf[:len(window)], window)
				carry = len(window)
			}
		}
		if err != nil {
			break
		}
	}
	return false
}

func listBinaryCandidates(root string) (json.RawMessage, error) {
	var pkgs []platformv1.PackageCandidate

	sddmPath := firstExistingPath(root, sddmBinaryPaths)
	if sddmPath != "" {
		if binaryContainsMarker(sddmPath, []byte(sddmFingerprintMarker)) {
			pkgs = append(pkgs, platformv1.PackageCandidate{
				PackageReference: "sddm-fplogin",
				Installed:        "yes",
				Version:          json.RawMessage(`"compatible"`),
				Evidence:         []protocol.Evidence{evidence("path", sddmPath, "AutoFingerprintForLegacyThemes")},
			})
		} else {
			pkgs = append(pkgs, platformv1.PackageCandidate{
				PackageReference: "sddm",
				Installed:        "yes",
				Version:          json.RawMessage(`"stock"`),
				Evidence:         []protocol.Evidence{evidence("path", sddmPath, "unpatched")},
			})
		}
	}

	fprintdPath := firstExistingPath(root, fprintdBinaryPaths)
	pamPath := firstExistingPath(root, pamFprintdPaths)
	fprintdInstalled := "no"
	ev := []protocol.Evidence{}
	if fprintdPath != "" {
		ev = append(ev, evidence("path", fprintdPath, "present"))
	}
	if pamPath != "" {
		ev = append(ev, evidence("path", pamPath, "present"))
	}
	if fprintdPath != "" && pamPath != "" {
		fprintdInstalled = "yes"
	}
	pkgs = append(pkgs, platformv1.PackageCandidate{
		PackageReference: "fprintd",
		Installed:        fprintdInstalled,
		Version:          json.RawMessage(`null`),
		Evidence:         ev,
	})

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PackageReference < pkgs[j].PackageReference })
	return json.Marshal(map[string]any{"packages": pkgs})
}

func findSystemctl() (string, error) {
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return exec.LookPath("systemctl")
}

func runSystemctl(ctx context.Context, args ...string) (string, error) {
	systemctl, err := findSystemctl()
	if err != nil {
		return "", err
	}
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        10 * time.Second,
		MaxInputBytes:  1,
		MaxStdoutBytes: 1 << 20,
		MaxStderrBytes: 16384,
		Arguments:      args,
		Environment:    []string{"LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"},
	})
	if err != nil {
		return "", err
	}
	res, err := runner.Run(ctx, systemctl, nil)
	if err != nil {
		return string(res.Stdout), fmt.Errorf("systemctl %v: %w (stderr=%q)", args, err, strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

func parseSystemctlShow(unit, out string) (loadState, activeState, unitFileState string) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			loadState = v
		case "ActiveState":
			activeState = v
		case "UnitFileState":
			unitFileState = v
		}
	}
	_ = unit
	return
}

func listServiceCandidates(ctx context.Context) (json.RawMessage, error) {
	services := []platformv1.ServiceCandidate{}
	for _, unit := range knownDMUnits {
		out, err := runSystemctl(ctx, "show", "--no-pager", "--property=LoadState,ActiveState,UnitFileState", unit)
		if err != nil {
			continue
		}
		loadState, activeState, fileState := parseSystemctlShow(unit, out)
		if loadState == "" || loadState == "not-found" {
			continue
		}
		active := "no"
		if activeState == "active" || activeState == "activating" {
			active = "yes"
		}
		enabled := "no"
		if fileState == "enabled" || fileState == "enabled-runtime" || fileState == "linked" || fileState == "static" {
			enabled = "yes"
		}
		configurable := "yes"
		if fileState == "masked" || fileState == "masked-runtime" {
			configurable = "no"
		}
		services = append(services, platformv1.ServiceCandidate{
			ServiceReference: unit,
			Active:           active,
			Enabled:          enabled,
			Configurable:     configurable,
			Evidence:         []protocol.Evidence{evidence("service", unit, fmt.Sprintf("load=%s active=%s file=%s", loadState, activeState, fileState))},
		})
	}
	return json.Marshal(map[string]any{"services": services})
}

func collectAnalyzerFacts(req platformv1.Request) (json.RawMessage, error) {
	if req.Context.Root != "/" {
		return nil, &opError{code: "host_read_failed", message: "analyzer probes require local root /"}
	}
	var payload platformv1.CollectAnalyzerFactsPayload
	if err := protocol.DecodeStrict(req.Payload, &payload, "scope", "probe_ids"); err != nil {
		return nil, &opError{code: "invalid_request", message: err.Error()}
	}
	fprintdBin := firstExistingPath("/", fprintdBinaryPaths)
	pamMod := firstExistingPath("/", pamFprintdPaths)
	facts := platformv1.PlatformAnalyzerFacts{
		Scope:       payload.Scope,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Evidence:    []protocol.Evidence{},
		ProbeErrors: []platformv1.ProbeError{},
	}
	if fprintdBin != "" {
		facts.Evidence = append(facts.Evidence, evidence("path", fprintdBin, "present"))
	} else {
		facts.Evidence = append(facts.Evidence, evidence("path", "fprintd", "missing"))
	}
	if pamMod != "" {
		facts.Evidence = append(facts.Evidence, evidence("path", pamMod, "present"))
	} else {
		facts.Evidence = append(facts.Evidence, evidence("path", "pam_fprintd.so", "missing"))
	}
	if err := facts.Validate(); err != nil {
		return nil, &opError{code: "internal_error", message: fmt.Sprintf("invalid analyzer facts: %v", err)}
	}
	return json.Marshal(facts)
}

func applyServiceOperation(req platformv1.Request) (json.RawMessage, error) {
	if os.Geteuid() != 0 {
		return nil, &opError{code: "mutation_failed", message: "ApplyOperation requires root privileges"}
	}
	var payload platformv1.ApplyOperationPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return nil, &opError{code: "invalid_request", message: err.Error()}
	}
	op := payload.Operation
	started := time.Now().UTC().Format(time.RFC3339)

	var unit string
	var params map[string]any
	if err := json.Unmarshal(op.Parameters, &params); err != nil {
		return nil, &opError{code: "invalid_request", message: err.Error()}
	}
	if u, ok := params["service_reference"].(string); ok && u != "" {
		unit = u
	} else if u, ok := params["unit"].(string); ok {
		unit = u
	}
	if unit == "" || strings.ContainsAny(unit, "/\\ \t\n") {
		return nil, &opError{code: "invalid_request", message: fmt.Sprintf("invalid systemd unit %q", unit)}
	}

	ctx := context.Background()
	beforeOut, _ := runSystemctl(ctx, "show", "--no-pager", "--property=LoadState,ActiveState,UnitFileState", unit)
	_, beforeActive, beforeFile := parseSystemctlShow(unit, beforeOut)

	var cmdArgs []string
	switch op.Kind {
	case protocol.SetServiceEnabled:
		if enabled, _ := params["enabled"].(bool); enabled {
			cmdArgs = []string{"enable", "--force", unit}
		} else {
			cmdArgs = []string{"disable", unit}
		}
	case protocol.SetServiceActive:
		if active, _ := params["active"].(bool); active {
			cmdArgs = []string{"start", unit}
		} else {
			cmdArgs = []string{"stop", unit}
		}
	case protocol.RestoreServiceState:
		if s, _ := params["enabled"].(string); s == "yes" {
			if _, err := runSystemctl(ctx, "enable", "--force", unit); err != nil {
				return nil, &opError{code: "mutation_failed", message: err.Error()}
			}
		} else if s == "no" {
			if _, err := runSystemctl(ctx, "disable", unit); err != nil {
				return nil, &opError{code: "mutation_failed", message: err.Error()}
			}
		}
		if s, _ := params["active"].(string); s == "yes" {
			cmdArgs = []string{"start", unit}
		} else if s == "no" {
			cmdArgs = []string{"stop", unit}
		}
	default:
		return nil, &opError{code: "unsupported_operation", message: fmt.Sprintf("generic linux provider does not support %q", op.Kind)}
	}

	if len(cmdArgs) > 0 {
		if _, err := runSystemctl(ctx, cmdArgs...); err != nil {
			return nil, &opError{code: "mutation_failed", message: err.Error()}
		}
	}

	afterOut, _ := runSystemctl(ctx, "show", "--no-pager", "--property=LoadState,ActiveState,UnitFileState", unit)
	_, afterActive, afterFile := parseSystemctlShow(unit, afterOut)
	completed := time.Now().UTC().Format(time.RFC3339)

	toObj := func(m map[string]any) protocol.Object {
		o := protocol.Object{}
		for k, v := range m {
			b, _ := json.Marshal(v)
			o[k] = b
		}
		return o
	}
	beforeEnabled := beforeFile == "enabled" || beforeFile == "enabled-runtime"
	beforeAct := beforeActive == "active"
	afterEnabled := afterFile == "enabled" || afterFile == "enabled-runtime"
	afterAct := afterActive == "active"

	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	var beforeState, afterState, compState protocol.Object
	if op.Kind == protocol.RestoreServiceState {
		beforeState = toObj(map[string]any{"service_reference": unit, "enabled": yn(beforeEnabled), "active": yn(beforeAct)})
		afterState = toObj(map[string]any{"service_reference": unit, "enabled": yn(afterEnabled), "active": yn(afterAct)})
		compState = toObj(map[string]any{"service_reference": unit, "enabled": yn(beforeEnabled), "active": yn(beforeAct)})
	} else {
		beforeState = toObj(map[string]any{"service_reference": unit, "enabled": beforeEnabled, "active": beforeAct})
		afterState = toObj(map[string]any{"service_reference": unit, "enabled": afterEnabled, "active": afterAct})
		compState = toObj(map[string]any{"service_reference": unit, "enabled": beforeEnabled, "active": beforeAct})
	}

	receipt := platformv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		StartedAt:    started,
		CompletedAt:  completed,
		Status:       "success",
		BeforeState:  beforeState,
		AfterState:   afterState,
		Compensation: compState,
	}
	return json.Marshal(receipt)
}

func emitSuccess(reqID string, pv protocol.Version, result json.RawMessage) {
	_ = json.NewEncoder(os.Stdout).Encode(platformv1.Response{
		ProtocolVersion: pv,
		RequestID:       reqID,
		OK:              true,
		Result:          result,
	})
}

func emitError(reqID string, pv protocol.Version, code, message string) {
	_ = json.NewEncoder(os.Stdout).Encode(platformv1.Response{
		ProtocolVersion: pv,
		RequestID:       reqID,
		OK:              false,
		Error: &platformv1.PlatformError{
			Code:      code,
			Message:   message,
			Retryable: false,
			Evidence:  []protocol.Evidence{},
		},
	})
}
