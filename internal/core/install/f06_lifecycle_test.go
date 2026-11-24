package install

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"fplogin/internal/core/discovery"
	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	a "fplogin/internal/protocol/adapter/v1"
	m "fplogin/internal/protocol/manifest/v1"
	p "fplogin/internal/protocol/platform/v1"
)

type f06Provider struct {
	*fakePlatformInvoker
	t          *testing.T
	installed  map[string]string
	services   map[string]bool
	failOpID   string
	mutatedOps []string
}

func (s *f06Provider) PrepareArtifactInstall(_ context.Context, _ discovery.Provider, payload p.PrepareArtifactInstallPayload, _ protocol.HostContext) error {
	for _, r := range payload.ArtifactReferences {
		if _, err := os.Stat(r.CanonicalPath); err != nil {
			return fmt.Errorf("missing staged artifact %q: %w", r.ArtifactID, err)
		}
		if _, err := os.Stat(r.CanonicalPath + ".sig"); err != nil {
			return fmt.Errorf("missing staged signature %q: %w", r.ArtifactID, err)
		}
	}
	return nil
}

func (s *f06Provider) ApplyPreparedOperation(_ context.Context, req PlatformOperationRequest) (m.OperationReceipt, error) {
	op := req.Operation
	if s.failOpID != "" && op.OperationID == s.failOpID {
		return m.OperationReceipt{}, fmt.Errorf("injected failure on %s", op.OperationID)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	r := m.OperationReceipt{
		OperationID: op.OperationID,
		Kind:        op.Kind,
		StartedAt:   now,
		CompletedAt: now,
		Status:      "success",
	}

	switch op.Kind {
	case protocol.InstallPackageArtifact:
		var params protocol.PackageArtifactParameters
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return r, err
		}
		if req.StageDir == "" {
			return r, errors.New("missing stage dir")
		}
		if _, err := os.Stat(filepath.Join(req.StageDir, params.SHA256)); err != nil {
			return r, fmt.Errorf("staged archive %q missing: %w", params.SHA256, err)
		}
		prevVer, existed := s.installed[params.PackageReference]
		r.BeforeState = protocol.Object{"installed": json.RawMessage(fmt.Sprintf("%t", existed))}
		if existed {
			v, _ := json.Marshal(prevVer)
			r.BeforeState["version"] = v
		}
		targetVer := "ver-" + params.SHA256[:8]
		if !existed || prevVer != targetVer {
			s.mutatedOps = append(s.mutatedOps, op.OperationID)
			if params.PackageReference == "sddm-fplogin" {
				delete(s.installed, "sddm")
			}
			if params.PackageReference == "sddm" {
				delete(s.installed, "sddm-fplogin")
			}
			s.installed[params.PackageReference] = targetVer
		}
		v, _ := json.Marshal(targetVer)
		r.AfterState = protocol.Object{"installed": json.RawMessage(`true`), "version": v}

	case protocol.RemoveOwnedPackage:
		var params struct {
			PackageReference string `json:"package_reference"`
		}
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return r, err
		}
		prevVer, existed := s.installed[params.PackageReference]
		r.BeforeState = protocol.Object{"installed": json.RawMessage(fmt.Sprintf("%t", existed))}
		if existed {
			v, _ := json.Marshal(prevVer)
			r.BeforeState["version"] = v
			s.mutatedOps = append(s.mutatedOps, op.OperationID)
			delete(s.installed, params.PackageReference)
		}
		r.AfterState = protocol.Object{"installed": json.RawMessage(`false`)}

	case protocol.SetServiceEnabled:
		var params struct {
			ServiceReference string `json:"service_reference"`
			Enabled          bool   `json:"enabled"`
		}
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return r, err
		}
		before := s.services[params.ServiceReference]
		r.BeforeState = protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", before))}
		if before != params.Enabled {
			s.mutatedOps = append(s.mutatedOps, op.OperationID)
			s.services[params.ServiceReference] = params.Enabled
		}
		r.AfterState = protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", s.services[params.ServiceReference]))}

	case protocol.RestoreServiceState:
		var params struct {
			ServiceReference string `json:"service_reference"`
			Enabled          string `json:"enabled"`
			Active           string `json:"active"`
		}
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return r, err
		}
		r.BeforeState = protocol.Object{}
		r.AfterState = protocol.Object{}
		if params.Enabled == "yes" || params.Enabled == "no" {
			before := s.services[params.ServiceReference]
			want := params.Enabled == "yes"
			bStr := "no"
			if before {
				bStr = "yes"
			}
			r.BeforeState["enabled"] = json.RawMessage(fmt.Sprintf("%q", bStr))
			if before != want {
				s.mutatedOps = append(s.mutatedOps, op.OperationID)
				s.services[params.ServiceReference] = want
			}
			r.AfterState["enabled"] = json.RawMessage(fmt.Sprintf("%q", params.Enabled))
		}
	default:
		return r, fmt.Errorf("unexpected op kind %s", op.Kind)
	}
	return r, nil
}

func setupF06Fixtures(t *testing.T, withPriorDM bool) (Config, *fakeAdapterInvoker, *f06Provider) {
	t.Helper()
	dir := t.TempDir()
	cfg, ad, pv := setupTestFixtures(dir)
	cfg.IsolatedArchiveCache = t.TempDir()

	services := map[string]bool{"sddm.service": false}
	if withPriorDM {
		services["lightdm.service"] = true
	}
	sp := &f06Provider{
		fakePlatformInvoker: pv,
		t:                   t,
		installed:           map[string]string{"sddm": "ver-stock"},
		services:            services,
	}
	cfg.PlatformInvoker = sp

	plan := &ad.plan
	fileOp := plan.Operations[0]
	plan.ArtifactReferences = nil
	for _, spec := range []struct{ id, role string }{
		{"qt5-dep", "shared_dependency"},
		{"sddm-fplogin", "display_manager_package"},
		{"sddm", "package"},
	} {
		hash := sha256Hex([]byte(spec.id))
		plan.ArtifactReferences = append(plan.ArtifactReferences, a.ArtifactReference{
			ArtifactID: spec.id, Size: int64(len(spec.id)), SHA256: hash,
			MediaType: "application/octet-stream", Role: spec.role, CanonicalPath: "/ignored",
		})
		path := filepath.Join(cfg.IsolatedArchiveCache, hash)
		for _, suffix := range []string{"", ".sig"} {
			if err := os.WriteFile(path+suffix, []byte(spec.id), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	qtOp := protocol.Operation{
		OperationID:    "pkg-qt5",
		Kind:           protocol.InstallPackageArtifact,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"installed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`true`)},
		Parameters:     json.RawMessage(fmt.Sprintf(`{"package_reference":"qt5-dep","artifact_id":"qt5-dep","sha256":%q}`, plan.ArtifactReferences[0].SHA256)),
		Compensation:   json.RawMessage(`{"kind":"remove_package","package_reference":"qt5-dep"}`),
	}
	candOp := protocol.Operation{
		OperationID:    "pkg-candidate",
		Kind:           protocol.InstallPackageArtifact,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"installed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`true`)},
		Parameters:     json.RawMessage(fmt.Sprintf(`{"package_reference":"sddm-fplogin","artifact_id":"sddm-fplogin","sha256":%q}`, plan.ArtifactReferences[1].SHA256)),
		Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"sddm","artifact_id":"sddm","sha256":%q}`, plan.ArtifactReferences[2].SHA256)),
	}

	ops := []protocol.Operation{qtOp, candOp, fileOp}
	if withPriorDM {
		ops = append(ops, protocol.Operation{
			OperationID:    "svc-disable-prior",
			Kind:           protocol.SetServiceEnabled,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`true`)},
			ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`false`)},
			Parameters:     json.RawMessage(`{"service_reference":"lightdm.service","enabled":false}`),
			Compensation:   json.RawMessage(`{"kind":"set_service_enabled","service_reference":"lightdm.service","enabled":true}`),
		})
	}
	ops = append(ops, protocol.Operation{
		OperationID:    "svc-enable-sddm",
		Kind:           protocol.SetServiceEnabled,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`true`)},
		Parameters:     json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`),
		Compensation:   json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":false}`),
	})
	plan.Operations = ops
	return cfg, ad, sp
}

func TestF06_RepeatInstallPreservesBaselineAndDistinguishesModes(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, ad, sp := setupF06Fixtures(t, true)
	ctx := context.Background()
	targetFile := cfg.IsolatedFiles[0]

	// Pre-existing file before fresh install with custom mode 0640.
	origBytes := []byte("[Theme]\nCurrent=stock\n")
	if err := os.WriteFile(targetFile, origBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	// 1. Fresh install
	res1, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("fresh install failed: %v", err)
	}
	if res1.Mode != "fresh_install" || res1.ManifestPath != cfg.ManifestPath {
		t.Fatalf("unexpected fresh install result: mode=%q manifest=%q", res1.Mode, res1.ManifestPath)
	}
	m1, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		t.Fatalf("load manifest after fresh install: %v", err)
	}
	if m1.AcceptedPlan.Mode != "fresh_install" || m1.PreviousDMState.ServiceName != "lightdm.service" || m1.PreviousDMState.Enabled != "yes" {
		t.Fatalf("unexpected fresh manifest DM state: %+v", m1.PreviousDMState)
	}
	if m1.RecoveryBaseline == nil || m1.RecoveryBaseline.BaselineTransactionID != res1.TransactionID {
		t.Fatalf("missing or wrong recovery baseline: %+v", m1.RecoveryBaseline)
	}
	if len(m1.InstalledPackages) != 2 || len(m1.InstalledFiles) != 1 || m1.InstalledFiles[0].SHA256 != sha256Hex([]byte("a")) {
		t.Fatalf("unexpected manifest records: files=%+v pkgs=%+v", m1.InstalledFiles, m1.InstalledPackages)
	}

	// Capture inode/mtime before repeat reinstall.
	infoBeforeReinstall, err := os.Lstat(targetFile)
	if err != nil {
		t.Fatal(err)
	}
	sp.mutatedOps = nil

	// 2. Repeat install (identical state) -> reinstall with ZERO unintended mutations
	res2, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("reinstall failed: %v", err)
	}
	if res2.Mode != "reinstall" {
		t.Fatalf("expected mode=reinstall, got %q", res2.Mode)
	}
	if len(sp.mutatedOps) != 0 {
		t.Fatalf("reinstall performed unintended platform mutations: %v", sp.mutatedOps)
	}
	infoAfterReinstall, err := os.Lstat(targetFile)
	if err != nil {
		t.Fatal(err)
	}
	if infoBeforeReinstall.Sys().(*syscall.Stat_t).Ino != infoAfterReinstall.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("reinstall unnecessarily rewrote unchanged target file")
	}
	m2, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if m2.AcceptedPlan.Mode != "reinstall" || !reflect.DeepEqual(m1.RecoveryBaseline, m2.RecoveryBaseline) {
		t.Fatalf("reinstall altered original recovery baseline:\nbefore=%+v\nafter=%+v", m1.RecoveryBaseline, m2.RecoveryBaseline)
	}

	// 3. Upgrade (new file content) -> upgrade, keeping original baseline intact
	upgradedBytes := []byte("upgraded-content")
	ad.plan.Operations[2].Parameters = json.RawMessage(fmt.Sprintf(
		`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
		targetFile, base64.StdEncoding.EncodeToString(upgradedBytes), sha256Hex(upgradedBytes),
	))
	res3, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	if res3.Mode != "upgrade" {
		t.Fatalf("expected mode=upgrade, got %q", res3.Mode)
	}
	m3, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if m3.AcceptedPlan.Mode != "upgrade" || m3.InstalledFiles[0].SHA256 != sha256Hex(upgradedBytes) {
		t.Fatalf("upgrade did not update installed file checksum: %+v", m3.InstalledFiles)
	}
	if !reflect.DeepEqual(m1.RecoveryBaseline, m3.RecoveryBaseline) {
		t.Fatalf("upgrade altered original recovery baseline:\nbefore=%+v\nafter=%+v", m1.RecoveryBaseline, m3.RecoveryBaseline)
	}

	// 4. Repair (file deleted or damaged) -> repair, keeping original baseline intact
	if err := os.WriteFile(targetFile, []byte("damaged"), 0o644); err != nil {
		t.Fatal(err)
	}
	res4, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	if res4.Mode != "repair" {
		t.Fatalf("expected mode=repair, got %q", res4.Mode)
	}
	m4, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m1.RecoveryBaseline, m4.RecoveryBaseline) {
		t.Fatalf("repair altered original recovery baseline")
	}
	if data, err := os.ReadFile(targetFile); err != nil || string(data) != string(upgradedBytes) {
		t.Fatalf("repair did not restore expected content: %q %v", data, err)
	}

	// 5. Uninstall WITHOUT any adapter -> restores pre-Run-1 baseline and keeps shared dependency
	uRes, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg.ManifestPath,
		IsolatedFiles: cfg.IsolatedFiles,
		Platform:      sp,
	})
	if err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}
	if !slices.Equal(uRes.KeptSharedPackages, []string{"qt5-dep"}) {
		t.Fatalf("expected qt5-dep kept by default, got %v", uRes.KeptSharedPackages)
	}
	if sp.installed["qt5-dep"] == "" || sp.installed["sddm"] == "" || sp.installed["sddm-fplogin"] != "" {
		t.Fatalf("unexpected packages after uninstall: %v", sp.installed)
	}
	if sp.services["sddm.service"] || !sp.services["lightdm.service"] {
		t.Fatalf("unexpected services after uninstall: %v", sp.services)
	}
	restoredBytes, restoredMode, err := readOrdinaryFile(targetFile)
	if err != nil || string(restoredBytes) != string(origBytes) || restoredMode != 0o640 {
		t.Fatalf("original file baseline not restored: %q %o %v", restoredBytes, restoredMode, err)
	}
	if _, err := os.Stat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manifest still exists after uninstall: %v", err)
	}

	// 6. Repeat uninstall makes no changes and reports ErrManifestNotFound
	sp.mutatedOps = nil
	if _, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg.ManifestPath,
		IsolatedFiles: cfg.IsolatedFiles,
		Platform:      sp,
	}); !errors.Is(err, manifest.ErrManifestNotFound) {
		t.Fatalf("expected ErrManifestNotFound on repeat uninstall, got %v", err)
	}
	if len(sp.mutatedOps) != 0 {
		t.Fatalf("repeat uninstall mutated platform state: %v", sp.mutatedOps)
	}
}

func TestF06_UninstallModifiedFilePolicies(t *testing.T) {
	requireUnprivilegedLab(t)
	ctx := context.Background()

	// Case 1: Refuse & Preserve policies
	cfg, _, sp := setupF06Fixtures(t, false)
	if _, err := Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	targetFile := cfg.IsolatedFiles[0]
	localEdit := []byte("# user local edit\n")
	if err := os.WriteFile(targetFile, localEdit, 0o644); err != nil {
		t.Fatal(err)
	}

	// ModifiedFileRefuse aborts before any mutation
	sp.mutatedOps = nil
	if _, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg.ManifestPath,
		IsolatedFiles: cfg.IsolatedFiles,
		Platform:      sp,
		ModifiedFiles: ModifiedFileRefuse,
	}); !errors.Is(err, manifest.ErrModifiedFiles) {
		t.Fatalf("expected ErrModifiedFiles, got %v", err)
	}
	if len(sp.mutatedOps) != 0 || sp.installed["sddm-fplogin"] == "" {
		t.Fatalf("refused uninstall mutated system: %v %v", sp.mutatedOps, sp.installed)
	}
	if _, err := manifest.Load(cfg.ManifestPath); err != nil {
		t.Fatalf("refused uninstall removed manifest: %v", err)
	}

	// Default (ModifiedFilePreserve) preserves user edit while restoring packages/services and removing manifest
	uRes, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg.ManifestPath,
		IsolatedFiles: cfg.IsolatedFiles,
		Platform:      sp,
	})
	if err != nil {
		t.Fatalf("preserve uninstall failed: %v", err)
	}
	if !slices.Equal(uRes.PreservedFiles, []string{targetFile}) {
		t.Fatalf("expected preserved file %q, got %v", targetFile, uRes.PreservedFiles)
	}
	if data, err := os.ReadFile(targetFile); err != nil || string(data) != string(localEdit) {
		t.Fatalf("modified file was not preserved: %q %v", data, err)
	}
	if sp.installed["sddm"] == "" || sp.installed["sddm-fplogin"] != "" || sp.services["sddm.service"] {
		t.Fatalf("packages/services not restored during preserve uninstall: %v %v", sp.installed, sp.services)
	}

	// Case 2: Explicit ModifiedFileRestore removes/restores modified file
	cfg2, _, sp2 := setupF06Fixtures(t, false)
	if _, err := Run(ctx, cfg2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg2.IsolatedFiles[0], localEdit, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg2.ManifestPath,
		IsolatedFiles: cfg2.IsolatedFiles,
		Platform:      sp2,
		ModifiedFiles: ModifiedFileRestore,
	}); err != nil {
		t.Fatalf("explicit restore uninstall failed: %v", err)
	}
	if _, err := os.Stat(cfg2.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("modified file not removed under ModifiedFileRestore: %v", err)
	}
}

func TestF06_UninstallFailedServiceRestoreKeepsManifestAndRollsBack(t *testing.T) {
	requireUnprivilegedLab(t)
	ctx := context.Background()
	cfg, _, sp := setupF06Fixtures(t, true)
	if _, err := Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	// Fail re-enabling the prior DM service AFTER sddm.service disable, file removal, and stock sddm install ran.
	sp.failOpID = "uninstall-svc-restore-0"
	_, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg.ManifestPath,
		IsolatedFiles: cfg.IsolatedFiles,
		Platform:      sp,
	})
	if !errors.Is(err, ErrTransactionAborted) {
		t.Fatalf("expected ErrTransactionAborted, got %v", err)
	}

	// Manifest MUST be kept and system rolled back to installed state matching manifest.
	if _, err := manifest.Load(cfg.ManifestPath); err != nil {
		t.Fatalf("manifest was not kept after failed service restore: %v", err)
	}
	if sp.installed["sddm-fplogin"] == "" || sp.installed["sddm"] != "" {
		t.Fatalf("package state not rolled back after failed uninstall: %v", sp.installed)
	}
	if !sp.services["sddm.service"] || sp.services["lightdm.service"] {
		t.Fatalf("service state not rolled back after failed uninstall: %v", sp.services)
	}
	if data, err := os.ReadFile(cfg.IsolatedFiles[0]); err != nil || string(data) != "a" {
		t.Fatalf("installed file not rolled back after failed uninstall: %q %v", data, err)
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		t.Fatalf("unresolved journal after rolled-back uninstall: %v", err)
	}

	// Clearing the service fault allows uninstall to succeed cleanly.
	sp.failOpID = ""
	if _, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:  cfg.ManifestPath,
		IsolatedFiles: cfg.IsolatedFiles,
		Platform:      sp,
	}); err != nil {
		t.Fatalf("retry uninstall failed: %v", err)
	}
	if _, err := os.Stat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manifest still present after retry uninstall: %v", err)
	}
	if !sp.services["lightdm.service"] || sp.services["sddm.service"] || sp.installed["sddm"] == "" {
		t.Fatalf("baseline not restored after retry uninstall: pkgs=%v svcs=%v", sp.installed, sp.services)
	}
}

func TestF06_UninstallRemoveSharedDependenciesOptIn(t *testing.T) {
	requireUnprivilegedLab(t)
	ctx := context.Background()
	cfg, _, sp := setupF06Fixtures(t, false)
	if _, err := Run(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	uRes, err := Uninstall(ctx, UninstallConfig{
		ManifestPath:             cfg.ManifestPath,
		IsolatedFiles:            cfg.IsolatedFiles,
		Platform:                 sp,
		RemoveSharedDependencies: true,
	})
	if err != nil {
		t.Fatalf("uninstall with RemoveSharedDependencies failed: %v", err)
	}
	if len(uRes.KeptSharedPackages) != 0 {
		t.Fatalf("expected no kept shared packages, got %v", uRes.KeptSharedPackages)
	}
	if sp.installed["qt5-dep"] != "" || sp.installed["sddm"] == "" || sp.installed["sddm-fplogin"] != "" {
		t.Fatalf("unexpected packages after opt-in shared removal: %v", sp.installed)
	}
}

func TestF06_CrashRecoveryAtManifestAndJournalBoundaries(t *testing.T) {
	if childMode := os.Getenv("F06_CRASH_CHILD"); childMode != "" {
		runF06CrashChild(t, childMode)
		return
	}
	requireUnprivilegedLab(t)

	for _, tc := range []struct {
		name           string
		mode           string
		expectManifest bool
		expectFile     bool
	}{
		{name: "stop_before_manifest_publish", mode: "before-publish", expectManifest: false, expectFile: false},
		{name: "stop_after_manifest_publish_before_checkpoint", mode: "after-publish", expectManifest: true, expectFile: true},
		{name: "stop_before_manifest_remove", mode: "before-remove", expectManifest: true, expectFile: true},
		{name: "stop_after_manifest_remove_before_checkpoint", mode: "after-remove", expectManifest: false, expectFile: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			labDir := t.TempDir()
			targetFile := filepath.Join(labDir, "test-install-dir")
			stateRoot := filepath.Join(labDir, "state")

			// For uninstall crash tests, first perform a clean install in this labDir.
			if strings.HasSuffix(tc.mode, "remove") {
				cfg, _, _ := setupTestFixtures(labDir)
				if _, err := Run(context.Background(), cfg); err != nil {
					t.Fatalf("initial install failed: %v", err)
				}
			}

			// Spawn real child process and SIGKILL it right at the target hook.
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestF06_CrashRecoveryAtManifestAndJournalBoundaries$")
			cmd.Env = append(os.Environ(), "F06_CRASH_CHILD="+tc.mode, "F06_CRASH_DIR="+labDir)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, err := stdout.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "F06_READY") {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("child did not reach hook: %q %v", string(buf[:n]), err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()

			// While unresolved, a second transaction MUST be blocked.
			if err := transaction.CheckNoUnresolved(filepath.Join(stateRoot, "transactions")); !errors.Is(err, transaction.ErrUnresolvedTransaction) {
				t.Fatalf("expected unresolved transaction after SIGKILL, got %v", err)
			}

			// Recover from disk in a fresh call.
			if err := RecoverPending(context.Background(), stateRoot, []string{targetFile}, nil); err != nil {
				t.Fatalf("RecoverPending failed: %v", err)
			}
			if err := transaction.CheckNoUnresolved(filepath.Join(stateRoot, "transactions")); err != nil {
				t.Fatalf("journal still unresolved after RecoverPending: %v", err)
			}

			// Verify stray manifest.json.tmp.* files were cleaned up.
			if temps, _ := filepath.Glob(filepath.Join(stateRoot, "manifest.json.tmp.*")); len(temps) != 0 {
				t.Fatalf("stray temp manifest files remain: %v", temps)
			}

			_, mErr := manifest.Load(filepath.Join(stateRoot, "manifest.json"))
			if tc.expectManifest && mErr != nil {
				t.Fatalf("expected valid manifest after recovery, got %v", mErr)
			}
			if !tc.expectManifest && !errors.Is(mErr, manifest.ErrManifestNotFound) {
				t.Fatalf("expected absent manifest after recovery, got %v", mErr)
			}

			_, fErr := os.Stat(targetFile)
			if tc.expectFile && fErr != nil {
				t.Fatalf("expected installed file present after recovery, got %v", fErr)
			}
			if !tc.expectFile && !errors.Is(fErr, os.ErrNotExist) {
				t.Fatalf("expected installed file absent after recovery, got %v", fErr)
			}
		})
	}
}

func runF06CrashChild(t *testing.T, mode string) {
	labDir := os.Getenv("F06_CRASH_DIR")
	cfg, _, _ := setupTestFixtures(labDir)
	pauseForKill := func(txID string) {
		if mode == "before-publish" {
			_ = os.WriteFile(filepath.Join(filepath.Dir(cfg.ManifestPath), "manifest.json.tmp.crash"), []byte("partial"), 0o600)
		}
		fmt.Println("F06_READY")
		select {}
	}

	defer func() {
		testBeforeManifestPublish = nil
		testAfterManifestPublish = nil
		testBeforeManifestRemove = nil
		testAfterManifestRemove = nil
	}()

	switch mode {
	case "before-publish":
		testBeforeManifestPublish = pauseForKill
		_, _ = Run(context.Background(), cfg)
	case "after-publish":
		testAfterManifestPublish = pauseForKill
		_, _ = Run(context.Background(), cfg)
	case "before-remove":
		testBeforeManifestRemove = pauseForKill
		_, _ = Uninstall(context.Background(), UninstallConfig{
			ManifestPath:  cfg.ManifestPath,
			IsolatedFiles: cfg.IsolatedFiles,
		})
	case "after-remove":
		testAfterManifestRemove = pauseForKill
		_, _ = Uninstall(context.Background(), UninstallConfig{
			ManifestPath:  cfg.ManifestPath,
			IsolatedFiles: cfg.IsolatedFiles,
		})
	}
}

func TestF06_JournalCompletionFailureRecoversWithoutDataLoss(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, _, _ := setupTestFixtures(t.TempDir())
	stateRoot := filepath.Dir(cfg.JournalDir)

	// Block journal directory rename right after manifest is published (simulating checkpoint I/O failure).
	savedDir := cfg.JournalDir + ".blocked"
	testAfterManifestPublish = func(string) {
		if err := os.Rename(cfg.JournalDir, savedDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.JournalDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { testAfterManifestPublish = nil }()

	res, err := Run(context.Background(), cfg)
	if res != nil || !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("expected ErrRecoveryRequired on checkpoint failure, got %+v %v", res, err)
	}

	// Restore journal directory and reconcile via RecoverPending.
	if err := os.Remove(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(savedDir, cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPending(context.Background(), stateRoot, cfg.IsolatedFiles, nil); err != nil {
		t.Fatalf("RecoverPending failed after checkpoint error: %v", err)
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		t.Fatalf("journal not completed after recovery: %v", err)
	}
	if _, err := manifest.Load(cfg.ManifestPath); err != nil {
		t.Fatalf("manifest invalid after recovery: %v", err)
	}
}
