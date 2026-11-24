package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"fplogin/internal/core/discovery"
	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	a "fplogin/internal/protocol/adapter/v1"
	m "fplogin/internal/protocol/manifest/v1"
	p "fplogin/internal/protocol/platform/v1"
)

type refusalProvider struct {
	*fakePlatformInvoker
	t        *testing.T
	refusal  error
	prepared bool
}

func (f *refusalProvider) PrepareArtifactInstall(_ context.Context, _ discovery.Provider, payload p.PrepareArtifactInstallPayload, _ protocol.HostContext) error {
	f.prepared = true
	if len(payload.ArtifactReferences) != 2 {
		f.t.Fatal("missing rollback archive")
	}
	for _, r := range payload.ArtifactReferences {
		b, err := os.ReadFile(r.CanonicalPath)
		if err != nil || string(b) != r.ArtifactID {
			f.t.Fatal("not staged")
		}
	}
	return f.refusal
}

func (f *refusalProvider) ApplyOperation(context.Context, protocol.Operation) (m.OperationReceipt, error) {
	f.t.Fatal("mutation before preparation")
	panic("unreachable")
}

type statefulLabProvider struct {
	*fakePlatformInvoker
	t           *testing.T
	prepared    bool
	prepErr     error
	failOpID    string
	events      []string
	installed   map[string]string
	svcEnabled  bool
	expectCount int
}

func (s *statefulLabProvider) PrepareArtifactInstall(_ context.Context, _ discovery.Provider, payload p.PrepareArtifactInstallPayload, _ protocol.HostContext) error {
	s.prepared = true
	s.events = append(s.events, "prepare")
	if s.expectCount > 0 && len(payload.ArtifactReferences) != s.expectCount {
		s.t.Fatalf("expected %d staged artifacts, got %d", s.expectCount, len(payload.ArtifactReferences))
	}
	for _, r := range payload.ArtifactReferences {
		b, err := os.ReadFile(r.CanonicalPath)
		if err != nil || string(b) != r.ArtifactID {
			s.t.Fatalf("artifact %q not staged at %q", r.ArtifactID, r.CanonicalPath)
		}
	}
	return s.prepErr
}

func (s *statefulLabProvider) ApplyPreparedOperation(_ context.Context, req PlatformOperationRequest) (m.OperationReceipt, error) {
	op := req.Operation
	s.events = append(s.events, op.OperationID)
	if !s.prepared && req.StageDir == "" {
		s.t.Fatal("missing stage dir for platform operation")
	}
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
			return r, fmt.Errorf("staged archive missing: %w", err)
		}
		_, existed := s.installed[params.PackageReference]
		r.BeforeState = protocol.Object{"installed": json.RawMessage(fmt.Sprintf("%t", existed))}
		if params.PackageReference == "sddm-fplogin" {
			delete(s.installed, "sddm")
		}
		if params.PackageReference == "sddm" {
			delete(s.installed, "sddm-fplogin")
		}
		s.installed[params.PackageReference] = params.SHA256
		r.AfterState = protocol.Object{"installed": json.RawMessage(`true`)}
	case protocol.RemoveOwnedPackage:
		var params struct {
			PackageReference string `json:"package_reference"`
		}
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return r, err
		}
		_, existed := s.installed[params.PackageReference]
		r.BeforeState = protocol.Object{"installed": json.RawMessage(fmt.Sprintf("%t", existed))}
		delete(s.installed, params.PackageReference)
		r.AfterState = protocol.Object{"installed": json.RawMessage(`false`)}
	case protocol.SetServiceEnabled:
		var params struct {
			ServiceReference string `json:"service_reference"`
			Enabled          bool   `json:"enabled"`
		}
		if err := json.Unmarshal(op.Parameters, &params); err != nil {
			return r, err
		}
		r.BeforeState = protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", s.svcEnabled))}
		s.svcEnabled = params.Enabled
		r.AfterState = protocol.Object{"enabled": json.RawMessage(fmt.Sprintf("%t", s.svcEnabled))}
	default:
		return r, fmt.Errorf("unexpected op kind %s", op.Kind)
	}
	return r, nil
}

func setupPackagePlanFixtures(t *testing.T) (Config, *fakeAdapterInvoker, *statefulLabProvider) {
	t.Helper()
	cfg, ad, pv := setupTestFixtures(t.TempDir())
	cfg.IsolatedArchiveCache = t.TempDir()
	sp := &statefulLabProvider{
		fakePlatformInvoker: pv,
		t:                   t,
		installed:           map[string]string{"sddm": sha256Hex([]byte("sddm"))},
		expectCount:         3,
	}
	cfg.PlatformInvoker = sp

	plan := &ad.plan
	file := plan.Operations[0]
	plan.ArtifactReferences = nil
	for _, id := range []string{"qt5-dep", "sddm-fplogin", "sddm"} {
		hash := sha256Hex([]byte(id))
		plan.ArtifactReferences = append(plan.ArtifactReferences, a.ArtifactReference{
			ArtifactID: id, Size: int64(len(id)), SHA256: hash,
			MediaType: "application/octet-stream", Role: "package", CanonicalPath: "/ignored",
		})
		path := filepath.Join(cfg.IsolatedArchiveCache, hash)
		for _, suffix := range []string{"", ".sig"} {
			if err := os.WriteFile(path+suffix, []byte(id), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	qtOp := file
	qtOp.OperationID = "pkg-qt5"
	qtOp.Kind = protocol.InstallPackageArtifact
	qtOp.ExpectedBefore = protocol.Object{"installed": json.RawMessage(`false`)}
	qtOp.ExpectedAfter = protocol.Object{"installed": json.RawMessage(`true`)}
	qtOp.Parameters = json.RawMessage(fmt.Sprintf(`{"package_reference":"qt5-dep","artifact_id":"qt5-dep","sha256":%q}`, plan.ArtifactReferences[0].SHA256))
	qtOp.Compensation = json.RawMessage(`{"kind":"remove_package","package_reference":"qt5-dep"}`)

	candOp := file
	candOp.OperationID = "pkg-candidate"
	candOp.Kind = protocol.InstallPackageArtifact
	candOp.ExpectedBefore = protocol.Object{"installed": json.RawMessage(`false`)}
	candOp.ExpectedAfter = protocol.Object{"installed": json.RawMessage(`true`)}
	candOp.Parameters = json.RawMessage(fmt.Sprintf(`{"package_reference":"sddm-fplogin","artifact_id":"sddm-fplogin","sha256":%q}`, plan.ArtifactReferences[1].SHA256))
	candOp.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"sddm","artifact_id":"sddm","sha256":%q}`, plan.ArtifactReferences[2].SHA256))

	svcOp := file
	svcOp.OperationID = "svc-enable"
	svcOp.Kind = protocol.SetServiceEnabled
	svcOp.ExpectedBefore = protocol.Object{"enabled": json.RawMessage(`false`)}
	svcOp.ExpectedAfter = protocol.Object{"enabled": json.RawMessage(`true`)}
	svcOp.Parameters = json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`)
	svcOp.Compensation = json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":false}`)

	plan.Operations = []protocol.Operation{qtOp, candOp, file, svcOp}
	return cfg, ad, sp
}

func TestRunPackagePreparationPrecedesMutation(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, ad, pv := setupTestFixtures(t.TempDir())
	cfg.IsolatedArchiveCache = t.TempDir()
	f := &refusalProvider{fakePlatformInvoker: pv, t: t, refusal: errors.New("signature rejected")}
	cfg.PlatformInvoker = f
	plan := &ad.plan
	file := plan.Operations[0]
	pkg := file
	pkg.OperationID = "package"
	pkg.Kind = protocol.InstallPackageArtifact
	for _, id := range []string{"candidate", "stock"} {
		hash := sha256Hex([]byte(id))
		plan.ArtifactReferences = append(plan.ArtifactReferences, a.ArtifactReference{ArtifactID: id, Size: int64(len(id)), SHA256: hash, MediaType: "application/octet-stream", Role: "package", CanonicalPath: "/ignored"})
		path := filepath.Join(cfg.IsolatedArchiveCache, hash)
		for _, suffix := range []string{"", ".sig"} {
			if err := os.WriteFile(path+suffix, []byte(id), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	pkg.Parameters = json.RawMessage(fmt.Sprintf(`{"package_reference":"candidate","artifact_id":"candidate","sha256":%q}`, plan.ArtifactReferences[0].SHA256))
	pkg.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"stock","artifact_id":"stock","sha256":%q}`, plan.ArtifactReferences[1].SHA256))
	svc := file
	svc.Kind = protocol.SetServiceEnabled
	svc.OperationID = "enable"
	svc.Parameters = json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`)
	svc.Compensation = json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":false}`)
	plan.Operations = []protocol.Operation{pkg, file, svc}
	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, f.refusal) || !f.prepared {
		t.Fatalf("prepared %t: %v", f.prepared, err)
	}
	if _, err = os.Stat(cfg.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected file change")
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
}

func TestRunPackageTransactionOrderAndSuccess(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, ad, sp := setupPackagePlanFixtures(t)
	ad.beforeVerify = func() {
		sp.events = append(sp.events, "verify")
		if sp.svcEnabled {
			t.Fatal("service enabled before verification")
		}
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	wantEvents := []string{"prepare", "pkg-qt5", "pkg-candidate", "verify", "svc-enable"}
	if !slices.Equal(sp.events, wantEvents) {
		t.Fatalf("events=%v, want %v", sp.events, wantEvents)
	}
	if !sp.svcEnabled || sp.installed["sddm-fplogin"] == "" || sp.installed["qt5-dep"] == "" || sp.installed["sddm"] != "" {
		t.Fatalf("unexpected final state: svc=%t pkgs=%v", sp.svcEnabled, sp.installed)
	}
	if data, err := os.ReadFile(cfg.IsolatedFiles[0]); err != nil || string(data) != "a" {
		t.Fatalf("theme file not written: %q %v", data, err)
	}
	j, err := transaction.Open(res.JournalPath)
	if err != nil || j.State() != "completed" || len(j.Data().AppliedOperations) != 4 {
		t.Fatalf("unexpected journal: %v %+v", err, j)
	}
}

func TestRunPackageFailureRestoresPackageState(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, _, sp := setupPackagePlanFixtures(t)
	sp.failOpID = "pkg-candidate"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrTransactionAborted) {
		t.Fatalf("expected ErrTransactionAborted, got %v", err)
	}
	if sp.svcEnabled {
		t.Fatal("service must not be enabled after package failure")
	}
	if _, ok := sp.installed["qt5-dep"]; ok {
		t.Fatal("qt5-dep was not rolled back")
	}
	if _, ok := sp.installed["sddm-fplogin"]; ok {
		t.Fatal("sddm-fplogin should not be installed")
	}
	if sp.installed["sddm"] == "" {
		t.Fatal("stock sddm missing after rollback")
	}
	if _, err := os.Stat(cfg.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("theme file must not exist")
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
}

func TestRunVerificationFailurePreventsActivationAndRollsBackPackages(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, ad, sp := setupPackagePlanFixtures(t)
	ad.verifyReport.Checks[0].Status = "failed"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}
	if sp.svcEnabled || slices.Contains(sp.events, "svc-enable") {
		t.Fatalf("service activation ran despite verification failure: events=%v", sp.events)
	}
	if _, err := os.Stat(cfg.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("theme file was not rolled back")
	}
	if sp.installed["sddm"] == "" || sp.installed["sddm-fplogin"] != "" || sp.installed["qt5-dep"] != "" {
		t.Fatalf("packages were not restored to stock: %v", sp.installed)
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
}

func TestRunServiceFailureRollsBackFileAndPackages(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, _, sp := setupPackagePlanFixtures(t)
	sp.failOpID = "svc-enable"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrTransactionAborted) {
		t.Fatalf("expected ErrTransactionAborted, got %v", err)
	}
	if sp.svcEnabled || sp.installed["sddm"] == "" || sp.installed["sddm-fplogin"] != "" || sp.installed["qt5-dep"] != "" {
		t.Fatalf("state not restored after service failure: svc=%t pkgs=%v", sp.svcEnabled, sp.installed)
	}
	if _, err := os.Stat(cfg.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("theme file not restored after service failure")
	}
}

func TestRunRollbackFailureBlocksNextTransactionUntilRecovered(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, ad, sp := setupPackagePlanFixtures(t)
	ad.verifyReport.Checks[0].Status = "failed"
	sp.failOpID = "pkg-candidate-rollback"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("expected ErrRecoveryRequired, got %v", err)
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); !errors.Is(err, transaction.ErrUnresolvedTransaction) {
		t.Fatalf("expected unresolved transaction, got %v", err)
	}
	// A second Run must be refused while recovery is pending.
	if _, err := Run(context.Background(), cfg); !errors.Is(err, transaction.ErrUnresolvedTransaction) {
		t.Fatalf("second Run was not blocked: %v", err)
	}

	// Clear rollback fault and recover from disk in a fresh call.
	entries, err := os.ReadDir(cfg.JournalDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one journal: %v %v", entries, err)
	}
	txID := entries[0].Name()[:len(entries[0].Name())-len(".json")]
	sp.failOpID = ""
	if err := RecoverTransaction(context.Background(), filepath.Dir(cfg.JournalDir), txID, cfg.IsolatedFiles, sp); err != nil {
		t.Fatalf("RecoverTransaction failed: %v", err)
	}
	if sp.installed["sddm"] == "" || sp.installed["sddm-fplogin"] != "" || sp.installed["qt5-dep"] != "" {
		t.Fatalf("state not restored after recovery: %v", sp.installed)
	}
	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsPackageOrFileAfterServiceOp(t *testing.T) {
	requireUnprivilegedLab(t)
	cfg, ad, _ := setupPackagePlanFixtures(t)
	// Put service op before the file op so activation would precede verification.
	ops := ad.plan.Operations
	ad.plan.Operations = []protocol.Operation{ops[0], ops[1], ops[3], ops[2]}
	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrPrecondition) {
		t.Fatalf("expected ErrPrecondition for out-of-order service op, got %v", err)
	}
}
