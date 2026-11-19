package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/discovery"
	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/platformclient"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

type fakeAdapterDiscoverer struct {
	result []adapterclient.Discovered
	err    error
}

func (f *fakeAdapterDiscoverer) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]adapterclient.Discovered, error) {
	return f.result, f.err
}

type fakeProviderDiscoverer struct {
	result []platformclient.Discovered
	err    error
}

func (f *fakeProviderDiscoverer) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]platformclient.Discovered, error) {
	return f.result, f.err
}

type fakeAdapterInvoker struct {
	detectReport adapterv1.DetectionReport
	prereqReport adapterv1.PrerequisiteReport
	dmState      adapterv1.DisplayManagerState
	plan         adapterv1.ChangePlan
	artifacts    adapterv1.ArtifactSet
	verifyReport adapterv1.VerificationReport
	planErr      error
	verifyErr    error
	beforeVerify func()
}

func (f *fakeAdapterInvoker) Detect(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.DetectionReport, error) {
	return f.detectReport, nil
}
func (f *fakeAdapterInvoker) CheckPrerequisites(ctx context.Context, adapter discovery.Adapter, payload adapterv1.CheckPrerequisitesPayload, host protocol.HostContext) (adapterv1.PrerequisiteReport, error) {
	return f.prereqReport, nil
}
func (f *fakeAdapterInvoker) InspectState(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.DisplayManagerState, error) {
	return f.dmState, nil
}
func (f *fakeAdapterInvoker) PlanInstall(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.ChangePlan, error) {
	return f.plan, f.planErr
}
func (f *fakeAdapterInvoker) PrepareArtifacts(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.ArtifactSet, error) {
	return f.artifacts, nil
}
func (f *fakeAdapterInvoker) Verify(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.VerificationReport, error) {
	if f.beforeVerify != nil {
		f.beforeVerify()
	}
	return f.verifyReport, f.verifyErr
}

type fakePlatformInvoker struct {
	hostReport platformv1.PlatformHostReport
	applierErr error
}

func (f *fakePlatformInvoker) ApplyOperation(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error) {
	if f.applierErr != nil {
		return manifestv1.OperationReceipt{}, f.applierErr
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		StartedAt:    now,
		CompletedAt:  now,
		Status:       "success",
		BeforeState:  protocol.Object{"k": json.RawMessage(`"v"`)},
		AfterState:   protocol.Object{"k": json.RawMessage(`"v2"`)},
		Compensation: protocol.Object{"restore": json.RawMessage(`"v"`)},
	}, nil
}

func (f *fakePlatformInvoker) InspectHost(ctx context.Context, provider discovery.Provider, host protocol.HostContext) (platformv1.PlatformHostReport, error) {
	return f.hostReport, nil
}

func (f *fakePlatformInvoker) PrepareArtifactInstall(ctx context.Context, provider discovery.Provider, payload platformv1.PrepareArtifactInstallPayload, host protocol.HostContext) error {
	return nil
}

func setupTestFixtures(tmpDir string) (Config, *fakeAdapterInvoker, *fakePlatformInvoker) {
	ad := adapterclient.Discovered{
		Descriptor: adapterv1.Descriptor{
			AdapterID:      "org.fplogin.adapter.sddm",
			AdapterVersion: "1.0.0",
		},
		ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
		DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	pr := platformclient.Discovered{
		Descriptor: platformv1.Descriptor{
			PlatformID:      "org.fplogin.platform.arch",
			PlatformVersion: "1.0.0",
			Capabilities: []protocol.Capability{
				{ID: "apply_operation", Status: "native"},
			},
		},
		ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
		DescriptorSHA256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	}

	targetDir := filepath.Join(tmpDir, "test-install-dir")
	params := json.RawMessage(`{"path":"` + targetDir + `","mode":"0755","owner":"root","group":"root"}`)
	comp := json.RawMessage(`{"kind":"remove_directory","path":"` + targetDir + `"}`)

	now := time.Now().UTC().Format(time.RFC3339)
	dummyDigest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validPlan := adapterv1.ChangePlan{
		PlanID:               "plan-1",
		AdapterID:            "org.fplogin.adapter.sddm",
		AdapterVersion:       "1.0.0",
		ProtocolVersion:      protocol.Version{Major: 1, Minor: 0},
		TargetInstanceID:     "sddm-inst",
		Mode:                 "fresh_install",
		CreatedAt:            now,
		InputHash:            dummyDigest,
		CanonicalPlanDigest:  dummyDigest,
		Approvals:            []adapterv1.Approval{},
		Preconditions:        []adapterv1.Condition{},
		Postconditions:       []adapterv1.Condition{},
		ArtifactReferences:   []adapterv1.ArtifactReference{},
		ExpectedCapabilities: []string{},
		Operations: []protocol.Operation{
			{
				OperationID:    "op-1",
				Kind:           protocol.CreateDirectory,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"existed": json.RawMessage(`false`)},
				ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
				Parameters:     params,
				Compensation:   comp,
			},
		},
	}
	adInvoker := &fakeAdapterInvoker{
		detectReport: adapterv1.DetectionReport{
			Targets: []adapterv1.DetectedTarget{
				{
					InstanceID:    "sddm-inst",
					DMID:          "org.freedesktop.DisplayManager.sddm",
					DisplayName:   "SDDM",
					Compatibility: "compatible",
					Confidence:    "confirmed",
					Evidence:      []json.RawMessage{},
				},
			},
		},
		prereqReport: adapterv1.PrerequisiteReport{
			Findings: []adapterv1.PrerequisiteFinding{},
		},
		dmState: adapterv1.DisplayManagerState{
			Active:       "no",
			Enabled:      "no",
			Configurable: "yes",
		},
		plan:      validPlan,
		artifacts: adapterv1.ArtifactSet{Artifacts: []adapterv1.Artifact{}},
		verifyReport: adapterv1.VerificationReport{
			ReportID:   "rep-1",
			VerifiedAt: now,
			Checks: []adapterv1.VerificationCheck{
				{
					CheckID:  "chk-1",
					Status:   "passed",
					Severity: "required",
					Evidence: []protocol.Evidence{},
				},
			},
		},
	}

	platInvoker := &fakePlatformInvoker{}

	cfg := Config{
		AdapterDiscoverer:  &fakeAdapterDiscoverer{result: []adapterclient.Discovered{ad}},
		ProviderDiscoverer: &fakeProviderDiscoverer{result: []platformclient.Discovered{pr}},
		AdapterInvoker:     adInvoker,
		PlatformInvoker:    platInvoker,
		AdapterDirs:        []string{filepath.Join(tmpDir, "adapters")},
		ProviderDirs:       []string{filepath.Join(tmpDir, "providers")},
		JournalDir:         filepath.Join(tmpDir, "state", "transactions"),
		ManifestPath:       filepath.Join(tmpDir, "state", "manifest.json"),
		BackupDir:          filepath.Join(tmpDir, "state", "backups"),
		Host: protocol.HostContext{
			Elevated: true,
		},
		ApprovePlan: func(string, bool) error { return nil },
	}

	return cfg, adInvoker, platInvoker
}

func TestRun_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, _, _ := setupTestFixtures(tmpDir)
	cfg.DryRun = true

	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("DryRun failed: %v", err)
	}

	if !res.DryRun {
		t.Error("expected DryRun true in result")
	}

	// Verify NO journal and NO manifest were created
	if _, err := os.Stat(cfg.ManifestPath); !os.IsNotExist(err) {
		t.Error("DryRun must NOT create manifest file")
	}
	if entries, err := os.ReadDir(cfg.JournalDir); err == nil && len(entries) > 0 {
		t.Error("DryRun must NOT create transaction journal files")
	}
}

func TestRun_FullInstallSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, _, _ := setupTestFixtures(tmpDir)

	var approved string
	cfg.ApprovePlan = func(digest string, _ bool) error { approved = digest; return nil }
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	j, err := transaction.Open(res.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	data := j.Data()
	if data.AcceptedPlan.PlanDigest != approved || approved == res.Plan.CanonicalPlanDigest {
		t.Fatal("journal did not persist the core-approved digest")
	}
	res.Plan.Operations[0].Compensation = json.RawMessage(`{"kind":"remove_directory","path":"/another-directory"}`)
	if digest, err := changePlanDigest(res.Plan); err != nil || digest == approved {
		t.Fatalf("changing the operation did not produce a different digest: %v", err)
	}

	if res.DryRun {
		t.Error("expected DryRun false")
	}

	// Verify manifest exists and is valid
	m, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		t.Fatalf("failed to load published manifest: %v", err)
	}
	if m.Target.DMID != "org.freedesktop.DisplayManager.sddm" {
		t.Errorf("expected target SDDM, got %q", m.Target.DMID)
	}

	// Verify directory was created
	createdDir := filepath.Join(tmpDir, "test-install-dir")
	if _, err := os.Stat(createdDir); err != nil {
		t.Errorf("expected target directory to be created: %v", err)
	}
}

func TestRun_CheckpointFailureDoesNotReportSuccess(t *testing.T) {
	cfg, adapter, _ := setupTestFixtures(t.TempDir())
	adapter.beforeVerify = func() {
		// Keep the recovery data, but prevent checkpoint writes at the original path.
		if err := os.Rename(cfg.JournalDir, cfg.JournalDir+".preserved"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.JournalDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Run(context.Background(), cfg)
	if res != nil || !errors.Is(err, syscall.ENOTDIR) || !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("expected checkpoint failure and no success result, got %+v, %v", res, err)
	}
}

func TestRun_PrivilegesRequired(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, _, _ := setupTestFixtures(tmpDir)
	cfg.Host.Elevated = false

	// Only test if running as non-root
	if os.Geteuid() != 0 {
		_, err := Run(context.Background(), cfg)
		if !errors.Is(err, ErrPrivilegesRequired) {
			t.Fatalf("expected ErrPrivilegesRequired, got %v", err)
		}
	}
}

func TestRun_ApprovalRequired(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, adInvoker, _ := setupTestFixtures(tmpDir)
	cfg.ApprovePlan = nil
	// Simulate existing active DM that would be replaced
	adInvoker.dmState.Active = "yes"
	adInvoker.dmState.Enabled = "yes"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("expected ErrApprovalRequired, got %v", err)
	}
}

func TestRun_BlocksConcurrentAndUnresolvedTransactions(t *testing.T) {
	cfg, adapter, _ := setupTestFixtures(t.TempDir())
	adapter.beforeVerify = func() {
		res, err := Run(context.Background(), cfg)
		if res != nil || !errors.Is(err, transaction.ErrTransactionBusy) {
			t.Fatalf("second run got %+v, %v; want transaction busy", res, err)
		}
	}
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	adapter.beforeVerify = nil
	if err := os.WriteFile(res.JournalPath, []byte("broken journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := Run(context.Background(), cfg); res != nil || !errors.Is(err, transaction.ErrUnresolvedTransaction) {
		t.Fatalf("run with corrupt journal got %+v, %v; want unresolved transaction", res, err)
	}
}

func TestRun_VerificationAndRollbackFailure(t *testing.T) {
	cfg, adapter, _ := setupTestFixtures(t.TempDir())
	verifyFailure := errors.New("verification failed")
	adapter.verifyErr = verifyFailure
	adapter.beforeVerify = func() {
		if err := os.Rename(cfg.JournalDir, cfg.JournalDir+".preserved"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.JournalDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Run(context.Background(), cfg)
	if res != nil || !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, verifyFailure) || !errors.Is(err, syscall.ENOTDIR) || errors.Is(err, ErrTransactionAborted) {
		t.Fatalf("expected both causes and recovery required, got %+v, %v", res, err)
	}
}

func TestRun_VerificationFailureRollback(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, adInvoker, _ := setupTestFixtures(tmpDir)
	// Force verification failure
	adInvoker.verifyReport.Checks[0].Status = "failed"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}

	// Target directory should have been rolled back
	createdDir := filepath.Join(tmpDir, "test-install-dir")
	if _, err := os.Stat(createdDir); !os.IsNotExist(err) {
		t.Errorf("expected created directory to be removed on rollback, err: %v", err)
	}

	// Manifest must NOT have been published
	if _, err := os.Stat(cfg.ManifestPath); !os.IsNotExist(err) {
		t.Error("manifest must not exist after rollback")
	}
}
