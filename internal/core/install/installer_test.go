package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/discovery"
	"fplogin/internal/core/manifest"
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
	detectReport  adapterv1.DetectionReport
	prereqReport  adapterv1.PrerequisiteReport
	dmState       adapterv1.DisplayManagerState
	plan          adapterv1.ChangePlan
	artifacts     adapterv1.ArtifactSet
	verifyReport  adapterv1.VerificationReport
	planErr       error
	verifyErr     error
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
		JournalDir:         filepath.Join(tmpDir, "transactions"),
		ManifestPath:       filepath.Join(tmpDir, "manifest.json"),
		BackupDir:          filepath.Join(tmpDir, "backups"),
		Host: protocol.HostContext{
			Elevated: true,
		},
		AutoApprove: true,
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

	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
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
	cfg.AutoApprove = false
	// Simulate existing active DM that would be replaced
	adInvoker.dmState.Active = "yes"
	adInvoker.dmState.Enabled = "yes"

	_, err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("expected ErrApprovalRequired, got %v", err)
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
