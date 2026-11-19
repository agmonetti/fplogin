package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/discovery"
	"fplogin/internal/core/install"
	"fplogin/internal/core/manifest"
	"fplogin/internal/platformclient"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

type fakeDiscoverer[T any] struct {
	items []T
	err   error
}

func (f *fakeDiscoverer[T]) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]T, error) {
	return f.items, f.err
}

type fakeAdapterInvoker struct {
	detectReport adapterv1.DetectionReport
	prereqReport adapterv1.PrerequisiteReport
	dmState      adapterv1.DisplayManagerState
	plan         adapterv1.ChangePlan
	artifacts    adapterv1.ArtifactSet
	verifyReport adapterv1.VerificationReport
}

func (f *fakeAdapterInvoker) Detect(ctx context.Context, a discovery.Adapter, h protocol.HostContext) (adapterv1.DetectionReport, error) {
	return f.detectReport, nil
}
func (f *fakeAdapterInvoker) CheckPrerequisites(ctx context.Context, a discovery.Adapter, p adapterv1.CheckPrerequisitesPayload, h protocol.HostContext) (adapterv1.PrerequisiteReport, error) {
	return f.prereqReport, nil
}
func (f *fakeAdapterInvoker) InspectState(ctx context.Context, a discovery.Adapter, h protocol.HostContext) (adapterv1.DisplayManagerState, error) {
	return f.dmState, nil
}
func (f *fakeAdapterInvoker) PlanInstall(ctx context.Context, a discovery.Adapter, h protocol.HostContext) (adapterv1.ChangePlan, error) {
	return f.plan, nil
}
func (f *fakeAdapterInvoker) PrepareArtifacts(ctx context.Context, a discovery.Adapter, h protocol.HostContext) (adapterv1.ArtifactSet, error) {
	return f.artifacts, nil
}
func (f *fakeAdapterInvoker) Verify(ctx context.Context, a discovery.Adapter, h protocol.HostContext) (adapterv1.VerificationReport, error) {
	return f.verifyReport, nil
}

type fakePlatformInvoker struct {
	failOnOpID string
}

func (f *fakePlatformInvoker) ApplyOperation(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error) {
	if f.failOnOpID != "" && op.OperationID == f.failOnOpID {
		return manifestv1.OperationReceipt{}, errors.New("simulated platform failure")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		StartedAt:    now,
		CompletedAt:  now,
		Status:       "success",
		BeforeState:  protocol.Object{"state": json.RawMessage(`"disabled"`)},
		AfterState:   protocol.Object{"state": json.RawMessage(`"enabled"`)},
		Compensation: protocol.Object{"state": json.RawMessage(`"disabled"`)},
	}, nil
}

func (f *fakePlatformInvoker) InspectHost(ctx context.Context, p discovery.Provider, h protocol.HostContext) (platformv1.PlatformHostReport, error) {
	return platformv1.PlatformHostReport{}, nil
}

func (f *fakePlatformInvoker) PrepareArtifactInstall(ctx context.Context, p discovery.Provider, pl platformv1.PrepareArtifactInstallPayload, h protocol.HostContext) error {
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func treeSnapshot(root string) (map[string]string, error) {
	snap := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			snap[rel] = "DIR"
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snap[rel] = sha256Hex(content)
		return nil
	})
	return snap, err
}

func buildIntegrationFixture(t *testing.T, tmpDir string, failOpID string) (install.Config, string, string) {
	t.Helper()
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("isolated Run requires an unprivileged user")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	dummyDigest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	file1Path := filepath.Join(tmpDir, "etc", "sddm.conf.d", "fplogin.conf")
	file1Content := []byte("[Theme]\nCurrent=fplogin\n")
	file1Hash := sha256Hex(file1Content)
	file1B64 := base64.StdEncoding.EncodeToString(file1Content)

	file2Path := filepath.Join(tmpDir, "etc", "pam.d", "sddm-fp")
	file2Content := []byte("auth sufficient pam_fprintd.so\n")
	file2Hash := sha256Hex(file2Content)
	file2B64 := base64.StdEncoding.EncodeToString(file2Content)

	op1 := protocol.Operation{
		OperationID:    "op-file-1",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
		Parameters: json.RawMessage(fmt.Sprintf(
			`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
			file1Path, file1B64, file1Hash)),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"remove_file","path":%q}`, file1Path)),
	}

	op2 := protocol.Operation{
		OperationID:    "op-file-2",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{"op-file-1"},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
		Parameters: json.RawMessage(fmt.Sprintf(
			`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
			file2Path, file2B64, file2Hash)),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"remove_file","path":%q}`, file2Path)),
	}

	plan := adapterv1.ChangePlan{
		PlanID:               "plan-integration-1",
		AdapterID:            "org.fplogin.adapter.sddm",
		AdapterVersion:       "1.0.0",
		ProtocolVersion:      protocol.Version{Major: 1, Minor: 0},
		TargetInstanceID:     "sddm-inst-1",
		Mode:                 "fresh_install",
		CreatedAt:            now,
		InputHash:            dummyDigest,
		CanonicalPlanDigest:  dummyDigest,
		Approvals:            []adapterv1.Approval{},
		Preconditions:        []adapterv1.Condition{},
		Postconditions:       []adapterv1.Condition{},
		ArtifactReferences:   []adapterv1.ArtifactReference{},
		Operations:           []protocol.Operation{op1, op2},
		ExpectedCapabilities: []string{"biometric_auth"},
	}

	adDiscovered := adapterclient.Discovered{
		Descriptor: adapterv1.Descriptor{
			AdapterID:      "org.fplogin.adapter.sddm",
			AdapterVersion: "1.0.0",
		},
		ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
		DescriptorSHA256: dummyDigest,
	}

	prDiscovered := platformclient.Discovered{
		Descriptor: platformv1.Descriptor{
			PlatformID:      "org.fplogin.platform.arch",
			PlatformVersion: "1.0.0",
			Capabilities:    []protocol.Capability{{ID: "apply_operation", Status: "native"}},
		},
		ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
		DescriptorSHA256: dummyDigest,
	}

	adInvoker := &fakeAdapterInvoker{
		detectReport: adapterv1.DetectionReport{
			Targets: []adapterv1.DetectedTarget{
				{
					InstanceID:    "sddm-inst-1",
					DMID:          "org.freedesktop.DisplayManager.sddm",
					DisplayName:   "SDDM",
					Compatibility: "compatible",
					Confidence:    "confirmed",
					Evidence:      []json.RawMessage{},
				},
			},
		},
		prereqReport: adapterv1.PrerequisiteReport{Findings: []adapterv1.PrerequisiteFinding{}},
		dmState: adapterv1.DisplayManagerState{
			Active:       "no",
			Enabled:      "no",
			Configurable: "yes",
		},
		plan:      plan,
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

	platInvoker := &fakePlatformInvoker{failOnOpID: failOpID}

	for _, dir := range []string{filepath.Dir(file1Path), filepath.Dir(file2Path)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := install.Config{
		AdapterDiscoverer:  &fakeDiscoverer[adapterclient.Discovered]{items: []adapterclient.Discovered{adDiscovered}},
		ProviderDiscoverer: &fakeDiscoverer[platformclient.Discovered]{items: []platformclient.Discovered{prDiscovered}},
		AdapterInvoker:     adInvoker,
		PlatformInvoker:    platInvoker,
		JournalDir:         filepath.Join(tmpDir, "state", "transactions"),
		ManifestPath:       filepath.Join(tmpDir, "state", "manifest.json"),
		IsolatedFiles:      []string{file1Path, file2Path},
		ApprovePlan:        func(string, bool) error { return nil },
	}

	return cfg, file1Path, file2Path
}

func TestIntegration_FreshInstall_Clean(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, file1, file2 := buildIntegrationFixture(t, tmpDir, "")

	res, err := install.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Install run failed: %v", err)
	}

	if res.DryRun {
		t.Fatal("expected real install, got DryRun")
	}

	// Verify both files exist with correct contents
	c1, err := os.ReadFile(file1)
	if err != nil || string(c1) != "[Theme]\nCurrent=fplogin\n" {
		t.Fatalf("file1 not written correctly: %s (err: %v)", string(c1), err)
	}

	c2, err := os.ReadFile(file2)
	if err != nil || string(c2) != "auth sufficient pam_fprintd.so\n" {
		t.Fatalf("file2 not written correctly: %s (err: %v)", string(c2), err)
	}

	if len(res.AppliedReceipts) != 2 || res.JournalPath == "" {
		t.Fatalf("missing durable file receipts: %+v", res)
	}
	if _, err := os.Lstat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lab must not publish a manifest: %v", err)
	}
}

func TestIntegration_DryRun_NoMutationSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, _, _ := buildIntegrationFixture(t, tmpDir, "")
	cfg.DryRun = true

	snapBefore, err := treeSnapshot(tmpDir)
	if err != nil {
		t.Fatalf("treeSnapshot before failed: %v", err)
	}

	res, err := install.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("DryRun failed: %v", err)
	}
	if !res.DryRun {
		t.Fatal("expected DryRun true")
	}

	snapAfter, err := treeSnapshot(tmpDir)
	if err != nil {
		t.Fatalf("treeSnapshot after failed: %v", err)
	}

	if len(snapBefore) != len(snapAfter) {
		t.Fatalf("tree changed! before: %v, after: %v", snapBefore, snapAfter)
	}
	for k, vBefore := range snapBefore {
		vAfter, ok := snapAfter[k]
		if !ok || vBefore != vAfter {
			t.Fatalf("path %q mutated during DryRun: before=%s, after=%s", k, vBefore, vAfter)
		}
	}
}

func TestIntegration_AbortMidMutation_Compensated(t *testing.T) {
	tmpDir := t.TempDir()
	// Fail on op-file-2: op-file-1 will be executed then compensated
	cfg, file1, file2 := buildIntegrationFixture(t, tmpDir, "")

	// Inject write failure on op-file-2: valid schema for Phase 5, but hash mismatch during Phase 9 execution
	badHash := "0000000000000000000000000000000000000000000000000000000000000000"
	cfg.AdapterInvoker.(*fakeAdapterInvoker).plan.Operations[1].Parameters = json.RawMessage(fmt.Sprintf(
		`{"destination_path":%q,"content_base64":"YXV0aCBzdWZmaWNpZW50IHBhbV9mcHJpbnRkLnNvCg==","sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
		file2, badHash))

	_, err := install.Run(context.Background(), cfg)
	if !errors.Is(err, install.ErrTransactionAborted) {
		t.Fatalf("expected ErrTransactionAborted, got %v", err)
	}

	// File 1 must have been rolled back / removed
	if _, err := os.Stat(file1); !os.IsNotExist(err) {
		t.Errorf("expected file1 to be removed during rollback, err: %v", err)
	}
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("expected file2 to not exist, err: %v", err)
	}

	// Manifest must NOT exist
	if _, err := os.Stat(cfg.ManifestPath); !os.IsNotExist(err) {
		t.Errorf("manifest must not exist after rollback, err: %v", err)
	}
}

func TestIntegration_LabDoesNotAuthorizeUninstall(t *testing.T) {
	cfg, file1, file2 := buildIntegrationFixture(t, t.TempDir(), "")
	if _, err := install.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	err := manifest.Uninstall(context.Background(), manifest.UninstallConfig{ManifestPath: cfg.ManifestPath, Force: true})
	if !errors.Is(err, manifest.ErrManifestNotFound) {
		t.Fatalf("uninstall without a manifest: %v", err)
	}
	for _, file := range []string{file1, file2} {
		if _, err := os.Stat(file); err != nil {
			t.Fatal(err)
		}
	}
}
