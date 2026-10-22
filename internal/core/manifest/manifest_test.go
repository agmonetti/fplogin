package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

func validTestManifest(tmpDir string) manifestv1.InstallManifest {
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.InstallManifest{
		SchemaVersion:  manifestv1.SchemaVersion,
		FPLoginVersion: "0.2.0",
		InstalledAt:    now,
		Target: manifestv1.Target{
			InstanceID:  "inst-1",
			DMID:        "org.freedesktop.DisplayManager.sddm",
			DisplayName: "SDDM",
		},
		Adapter: manifestv1.AdapterIdentity{
			ComponentIdentity: manifestv1.ComponentIdentity{
				ID:               "org.fplogin.adapter.sddm",
				Version:          "1.0.0",
				ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
				DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
			InstalledCapabilities: []string{"biometric_auth"},
		},
		PlatformProvider: manifestv1.ComponentIdentity{
			ID:               "org.fplogin.platform.arch",
			Version:          "1.0.0",
			ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
			DescriptorSHA256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		},
		AcceptedPlan: manifestv1.AcceptedPlan{
			PlanID:     "plan-1",
			PlanDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			InputHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Mode:       "fresh_install",
		},
		InstalledFiles:    []manifestv1.InstalledFile{},
		InstalledPackages: []manifestv1.InstalledPackage{},
		Services: manifestv1.Services{
			Enabled:     []string{"sddm.service"},
			Disabled:    []string{},
			PriorStates: []manifestv1.ServiceState{},
		},
		PreviousDMState: manifestv1.PreviousDMState{
			ServiceName: "lightdm.service",
			Enabled:     "yes",
			Active:      "yes",
		},
		OperationReceipts: []manifestv1.OperationReceipt{},
		Verification: manifestv1.Verification{
			ReportID:   "rep-1",
			VerifiedAt: now,
			Checks:     []manifestv1.VerificationCheck{},
		},
	}
}

type fakePlatformApplier struct {
	calledOps []protocol.Operation
}

func (f *fakePlatformApplier) ApplyOperation(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error) {
	f.calledOps = append(f.calledOps, op)
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		StartedAt:    now,
		CompletedAt:  now,
		Status:       "success",
		BeforeState:  protocol.Object{},
		AfterState:   protocol.Object{},
		Compensation: protocol.Object{},
	}, nil
}

func sha256Str(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestPublishAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "manifest.json")

	m := validTestManifest(tmpDir)
	if err := Publish(path, m); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.FPLoginVersion != "0.2.0" {
		t.Errorf("expected FPLoginVersion 0.2.0, got %q", loaded.FPLoginVersion)
	}
	if loaded.Target.DMID != "org.freedesktop.DisplayManager.sddm" {
		t.Errorf("expected target DMID SDDM, got %q", loaded.Target.DMID)
	}
}

func TestVerifyFiles_AndUninstallFlow(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "manifest.json")

	// Create a dummy installed file
	installedFilePath := filepath.Join(tmpDir, "usr", "share", "fplogin", "asset.txt")
	_ = os.MkdirAll(filepath.Dir(installedFilePath), 0o755)
	fileContent := []byte("Initial asset content")
	_ = os.WriteFile(installedFilePath, fileContent, 0o644)
	fileHash := sha256Str(fileContent)

	m := validTestManifest(tmpDir)
	m.InstalledFiles = []manifestv1.InstalledFile{
		{
			Path:   installedFilePath,
			SHA256: fileHash,
			Mode:   "0644",
			Owner:  "root",
			Group:  "root",
			Size:   int64(len(fileContent)),
		},
	}
	m.InstalledPackages = []manifestv1.InstalledPackage{
		{
			PackageReference: "fplogin-theme-sddm",
			Version:          "1.0.0",
		},
	}

	if err := Publish(path, m); err != nil {
		t.Fatal(err)
	}

	// Verify intact files
	mismatches, err := VerifyFiles(m)
	if err != nil || len(mismatches) != 0 {
		t.Fatalf("expected 0 mismatches, got %v (err: %v)", mismatches, err)
	}

	// Modify file
	_ = os.WriteFile(installedFilePath, []byte("Tampered content"), 0o644)

	mismatches, err = VerifyFiles(m)
	if err != nil || len(mismatches) != 1 || mismatches[0].Kind != "modified" {
		t.Fatalf("expected 1 modified mismatch, got %v", mismatches)
	}

	// Uninstall without force must fail
	fakePlat := &fakePlatformApplier{}
	cfg := UninstallConfig{
		ManifestPath: path,
		Force:        false,
		Platform:     fakePlat,
	}

	err = Uninstall(context.Background(), cfg)
	if !errors.Is(err, ErrModifiedFiles) {
		t.Fatalf("expected ErrModifiedFiles, got %v", err)
	}

	// Uninstall with Force: must succeed, remove file, remove manifest, call restore DM
	cfg.Force = true
	if err := Uninstall(context.Background(), cfg); err != nil {
		t.Fatalf("Uninstall with Force failed: %v", err)
	}

	if _, err := os.Stat(installedFilePath); !os.IsNotExist(err) {
		t.Errorf("expected installed file to be removed, err: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected manifest to be removed, err: %v", err)
	}

	// Check platform was invoked for package removal and restore DM
	if len(fakePlat.calledOps) != 2 {
		t.Errorf("expected 2 platform ops (pkg remove + restore DM), got %d", len(fakePlat.calledOps))
	}
}

func TestPublish_SecretRejection(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "manifest.json")

	m := validTestManifest(tmpDir)
	// Inject secret into verification check message
	m.Verification.Checks = []manifestv1.VerificationCheck{
		{
			CheckID:  "chk-1",
			Status:   "passed",
			Evidence: []json.RawMessage{json.RawMessage(`{"password":"leaked-password-123"}`)},
		},
	}

	err := Publish(path, m)
	if !errors.Is(err, ErrSecretDetected) {
		t.Fatalf("expected ErrSecretDetected, got %v", err)
	}
}
