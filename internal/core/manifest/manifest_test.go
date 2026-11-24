package manifest

import (
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

func validTestManifest() manifestv1.InstallManifest {
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.InstallManifest{
		SchemaVersion:  manifestv1.SchemaVersion,
		TransactionID:  "tx-1",
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

func sha256Str(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestPublishLoadAndRemove(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "manifest.json")

	m := validTestManifest()
	if err := Publish(path, m); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.FPLoginVersion != "0.2.0" || loaded.TransactionID != "tx-1" {
		t.Fatalf("unexpected manifest identity: %+v", loaded)
	}

	if err := Remove(path); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if _, err := Load(path); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("expected ErrManifestNotFound after Remove, got %v", err)
	}
	if err := Remove(path); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("expected ErrManifestNotFound on second Remove, got %v", err)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realPath := filepath.Join(tmpDir, "real.json")
	linkPath := filepath.Join(tmpDir, "manifest.json")
	if err := Publish(realPath, validTestManifest()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(linkPath); !errors.Is(err, ErrCorruptManifest) {
		t.Fatalf("expected ErrCorruptManifest for symlink manifest, got %v", err)
	}
}

func TestVerifyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	installedFilePath := filepath.Join(tmpDir, "asset.txt")
	fileContent := []byte("Initial asset content")
	if err := os.WriteFile(installedFilePath, fileContent, 0o644); err != nil {
		t.Fatal(err)
	}

	m := validTestManifest()
	m.InstalledFiles = []manifestv1.InstalledFile{
		{
			Path:   installedFilePath,
			SHA256: sha256Str(fileContent),
			Mode:   "0644",
			Owner:  "root",
			Group:  "root",
			Size:   int64(len(fileContent)),
		},
	}

	mismatches, err := VerifyFiles(m)
	if err != nil || len(mismatches) != 0 {
		t.Fatalf("expected 0 mismatches, got %v (err: %v)", mismatches, err)
	}

	if err := os.WriteFile(installedFilePath, []byte("Tampered content"), 0o644); err != nil {
		t.Fatal(err)
	}
	mismatches, err = VerifyFiles(m)
	if err != nil || len(mismatches) != 1 || mismatches[0].Kind != "modified" {
		t.Fatalf("expected 1 modified mismatch, got %v (err: %v)", mismatches, err)
	}

	if err := os.Remove(installedFilePath); err != nil {
		t.Fatal(err)
	}
	mismatches, err = VerifyFiles(m)
	if err != nil || len(mismatches) != 1 || mismatches[0].Kind != "missing" {
		t.Fatalf("expected 1 missing mismatch, got %v (err: %v)", mismatches, err)
	}
}

func TestPublish_SecretRejection(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "manifest.json")

	m := validTestManifest()
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
