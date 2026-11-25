package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	platformv1 "fplogin/internal/protocol/platform/v1"
)

func TestStaticDescriptorValidates(t *testing.T) {
	desc, err := platformv1.DecodeDescriptor([]byte(staticPlatformDescriptor))
	if err != nil {
		t.Fatalf("static descriptor invalid: %v", err)
	}
	if desc.PlatformID != "org.fplogin.platform.linux" {
		t.Fatalf("unexpected platform_id: %s", desc.PlatformID)
	}
	diskBytes, err := os.ReadFile(filepath.Join("..", "..", "platforms", "linux", "platform.json"))
	if err != nil {
		t.Fatalf("read platforms/linux/platform.json: %v", err)
	}
	if _, err := platformv1.DecodeDescriptor(diskBytes); err != nil {
		t.Fatalf("platforms/linux/platform.json invalid: %v", err)
	}
}

func TestListBinaryCandidates_DetectsPatchedAndStockSDDM(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "bin")
	secDir := filepath.Join(root, "usr", "lib", "x86_64-linux-gnu", "security")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 1. Stock SDDM (no marker) + fprintd present
	if err := os.WriteFile(filepath.Join(binDir, "sddm"), []byte("ELF-stock-sddm-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "fprintd-list"), []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secDir, "pam_fprintd.so"), []byte("ELF"), 0o644); err != nil {
		t.Fatal(err)
	}

	raw, err := listBinaryCandidates(root)
	if err != nil {
		t.Fatalf("listBinaryCandidates stock: %v", err)
	}
	var resp struct {
		Packages []platformv1.PackageCandidate `json:"packages"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	foundStock, foundFprintd := false, false
	for _, p := range resp.Packages {
		if p.PackageReference == "sddm" && p.Installed == "yes" {
			foundStock = true
		}
		if p.PackageReference == "fprintd" && p.Installed == "yes" {
			foundFprintd = true
		}
	}
	if !foundStock || !foundFprintd {
		t.Fatalf("expected stock sddm + fprintd, got %+v", resp.Packages)
	}

	// 2. Patched / upstream-merged SDDM (contains AutoFingerprintForLegacyThemes)
	if err := os.WriteFile(filepath.Join(binDir, "sddm"), []byte("ELF...AutoFingerprintForLegacyThemes..."), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err = listBinaryCandidates(root)
	if err != nil {
		t.Fatalf("listBinaryCandidates patched: %v", err)
	}
	resp.Packages = nil
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	foundPatched := false
	for _, p := range resp.Packages {
		if p.PackageReference == "sddm-fplogin" && p.Installed == "yes" {
			foundPatched = true
		}
	}
	if !foundPatched {
		t.Fatalf("expected sddm-fplogin compatible detection, got %+v", resp.Packages)
	}
}
