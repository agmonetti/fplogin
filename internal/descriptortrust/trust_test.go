package descriptortrust_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fplogin/internal/descriptortrust"
)

func TestPackagedDirectoryChecksAncestors(t *testing.T) {
	if !descriptortrust.Elevated() {
		t.Skip("requires an isolated root namespace with a trusted temporary directory")
	}
	parent := t.TempDir()
	if err := descriptortrust.ValidatePackagedDir(parent); err != nil {
		t.Skipf("temporary directory is not under a trusted root: %v", err)
	}
	child := filepath.Join(parent, "components")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := descriptortrust.ValidatePackagedDir(child); err != nil {
		t.Fatalf("trusted directory rejected: %v", err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	if err := descriptortrust.ValidatePackagedDir(filepath.Join(link, "missing")); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("symlink ancestor not refused: %v", err)
	}
	if err := os.Chmod(parent, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := descriptortrust.ValidatePackagedDir(child); err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("writable ancestor not refused: %v", err)
	}
}

func TestRead_Success(t *testing.T) {
	dir := t.TempDir()
	descPath := filepath.Join(dir, "descriptor.json")
	content := []byte(`{"version":"1.0"}`)
	if err := os.WriteFile(descPath, content, 0o400); err != nil {
		t.Fatal(err)
	}

	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	trusted, err := descriptortrust.Read(policy, descPath, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(trusted.DescriptorData) != string(content) {
		t.Fatalf("data mismatch: %s vs %s", string(trusted.DescriptorData), string(content))
	}
	if trusted.SHA256 == "" {
		t.Fatal("expected non-empty sha256")
	}
}

func TestRead_ExceedsSizeLimit(t *testing.T) {
	dir := t.TempDir()
	descPath := filepath.Join(dir, "descriptor.json")
	content := []byte("12345678901234567890")
	if err := os.WriteFile(descPath, content, 0o400); err != nil {
		t.Fatal(err)
	}

	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	_, err := descriptortrust.Read(policy, descPath, 10)
	if err == nil {
		t.Fatal("expected size limit error, got nil")
	}
}

func TestRead_NonexistentFile(t *testing.T) {
	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	_, err := descriptortrust.Read(policy, "/nonexistent/path/descriptor.json", 1024)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRead_WritableByOthersRejected(t *testing.T) {
	dir := t.TempDir()
	descPath := filepath.Join(dir, "descriptor.json")
	if err := os.WriteFile(descPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(descPath, 0o666); err != nil {
		t.Fatal(err)
	}

	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	_, err := descriptortrust.Read(policy, descPath, 1024)
	if err == nil {
		t.Fatal("expected error for world-writable file, got nil")
	}
}

func TestValidateReferences_Success(t *testing.T) {
	dir := t.TempDir()
	descPath := filepath.Join(dir, "descriptor.json")
	if err := os.WriteFile(descPath, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(binDir, "runner")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\n"), 0o500); err != nil {
		t.Fatal(err)
	}

	assetDir := filepath.Join(dir, "assets")
	if err := os.Mkdir(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}

	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	trusted, err := descriptortrust.Read(policy, descPath, 1024)
	if err != nil {
		t.Fatal(err)
	}

	validated, err := descriptortrust.ValidateReferences(policy, trusted, "bin/runner", "assets")
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if validated.ExecutablePath != exePath {
		t.Fatalf("unexpected executable path: %s", validated.ExecutablePath)
	}
	if validated.AssetRootPath != assetDir {
		t.Fatalf("unexpected asset root path: %s", validated.AssetRootPath)
	}
}

func TestValidateReferences_EscapesDirectory(t *testing.T) {
	dir := t.TempDir()
	descPath := filepath.Join(dir, "descriptor.json")
	if err := os.WriteFile(descPath, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}

	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	trusted, err := descriptortrust.Read(policy, descPath, 1024)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := descriptortrust.ValidateReferences(policy, trusted, "../bin/runner", "assets"); err == nil {
		t.Fatal("expected error for escaping executable path")
	}
	if _, err := descriptortrust.ValidateReferences(policy, trusted, "bin/runner", "../assets"); err == nil {
		t.Fatal("expected error for escaping asset path")
	}
}

func TestValidateReferences_NonExecutableBinary(t *testing.T) {
	dir := t.TempDir()
	descPath := filepath.Join(dir, "descriptor.json")
	if err := os.WriteFile(descPath, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nonExe := filepath.Join(binDir, "not_executable")
	if err := os.WriteFile(nonExe, []byte("data"), 0o400); err != nil {
		t.Fatal(err)
	}

	assetDir := filepath.Join(dir, "assets")
	if err := os.Mkdir(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}

	policy := descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}
	trusted, err := descriptortrust.Read(policy, descPath, 1024)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := descriptortrust.ValidateReferences(policy, trusted, "bin/not_executable", "assets"); err == nil {
		t.Fatal("expected error for non-executable file")
	}
}
