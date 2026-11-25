package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentConfigRoundTripAndSymlinkRejection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "90-fplogin.conf")

	// Default when absent
	cfg, exists, err := loadPersistentConfig(path)
	if err != nil || exists || !cfg.AutoLegacy || cfg.Overlay || cfg.Timeout != 30 || cfg.Theme != "preserve" {
		t.Fatalf("unexpected default config: %+v exists=%v err=%v", cfg, exists, err)
	}

	// Save custom persistent settings
	want := persistentConfig{AutoLegacy: false, Overlay: true, Timeout: 45, Theme: "fplogin"}
	if err := savePersistentConfig(path, want); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	got, exists, err := loadPersistentConfig(path)
	if err != nil || !exists || got != want {
		t.Fatalf("round-trip mismatch: got=%+v want=%+v exists=%v err=%v", got, want, exists, err)
	}

	// Switch back to preserve theme
	want2 := persistentConfig{AutoLegacy: true, Overlay: false, Timeout: 30, Theme: "preserve"}
	if err := savePersistentConfig(path, want2); err != nil {
		t.Fatalf("save preserve failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[General]\nAutoFingerprintForLegacyThemes=true\n" {
		t.Fatalf("unexpected canonical content: %q", string(raw))
	}

	// Reject symlink target
	sym := filepath.Join(dir, "sym.conf")
	if err := os.Symlink(path, sym); err != nil {
		t.Fatal(err)
	}
	if err := savePersistentConfig(sym, want2); err == nil {
		t.Fatal("expected symlink rejection on save")
	}
	if _, _, err := loadPersistentConfig(sym); err == nil {
		t.Fatal("expected symlink rejection on load")
	}

	// Reject unsafe theme names
	for _, bad := range []string{"../etc", "a/b", "bad\n[General]", ""} {
		if validateThemeName(bad) == nil {
			t.Fatalf("expected theme name %q to be rejected", bad)
		}
	}
}
