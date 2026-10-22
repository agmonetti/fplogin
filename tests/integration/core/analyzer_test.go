package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"fplogin/internal/core/analyze"
	"fplogin/internal/core/report"
)

func TestIntegration_Analyzer_PlainPAM_NoDegradation(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)

	// Clean standard PAM without wallet modules
	pamContent := "auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_unix.so\n"
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte(pamContent), 0o644)

	engine := analyze.NewEngine()
	cfg := analyze.EngineConfig{
		Root:        tmpDir,
		ServiceName: "display-manager",
	}

	rep, err := engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, f := range rep.Findings {
		if f.Impact.Severity == "degraded" || f.Impact.Severity == "blocked" {
			t.Errorf("did not expect degraded/blocked finding on plain PAM, got: %s (%s)", f.FindingID, f.Impact.Severity)
		}
	}
}

func TestIntegration_Analyzer_KWallet_ConfirmedDegraded(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)

	pamContent := "auth optional pam_kwallet5.so\nsession optional pam_kwallet5.so auto_start\n"
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte(pamContent), 0o644)

	userHome := filepath.Join(tmpDir, "home", "bob")
	cfgDir := filepath.Join(userHome, ".config")
	_ = os.MkdirAll(cfgDir, 0o755)
	_ = os.WriteFile(filepath.Join(cfgDir, "kwalletrc"), []byte("[Wallet]\nEnabled=true\n"), 0o644)

	engine := analyze.NewEngine()
	cfg := analyze.EngineConfig{
		Root:        tmpDir,
		Username:    "bob",
		UserHome:    userHome,
		ServiceName: "display-manager",
	}

	rep, err := engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, f := range rep.Findings {
		if f.FindingID == "kwallet5_pam_autounlock" {
			found = true
			if f.Impact.Severity != "degraded" {
				t.Errorf("expected degraded severity, got %s", f.Impact.Severity)
			}
			if f.Confidence != "confirmed" {
				t.Errorf("expected confirmed confidence, got %s", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected kwallet5_pam_autounlock finding")
	}

	// Verify terminal output formatting
	terminalOut := report.FormatTerminal(rep)
	if terminalOut == "" {
		t.Error("expected non-empty terminal report")
	}
}

func TestIntegration_Analyzer_NoMutation(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte("auth required pam_unix.so\n"), 0o644)

	userHome := filepath.Join(tmpDir, "home", "bob")
	_ = os.MkdirAll(userHome, 0o755)

	snapBefore, err := treeSnapshot(tmpDir)
	if err != nil {
		t.Fatalf("treeSnapshot failed: %v", err)
	}

	engine := analyze.NewEngine()
	cfg := analyze.EngineConfig{
		Root:        tmpDir,
		Username:    "bob",
		UserHome:    userHome,
		ServiceName: "display-manager",
	}

	_, err = engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	snapAfter, err := treeSnapshot(tmpDir)
	if err != nil {
		t.Fatalf("treeSnapshot failed: %v", err)
	}

	if len(snapBefore) != len(snapAfter) {
		t.Fatalf("Analyzer mutated filesystem! before=%d, after=%d", len(snapBefore), len(snapAfter))
	}
	for k, vBefore := range snapBefore {
		vAfter, ok := snapAfter[k]
		if !ok || vBefore != vAfter {
			t.Fatalf("path %q mutated by analyzer", k)
		}
	}
}
