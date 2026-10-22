package analyze

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
)

func TestParsePAM_IncludesAndModules(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)

	// Base sddm file that includes system-login
	sddmContent := `# SDDM PAM configuration
auth     include  system-login
account  include  system-login
session  include  system-login
`
	_ = os.WriteFile(filepath.Join(pamDir, "sddm"), []byte(sddmContent), 0o644)

	// system-login file containing pam_kwallet5 and pam_gnome_keyring
	systemLoginContent := `# system-login
auth     sufficient pam_fprintd.so
auth     optional   pam_kwallet5.so
session  optional   pam_gnome_keyring.so auto_start
session  optional   pam_kwallet5.so auto_start
`
	_ = os.WriteFile(filepath.Join(pamDir, "system-login"), []byte(systemLoginContent), 0o644)

	stack, err := ParsePAM(tmpDir, "sddm", 5)
	if err != nil {
		t.Fatalf("ParsePAM failed: %v", err)
	}

	if len(stack.FilesParsed) != 2 {
		t.Errorf("expected 2 files parsed, got %d: %v", len(stack.FilesParsed), stack.FilesParsed)
	}

	if !stack.HasModule("pam_kwallet5.so", "auth", "session") {
		t.Error("expected pam_kwallet5.so to be detected in auth/session")
	}
	if !stack.HasModule("pam_gnome_keyring.so", "session") {
		t.Error("expected pam_gnome_keyring.so to be detected in session")
	}
	if !stack.HasModule("pam_fprintd.so", "auth") {
		t.Error("expected pam_fprintd.so to be detected in auth")
	}
	if stack.HasModule("pam_nonexistent.so") {
		t.Error("did not expect pam_nonexistent.so")
	}
}

func TestParsePAM_CycleProtection(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)

	// Cycle: a includes b, b includes a
	_ = os.WriteFile(filepath.Join(pamDir, "a"), []byte("auth include b\n"), 0o644)
	_ = os.WriteFile(filepath.Join(pamDir, "b"), []byte("auth include a\n"), 0o644)

	stack, err := ParsePAM(tmpDir, "a", 5)
	if err != nil {
		t.Fatalf("ParsePAM failed on circular includes: %v", err)
	}
	if len(stack.FilesParsed) != 2 {
		t.Errorf("expected 2 files parsed before cycle break, got %d", len(stack.FilesParsed))
	}
}

func TestProbeWallets(t *testing.T) {
	tmpDir := t.TempDir()

	// KWallet enabled
	cfgDir := filepath.Join(tmpDir, ".config")
	_ = os.MkdirAll(cfgDir, 0o755)
	_ = os.WriteFile(filepath.Join(cfgDir, "kwalletrc"), []byte("[Wallet]\nEnabled=true\nFirst Use=false\n"), 0o644)

	// Keyring present
	keyringsDir := filepath.Join(tmpDir, ".local", "share", "keyrings")
	_ = os.MkdirAll(keyringsDir, 0o755)
	_ = os.WriteFile(filepath.Join(keyringsDir, "login.keyring"), []byte("dummy encrypted keyring"), 0o644)

	facts, err := ProbeWallets(tmpDir)
	if err != nil {
		t.Fatalf("ProbeWallets failed: %v", err)
	}

	if !facts.KWalletEnabled {
		t.Error("expected KWalletEnabled true")
	}
	if !facts.GnomeKeyringPresent || !facts.GnomeKeyringHasLogin {
		t.Error("expected GnomeKeyringPresent and GnomeKeyringHasLogin true")
	}
}

func TestProbeStorage(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. systemd-homed identity
	homedDir := filepath.Join(tmpDir, "var", "lib", "systemd", "home")
	_ = os.MkdirAll(homedDir, 0o755)
	_ = os.WriteFile(filepath.Join(homedDir, "alice.identity"), []byte("{}"), 0o644)

	// 2. crypttab
	etcDir := filepath.Join(tmpDir, "etc")
	_ = os.MkdirAll(etcDir, 0o755)
	_ = os.WriteFile(filepath.Join(etcDir, "crypttab"), []byte("home_crypt UUID=123-456 none luks\n"), 0o644)

	facts, err := ProbeStorage(tmpDir, "alice")
	if err != nil {
		t.Fatalf("ProbeStorage failed: %v", err)
	}

	if !facts.SystemdHomedDetected {
		t.Error("expected SystemdHomedDetected true for alice")
	}
	if !facts.CrypttabHasUserHome {
		t.Error("expected CrypttabHasUserHome true for home_crypt")
	}
}

func TestProbeSession(t *testing.T) {
	tmpDir := t.TempDir()

	// autostart desktop file
	autostartDir := filepath.Join(tmpDir, "etc", "xdg", "autostart")
	_ = os.MkdirAll(autostartDir, 0o755)
	_ = os.WriteFile(filepath.Join(autostartDir, "gnome-keyring-secrets.desktop"), []byte("[Desktop Entry]\nName=Keyring\n"), 0o644)

	facts, err := ProbeSession(tmpDir, "")
	if err != nil {
		t.Fatalf("ProbeSession failed: %v", err)
	}

	if !facts.AutostartGnomeKeyring {
		t.Error("expected AutostartGnomeKeyring true")
	}
}

func TestAnalyzeEngine_FullReport(t *testing.T) {
	tmpDir := t.TempDir()
	userHome := filepath.Join(tmpDir, "home", "alice")
	_ = os.MkdirAll(userHome, 0o755)

	// PAM setup
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	sddmContent := "auth optional pam_kwallet5.so\nsession optional pam_kwallet5.so\n"
	_ = os.WriteFile(filepath.Join(pamDir, "sddm"), []byte(sddmContent), 0o644)

	// KWallet setup
	cfgDir := filepath.Join(userHome, ".config")
	_ = os.MkdirAll(cfgDir, 0o755)
	_ = os.WriteFile(filepath.Join(cfgDir, "kwalletrc"), []byte("[Wallet]\nEnabled=true\n"), 0o644)

	engine := NewEngine()
	targetAdapter := "org.fplogin.adapter.sddm"
	targetInstance := "sddm-inst"

	cfg := EngineConfig{
		Root:        tmpDir,
		Username:    "alice",
		UserHome:    userHome,
		ServiceName: "sddm",
		PlatformProvider: analyzerv1.ProviderIdentity{
			ID:               "org.fplogin.platform.arch",
			Version:          "1.0.0",
			DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Target: analyzerv1.Target{
			AdapterID:  &targetAdapter,
			InstanceID: &targetInstance,
		},
		AnalyzerVersion: "0.2.0",
	}

	report, err := engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected at least 1 finding for kwallet autounlock")
	}

	finding := report.Findings[0]
	if finding.FindingID != "kwallet5_pam_autounlock" {
		t.Errorf("unexpected finding ID: %s", finding.FindingID)
	}
	if finding.Impact.Severity != "degraded" {
		t.Errorf("expected degraded severity, got %s", finding.Impact.Severity)
	}
	if finding.Confidence != "confirmed" {
		t.Errorf("expected confirmed confidence, got %s", finding.Confidence)
	}
}
