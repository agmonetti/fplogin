package analyze

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func TestParsePAM_IncludesBracketedSyntaxAndModules(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)

	// Base display-manager file that includes system-login multiple times (normal PAM pattern, NOT a cycle)
	dmContent := `# DM PAM configuration
auth     include  system-login
account  include  system-login
session  include  system-login
`
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte(dmContent), 0o644)

	// system-login using Arch-style bracketed controls and leading '-'
	systemLoginContent := `# system-login
-auth    [success=2 default=ignore]  pam_systemd_home.so
auth     [success=1 default=bad]     pam_unix.so try_first_pass
auth     sufficient                  pam_fprintd.so
auth     optional                    pam_kwallet5.so
auth     optional                    pam_mount.so
session  optional                    pam_gnome_keyring.so auto_start
session  optional                    pam_kwallet5.so auto_start
session  optional                    pam_mount.so
`
	_ = os.WriteFile(filepath.Join(pamDir, "system-login"), []byte(systemLoginContent), 0o644)

	stack, err := ParsePAM(tmpDir, "display-manager", 5)
	if err != nil {
		t.Fatalf("ParsePAM failed: %v", err)
	}

	if len(stack.FilesParsed) != 2 {
		t.Errorf("expected 2 files parsed, got %d: %v", len(stack.FilesParsed), stack.FilesParsed)
	}
	if len(stack.Issues) != 0 {
		t.Errorf("expected zero issues on repeated non-cyclic include, got %+v", stack.Issues)
	}
	for _, ev := range stack.Evidence {
		if ev.Source != "core" {
			t.Errorf("expected core provenance on PAM evidence, got %q", ev.Source)
		}
	}

	for _, mod := range []string{"pam_systemd_home.so", "pam_unix.so", "pam_fprintd.so", "pam_kwallet5.so", "pam_mount.so"} {
		if !stack.HasModule(mod, "auth") {
			t.Errorf("expected %s in auth stack", mod)
		}
	}
	if !stack.HasModule("pam_gnome_keyring.so", "session") {
		t.Error("expected pam_gnome_keyring.so in session stack")
	}
	if stack.HasModule("pam_nonexistent.so") {
		t.Error("did not expect pam_nonexistent.so")
	}
}

func TestParsePAM_Issues_CycleMissingDepthCustom(t *testing.T) {
	t.Run("true_cycle", func(t *testing.T) {
		tmpDir := t.TempDir()
		pamDir := filepath.Join(tmpDir, "etc", "pam.d")
		_ = os.MkdirAll(pamDir, 0o755)
		_ = os.WriteFile(filepath.Join(pamDir, "a"), []byte("auth include b\n"), 0o644)
		_ = os.WriteFile(filepath.Join(pamDir, "b"), []byte("auth include a\n"), 0o644)

		stack, err := ParsePAM(tmpDir, "a", 5)
		if err != nil {
			t.Fatalf("ParsePAM failed on cycle: %v", err)
		}
		if len(stack.FilesParsed) != 2 {
			t.Errorf("expected 2 files parsed before cycle break, got %d", len(stack.FilesParsed))
		}
		foundCycle := false
		for _, iss := range stack.Issues {
			if iss.Code == "pam_include_cycle" {
				foundCycle = true
			}
		}
		if !foundCycle {
			t.Errorf("expected pam_include_cycle issue, got %+v", stack.Issues)
		}
	})

	t.Run("missing_include_and_custom_module", func(t *testing.T) {
		tmpDir := t.TempDir()
		pamDir := filepath.Join(tmpDir, "etc", "pam.d")
		_ = os.MkdirAll(pamDir, 0o755)
		_ = os.WriteFile(filepath.Join(pamDir, "dm"), []byte(
			"auth include nonexistent-stack\nauth optional pam_custom_vault.so\n",
		), 0o644)

		stack, err := ParsePAM(tmpDir, "dm", 5)
		if err != nil {
			t.Fatalf("ParsePAM failed: %v", err)
		}
		foundMissing := false
		for _, iss := range stack.Issues {
			if iss.Code == "pam_missing_include" {
				foundMissing = true
			}
		}
		if !foundMissing {
			t.Errorf("expected pam_missing_include issue, got %+v", stack.Issues)
		}
		if len(stack.CustomModules) != 1 || stack.CustomModules[0].Module != "pam_custom_vault.so" {
			t.Errorf("expected custom module pam_custom_vault.so, got %+v", stack.CustomModules)
		}
	})

	t.Run("depth_truncation", func(t *testing.T) {
		tmpDir := t.TempDir()
		pamDir := filepath.Join(tmpDir, "etc", "pam.d")
		_ = os.MkdirAll(pamDir, 0o755)
		_ = os.WriteFile(filepath.Join(pamDir, "d0"), []byte("auth include d1\n"), 0o644)
		_ = os.WriteFile(filepath.Join(pamDir, "d1"), []byte("auth include d2\n"), 0o644)
		_ = os.WriteFile(filepath.Join(pamDir, "d2"), []byte("auth optional pam_kwallet5.so\n"), 0o644)

		stack, err := ParsePAM(tmpDir, "d0", 1)
		if err != nil {
			t.Fatalf("ParsePAM failed: %v", err)
		}
		foundTrunc := false
		for _, iss := range stack.Issues {
			if iss.Code == "pam_depth_truncated" {
				foundTrunc = true
			}
		}
		if !foundTrunc {
			t.Errorf("expected pam_depth_truncated issue, got %+v", stack.Issues)
		}
	})
}

func TestProbeWallets(t *testing.T) {
	t.Run("configured_kwallet_and_login_keyring", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgDir := filepath.Join(tmpDir, ".config")
		_ = os.MkdirAll(cfgDir, 0o755)
		_ = os.WriteFile(filepath.Join(cfgDir, "kwalletrc"), []byte("[Wallet]\nEnabled=true\nFirst Use=false\n"), 0o644)

		keyringsDir := filepath.Join(tmpDir, ".local", "share", "keyrings")
		_ = os.MkdirAll(keyringsDir, 0o755)
		_ = os.WriteFile(filepath.Join(keyringsDir, "login.keyring"), []byte("SECRET_SENTINEL_DO_NOT_READ"), 0o600)

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
		for _, ev := range facts.Evidence {
			if ev.Source != "core" {
				t.Errorf("expected core source, got %q", ev.Source)
			}
			if strings.Contains(ev.ObservedValue, "SECRET_SENTINEL") {
				t.Error("ProbeWallets leaked keyring file contents")
			}
		}
	})

	t.Run("empty_keyrings_dir_not_confirmed_present", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(tmpDir, ".local", "share", "keyrings"), 0o755)

		facts, err := ProbeWallets(tmpDir)
		if err != nil {
			t.Fatalf("ProbeWallets failed: %v", err)
		}
		if !facts.GnomeKeyringDirExists {
			t.Error("expected GnomeKeyringDirExists true")
		}
		if facts.GnomeKeyringPresent {
			t.Error("empty keyrings directory must NOT set GnomeKeyringPresent")
		}
	})
}

func TestProbeStorage(t *testing.T) {
	tmpDir := t.TempDir()

	homedDir := filepath.Join(tmpDir, "var", "lib", "systemd", "home")
	_ = os.MkdirAll(homedDir, 0o755)
	_ = os.WriteFile(filepath.Join(homedDir, "alice.identity"), []byte("{}"), 0o644)

	secDir := filepath.Join(tmpDir, "etc", "security")
	_ = os.MkdirAll(secDir, 0o755)
	_ = os.WriteFile(filepath.Join(secDir, "pam_mount.conf.xml"), []byte(
		`<pam_mount><volume user="alice" fstype="crypt" path="/dev/sda3" mountpoint="/home/alice" /></pam_mount>`,
	), 0o644)

	etcDir := filepath.Join(tmpDir, "etc")
	_ = os.WriteFile(filepath.Join(etcDir, "crypttab"), []byte(
		"home_crypt UUID=123-456 none luks\nsecret_vol UUID=789-012 none luks,keyscript=/usr/local/bin/mykey\n",
	), 0o644)

	facts, err := ProbeStorage(tmpDir, "alice")
	if err != nil {
		t.Fatalf("ProbeStorage failed: %v", err)
	}

	if !facts.SystemdHomedDetected {
		t.Error("expected SystemdHomedDetected true for alice")
	}
	if !facts.PamMountConfigPresent || facts.PamMountVolumeCount != 1 || !facts.PamMountHomeVolume {
		t.Errorf("unexpected pam_mount facts: %+v", facts)
	}
	if !facts.CrypttabHasUserHome || !facts.CrypttabBootHome || !facts.CrypttabLoginCoupled {
		t.Errorf("unexpected crypttab classification: %+v", facts)
	}
	for _, ev := range facts.Evidence {
		if ev.Source != "core" {
			t.Errorf("expected core source, got %q", ev.Source)
		}
	}
}

func TestProbeStorage_UnreadableCrypttabPropagatesIssue(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 test requires unprivileged user")
	}
	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc")
	_ = os.MkdirAll(etcDir, 0o755)
	ct := filepath.Join(etcDir, "crypttab")
	_ = os.WriteFile(ct, []byte("home UUID=123 none luks\n"), 0o000)
	t.Cleanup(func() { _ = os.Chmod(ct, 0o600) })

	facts, err := ProbeStorage(tmpDir, "alice")
	if err != nil {
		t.Fatalf("ProbeStorage returned fatal error instead of issue: %v", err)
	}
	if len(facts.Issues) == 0 || facts.Issues[0].Code != "storage_read_error" {
		t.Fatalf("expected storage_read_error issue for unreadable crypttab, got %+v", facts.Issues)
	}
}

func TestProbeSession_AutostartAndUserSystemd(t *testing.T) {
	tmpDir := t.TempDir()
	userHome := filepath.Join(tmpDir, "home", "alice")

	// System autostart with Hidden=true (should be ignored)
	sysAuto := filepath.Join(tmpDir, "etc", "xdg", "autostart")
	_ = os.MkdirAll(sysAuto, 0o755)
	_ = os.WriteFile(filepath.Join(sysAuto, "kwalletd.desktop"), []byte("[Desktop Entry]\nHidden=true\nExec=kwalletd5\n"), 0o644)

	// User autostart for gnome-keyring
	userAuto := filepath.Join(userHome, ".config", "autostart")
	_ = os.MkdirAll(userAuto, 0o755)
	_ = os.WriteFile(filepath.Join(userAuto, "custom-secrets.desktop"), []byte("[Desktop Entry]\nExec=/usr/bin/gnome-keyring-daemon --start\n"), 0o644)

	// User systemd wants unit for kwallet
	wantsDir := filepath.Join(userHome, ".config", "systemd", "user", "default.target.wants")
	_ = os.MkdirAll(wantsDir, 0o755)
	_ = os.WriteFile(filepath.Join(wantsDir, "kwallet.service"), []byte("[Service]\nExecStart=/usr/bin/kwalletd6\n"), 0o644)

	facts, err := ProbeSession(tmpDir, userHome)
	if err != nil {
		t.Fatalf("ProbeSession failed: %v", err)
	}
	if !facts.AutostartGnomeKeyring {
		t.Error("expected AutostartGnomeKeyring from ~/.config/autostart")
	}
	if !facts.AutostartKWallet {
		t.Error("expected AutostartKWallet from ~/.config/systemd/user")
	}
	for _, ev := range facts.Evidence {
		if ev.Source != "core" {
			t.Errorf("expected core source, got %q", ev.Source)
		}
	}
}

func TestResolveUserHome(t *testing.T) {
	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc")
	_ = os.MkdirAll(etcDir, 0o755)
	_ = os.WriteFile(filepath.Join(etcDir, "passwd"), []byte(
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/srv/users/alice:/bin/zsh\n",
	), 0o644)

	home, found, err := ResolveUserHome(tmpDir, "alice")
	if err != nil || !found {
		t.Fatalf("ResolveUserHome(alice) = (%q, %v, %v)", home, found, err)
	}
	want := filepath.Join(tmpDir, "srv", "users", "alice")
	if home != want {
		t.Errorf("expected %q, got %q", want, home)
	}

	_, found, err = ResolveUserHome(tmpDir, "nobody-here")
	if err != nil || found {
		t.Errorf("expected missing user to return (false, nil), got (%v, %v)", found, err)
	}
}

func TestClassifier_PackagePresenceAloneNeverConfirmed(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	pf := &platformv1.PlatformAnalyzerFacts{
		Scope:       "biometric_login_difference",
		CollectedAt: now,
		Evidence: []protocol.Evidence{
			{Source: "platform", Kind: "package", Subject: "kwallet", ObservedValue: "version=6.0-1, status=installed", Timestamp: now},
			{Source: "platform", Kind: "package", Subject: "gnome-keyring", ObservedValue: "version=48.0-1, status=installed", Timestamp: now},
			{Source: "platform", Kind: "package", Subject: "pam_mount", ObservedValue: "version=2.20-1, status=installed", Timestamp: now},
		},
		ProbeErrors: []platformv1.ProbeError{},
	}

	c := NewClassifier()
	findings := c.ClassifyWithContext(nil, nil, nil, nil, nil, pf)
	if len(findings) != 3 {
		t.Fatalf("expected 3 informational findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Confidence == "confirmed" {
			t.Errorf("package presence alone for %s must NEVER be classified as confirmed", f.FindingID)
		}
		if f.Impact.Severity == "degraded" || f.Impact.Severity == "blocked" {
			t.Errorf("package presence alone for %s must not be degraded/blocked, got %s", f.FindingID, f.Impact.Severity)
		}
	}
}

func TestClassifier_OptionalPAMHookWhenPackageAbsentIsNotDegraded(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte(
		"-auth optional pam_kwallet5.so\n-session optional pam_kwallet5.so auto_start\n"+
			"-auth optional pam_gnome_keyring.so\n-session optional pam_gnome_keyring.so auto_start\n",
	), 0o644)

	now := time.Now().UTC().Format(time.RFC3339)
	pf := &platformv1.PlatformAnalyzerFacts{
		Scope:       "biometric_login_difference",
		CollectedAt: now,
		Evidence: []protocol.Evidence{
			{Source: "platform", Kind: "package", Subject: "kwallet-pam", ObservedValue: "status=absent", Timestamp: now},
			{Source: "platform", Kind: "package", Subject: "gnome-keyring", ObservedValue: "status=absent", Timestamp: now},
		},
		ProbeErrors: []platformv1.ProbeError{},
	}

	rep, err := NewEngine().Analyze(context.Background(), EngineConfig{
		Root:          tmpDir,
		Username:      "alice",
		UserHome:      filepath.Join(tmpDir, "home", "alice"),
		ServiceName:   "display-manager",
		PlatformFacts: pf,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 non-degraded findings, got %+v", rep.Findings)
	}
	for _, f := range rep.Findings {
		if f.Impact.Severity != "none" || f.Confidence != "confirmed" {
			t.Errorf("expected severity=none confidence=confirmed for absent optional PAM module %s, got %s/%s", f.FindingID, f.Impact.Severity, f.Confidence)
		}
	}
}

func TestAnalyzeEngine_FullReportAndMandatoryLimitations(t *testing.T) {
	tmpDir := t.TempDir()
	userHome := filepath.Join(tmpDir, "home", "alice")
	_ = os.MkdirAll(userHome, 0o755)

	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte("auth optional pam_kwallet5.so\nsession optional pam_kwallet5.so\n"), 0o644)

	cfgDir := filepath.Join(userHome, ".config")
	_ = os.MkdirAll(cfgDir, 0o755)
	_ = os.WriteFile(filepath.Join(cfgDir, "kwalletrc"), []byte("[Wallet]\nEnabled=true\n"), 0o644)

	engine := NewEngine()
	targetAdapter := "org.fplogin.adapter.example"
	targetInstance := "dm-inst"

	cfg := EngineConfig{
		Root:        tmpDir,
		Username:    "alice",
		UserHome:    userHome,
		ServiceName: "display-manager",
		PlatformProvider: analyzerv1.ProviderIdentity{
			ID:               "org.fplogin.platform.example",
			Version:          "1.0.0",
			DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Target: analyzerv1.Target{
			AdapterID:  &targetAdapter,
			InstanceID: &targetInstance,
		},
		AnalyzerVersion: "0.2.0",
	}

	rep, err := engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(rep.Findings) == 0 {
		t.Fatal("expected at least 1 finding for kwallet autounlock")
	}
	finding := rep.Findings[0]
	if finding.FindingID != "kwallet5_pam_autounlock" || finding.Impact.Severity != "degraded" || finding.Confidence != "confirmed" {
		t.Errorf("unexpected finding: %+v", finding)
	}
	for _, ev := range finding.Evidence {
		if ev.Source != "core" {
			t.Errorf("expected core evidence source, got %q", ev.Source)
		}
	}

	seenCodes := map[string]bool{}
	for _, lim := range rep.Limitations {
		seenCodes[lim.Code] = true
	}
	if !seenCodes["known_blind_spots"] || !seenCodes["login_scope_only"] {
		t.Errorf("expected mandatory baseline limitations, got %+v", rep.Limitations)
	}
}
