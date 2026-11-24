package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fplogin/internal/core/analyze"
	"fplogin/internal/core/report"
	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func validateReportAndFormat(t *testing.T, rep analyzerv1.Report) (string, string) {
	t.Helper()
	jsonBytes, err := report.FormatJSON(rep)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	if _, err := analyzerv1.DecodeReport(jsonBytes); err != nil {
		t.Fatalf("DecodeReport schema validation failed: %v\n%s", err, string(jsonBytes))
	}
	for _, f := range rep.Findings {
		fBytes, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal finding %s: %v", f.FindingID, err)
		}
		if _, err := analyzerv1.DecodeFinding(fBytes); err != nil {
			t.Fatalf("DecodeFinding schema validation failed for %s: %v", f.FindingID, err)
		}
	}

	// Mandatory baseline limitations (Audit A8)
	hasBlindSpots := false
	hasLoginScope := false
	for _, lim := range rep.Limitations {
		if lim.Code == "known_blind_spots" {
			hasBlindSpots = true
		}
		if lim.Code == "login_scope_only" {
			hasLoginScope = true
		}
	}
	if !hasBlindSpots || !hasLoginScope {
		t.Errorf("missing mandatory baseline limitations in %+v", rep.Limitations)
	}

	term := report.FormatTerminal(rep)
	if strings.Contains(strings.ToLower(term), "fingerprint login is safe") {
		t.Errorf("banned overclaim phrase found in terminal output:\n%s", term)
	}
	if !strings.Contains(term, "sudo, su, polkit, ssh, screen lockers") {
		t.Errorf("missing login vs independent auth distinction in terminal output:\n%s", term)
	}
	return string(jsonBytes), term
}

func findByID(findings []analyzerv1.Finding, id string) (analyzerv1.Finding, bool) {
	for _, f := range findings {
		if f.FindingID == id {
			return f, true
		}
	}
	return analyzerv1.Finding{}, false
}

func TestIntegration_Analyzer_FixtureMatrix(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	// 1. KWallet family
	t.Run("1_kwallet_pam_confirmed_and_package_only_and_session_only", func(t *testing.T) {
		// 1a. PAM + user config -> confirmed degraded
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte(
			"auth optional pam_kwallet5.so\nsession optional pam_kwallet5.so auto_start\n",
		), 0o644)
		userHome := filepath.Join(root, "home", "bob")
		_ = os.MkdirAll(filepath.Join(userHome, ".config"), 0o755)
		_ = os.WriteFile(filepath.Join(userHome, ".config", "kwalletrc"), []byte("[Wallet]\nEnabled=true\n"), 0o644)
		_ = os.MkdirAll(filepath.Join(userHome, ".local", "share", "kwalletd"), 0o755)
		_ = os.WriteFile(filepath.Join(userHome, ".local", "share", "kwalletd", "kdewallet.kwl"), []byte("KWALLET_SECRET_SENTINEL"), 0o600)

		rep, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, Username: "bob", UserHome: userHome, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		rawJSON, term := validateReportAndFormat(t, rep)
		if strings.Contains(rawJSON, "KWALLET_SECRET_SENTINEL") || strings.Contains(term, "KWALLET_SECRET_SENTINEL") {
			t.Fatal("wallet file contents leaked into report")
		}
		f, ok := findByID(rep.Findings, "kwallet5_pam_autounlock")
		if !ok || f.Impact.Severity != "degraded" || f.Confidence != "confirmed" {
			t.Fatalf("expected confirmed degraded kwallet5_pam_autounlock, got %+v", rep.Findings)
		}

		// 1b. Package-only without PAM -> NEVER confirmed
		rootPkg := t.TempDir()
		_ = os.MkdirAll(filepath.Join(rootPkg, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(rootPkg, "etc", "pam.d", "display-manager"), []byte("auth required pam_unix.so\n"), 0o644)
		repPkg, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: rootPkg, Username: "bob", UserHome: filepath.Join(rootPkg, "home", "bob"), ServiceName: "display-manager",
			PlatformFacts: &platformv1.PlatformAnalyzerFacts{
				Scope:       "biometric_login_difference",
				CollectedAt: now,
				Evidence: []protocol.Evidence{
					{Source: "platform", Kind: "package", Subject: "kwallet", ObservedValue: "version=6.0-1, status=installed", Timestamp: now},
				},
				ProbeErrors: []platformv1.ProbeError{},
			},
		})
		if err != nil {
			t.Fatalf("Analyze package-only: %v", err)
		}
		validateReportAndFormat(t, repPkg)
		fPkg, ok := findByID(repPkg.Findings, "kwallet_installed_no_pam")
		if !ok || fPkg.Confidence == "confirmed" || fPkg.Impact.Severity != "informational" {
			t.Fatalf("package-only kwallet must be informational/non-confirmed, got %+v", repPkg.Findings)
		}

		// 1c. Session-only -> severity none
		rootSess := t.TempDir()
		_ = os.MkdirAll(filepath.Join(rootSess, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(rootSess, "etc", "pam.d", "display-manager"), []byte("auth required pam_unix.so\n"), 0o644)
		_ = os.MkdirAll(filepath.Join(rootSess, "etc", "xdg", "autostart"), 0o755)
		_ = os.WriteFile(filepath.Join(rootSess, "etc", "xdg", "autostart", "kwalletd.desktop"), []byte("[Desktop Entry]\nExec=kwalletd6\n"), 0o644)
		repSess, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: rootSess, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze session-only: %v", err)
		}
		validateReportAndFormat(t, repSess)
		fSess, ok := findByID(repSess.Findings, "kwallet_session_startup")
		if !ok || fSess.Impact.Severity != "none" {
			t.Fatalf("expected severity=none kwallet_session_startup, got %+v", repSess.Findings)
		}
	})

	// 2. GNOME Keyring family
	t.Run("2_gnome_keyring_confirmed_vs_empty_dir_likely_vs_session", func(t *testing.T) {
		// 2a. PAM + login.keyring -> confirmed degraded
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte(
			"auth optional pam_gnome_keyring.so\nsession optional pam_gnome_keyring.so auto_start\n",
		), 0o644)
		userHome := filepath.Join(root, "home", "alice")
		_ = os.MkdirAll(filepath.Join(userHome, ".local", "share", "keyrings"), 0o755)
		_ = os.WriteFile(filepath.Join(userHome, ".local", "share", "keyrings", "login.keyring"), []byte("KEYRING_SECRET_SENTINEL"), 0o600)

		rep, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, Username: "alice", UserHome: userHome, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		rawJSON, term := validateReportAndFormat(t, rep)
		if strings.Contains(rawJSON, "KEYRING_SECRET_SENTINEL") || strings.Contains(term, "KEYRING_SECRET_SENTINEL") {
			t.Fatal("keyring file contents leaked into report")
		}
		f, ok := findByID(rep.Findings, "gnome_keyring_pam_autounlock")
		if !ok || f.Confidence != "confirmed" || f.Impact.Severity != "degraded" {
			t.Fatalf("expected confirmed degraded gnome_keyring_pam_autounlock, got %+v", rep.Findings)
		}

		// 2b. PAM + empty keyrings dir -> likely (NOT confirmed!)
		rootEmpty := t.TempDir()
		_ = os.MkdirAll(filepath.Join(rootEmpty, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(rootEmpty, "etc", "pam.d", "display-manager"), []byte("auth optional pam_gnome_keyring.so\n"), 0o644)
		emptyHome := filepath.Join(rootEmpty, "home", "alice")
		_ = os.MkdirAll(filepath.Join(emptyHome, ".local", "share", "keyrings"), 0o755)
		repEmpty, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: rootEmpty, Username: "alice", UserHome: emptyHome, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze empty keyrings: %v", err)
		}
		validateReportAndFormat(t, repEmpty)
		fEmpty, ok := findByID(repEmpty.Findings, "gnome_keyring_pam_autounlock")
		if !ok || fEmpty.Confidence != "likely" {
			t.Fatalf("empty keyrings dir must yield likely (not confirmed), got %+v", fEmpty)
		}

		// 2c. User systemd startup without PAM -> none
		rootUnit := t.TempDir()
		_ = os.MkdirAll(filepath.Join(rootUnit, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(rootUnit, "etc", "pam.d", "display-manager"), []byte("auth required pam_unix.so\n"), 0o644)
		unitHome := filepath.Join(rootUnit, "home", "alice")
		_ = os.MkdirAll(filepath.Join(unitHome, ".config", "systemd", "user"), 0o755)
		_ = os.WriteFile(filepath.Join(unitHome, ".config", "systemd", "user", "gnome-keyring.service"), []byte("[Service]\nExecStart=/usr/bin/gnome-keyring-daemon\n"), 0o644)
		repUnit, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: rootUnit, Username: "alice", UserHome: unitHome, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze user systemd: %v", err)
		}
		validateReportAndFormat(t, repUnit)
		fUnit, ok := findByID(repUnit.Findings, "gnome_keyring_session_startup")
		if !ok || fUnit.Impact.Severity != "none" {
			t.Fatalf("expected severity=none gnome_keyring_session_startup, got %+v", repUnit.Findings)
		}
	})

	// 3. Clean system / no wallet
	t.Run("3_clean_system_no_wallet_honest_wording", func(t *testing.T) {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte(
			"auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_unix.so\n",
		), 0o644)
		userHome := filepath.Join(root, "home", "clean")
		_ = os.MkdirAll(userHome, 0o755)

		rep, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, Username: "clean", UserHome: userHome, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		_, term := validateReportAndFormat(t, rep)
		if len(rep.Findings) != 0 {
			t.Errorf("expected 0 findings on clean system, got %+v", rep.Findings)
		}
		if !strings.Contains(term, "No known PAM-coupled password-derived facilities were observed") {
			t.Errorf("unexpected clean wording:\n%s", term)
		}
	})

	// 4. LUKS crypttab boot-time vs keyscript vs pam_mount login-time
	t.Run("4_luks_boot_vs_keyscript_vs_pam_mount", func(t *testing.T) {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte(
			"auth optional pam_mount.so\nsession optional pam_mount.so\n",
		), 0o644)
		_ = os.MkdirAll(filepath.Join(root, "etc", "security"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "security", "pam_mount.conf.xml"), []byte(
			`<pam_mount><volume user="alice" fstype="crypt" path="/dev/nvme0n1p3" mountpoint="/home/alice" /></pam_mount>`,
		), 0o644)
		_ = os.WriteFile(filepath.Join(root, "etc", "crypttab"), []byte(
			"home_boot UUID=1111 none luks\nhome_ks UUID=2222 none luks,keyscript=/usr/local/bin/ks\n",
		), 0o644)

		rep, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, Username: "alice", UserHome: filepath.Join(root, "home", "alice"), ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		validateReportAndFormat(t, rep)

		fMount, ok := findByID(rep.Findings, "pam_mount_login_volume")
		if !ok || fMount.Confidence != "confirmed" || fMount.Impact.Severity != "blocked" {
			t.Fatalf("expected confirmed blocked pam_mount_login_volume, got %+v", fMount)
		}
		fBoot, ok := findByID(rep.Findings, "luks_crypttab_boot_unlock")
		if !ok || fBoot.Impact.Severity != "none" {
			t.Fatalf("expected boot crypttab severity=none, got %+v", fBoot)
		}
		fKS, ok := findByID(rep.Findings, "luks_crypttab_login_coupled")
		if !ok || fKS.Confidence != "unknown" {
			t.Fatalf("expected keyscript crypttab confidence=unknown, got %+v", fKS)
		}
	})

	// 5. systemd-homed (confirmed identity vs module-only likely)
	t.Run("5_systemd_homed_confirmed_and_module_only", func(t *testing.T) {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte(
			"-auth [success=2 default=ignore] pam_systemd_home.so\n-session optional pam_systemd_home.so\n",
		), 0o644)
		_ = os.MkdirAll(filepath.Join(root, "var", "lib", "systemd", "home"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "var", "lib", "systemd", "home", "homeduser.identity"), []byte("{}"), 0o644)

		// Managed user -> confirmed blocked
		repManaged, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, Username: "homeduser", UserHome: filepath.Join(root, "home", "homeduser"), ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze managed: %v", err)
		}
		validateReportAndFormat(t, repManaged)
		fManaged, ok := findByID(repManaged.Findings, "systemd_homed_encryption")
		if !ok || fManaged.Confidence != "confirmed" || fManaged.Impact.Severity != "blocked" {
			t.Fatalf("expected confirmed blocked systemd_homed_encryption, got %+v", repManaged.Findings)
		}

		// Non-homed local user -> informational likely (not false blocked)
		repLocal, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, Username: "localuser", UserHome: filepath.Join(root, "home", "localuser"), ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze local: %v", err)
		}
		validateReportAndFormat(t, repLocal)
		fLocal, ok := findByID(repLocal.Findings, "systemd_homed_pam_module")
		if !ok || fLocal.Confidence != "likely" || fLocal.Impact.Severity != "informational" {
			t.Fatalf("expected informational likely systemd_homed_pam_module for non-homed user, got %+v", repLocal.Findings)
		}
	})

	// 6. Unknown / custom PAM configurations
	t.Run("6_unknown_custom_pam_missing_include_and_custom_module", func(t *testing.T) {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte(
			"auth include missing-auth\nauth optional pam_my_secret_store.so\n",
		), 0o644)

		rep, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
			Root: root, ServiceName: "display-manager",
		})
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		validateReportAndFormat(t, rep)
		fCustom, ok := findByID(rep.Findings, "pam_custom_modules")
		if !ok || fCustom.Confidence != "unknown" {
			t.Fatalf("expected unknown pam_custom_modules, got %+v", rep.Findings)
		}
		fInc, ok := findByID(rep.Findings, "pam_incomplete_analysis")
		if !ok || fInc.Confidence != "unknown" {
			t.Fatalf("expected unknown pam_incomplete_analysis, got %+v", rep.Findings)
		}
	})

	// 7. Biometric readiness (fprintd)
	t.Run("7_biometric_readiness_states", func(t *testing.T) {
		root := t.TempDir()
		_ = os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755)
		_ = os.WriteFile(filepath.Join(root, "etc", "pam.d", "display-manager"), []byte("auth required pam_unix.so\n"), 0o644)

		cases := []struct {
			name    string
			pf      platformv1.PlatformAnalyzerFacts
			wantID  string
			wantSev string
			wantCnf string
		}{
			{
				name: "missing_fprintd_package",
				pf: platformv1.PlatformAnalyzerFacts{
					Scope: "biometric_login_difference", CollectedAt: now,
					Evidence:    []protocol.Evidence{{Source: "platform", Kind: "package", Subject: "fprintd", ObservedValue: "status=absent", Timestamp: now}},
					ProbeErrors: []platformv1.ProbeError{},
				},
				wantID: "fprintd_package_missing", wantSev: "blocked", wantCnf: "confirmed",
			},
			{
				name: "no_reader",
				pf: platformv1.PlatformAnalyzerFacts{
					Scope: "biometric_login_difference", CollectedAt: now,
					Evidence:    []protocol.Evidence{{Source: "platform", Kind: "command", Subject: "fprintd-list", ObservedValue: "status=no_reader, reader=absent", Timestamp: now}},
					ProbeErrors: []platformv1.ProbeError{},
				},
				wantID: "fprintd_no_reader", wantSev: "blocked", wantCnf: "confirmed",
			},
			{
				name: "no_enrolled_fingers",
				pf: platformv1.PlatformAnalyzerFacts{
					Scope: "biometric_login_difference", CollectedAt: now,
					Evidence:    []protocol.Evidence{{Source: "platform", Kind: "command", Subject: "fprintd-list", ObservedValue: "status=no_enrolled_fingers, reader=present, enrolled_count=0", Timestamp: now}},
					ProbeErrors: []platformv1.ProbeError{},
				},
				wantID: "fprintd_no_enrolled_fingers", wantSev: "blocked", wantCnf: "confirmed",
			},
			{
				name: "enrolled_ready",
				pf: platformv1.PlatformAnalyzerFacts{
					Scope: "biometric_login_difference", CollectedAt: now,
					Evidence:    []protocol.Evidence{{Source: "platform", Kind: "command", Subject: "fprintd-list", ObservedValue: "status=enrolled, reader=present, enrolled_count=2", Timestamp: now}},
					ProbeErrors: []platformv1.ProbeError{},
				},
				wantID: "fprintd_ready", wantSev: "none", wantCnf: "confirmed",
			},
			{
				name: "dbus_probe_error_unknown",
				pf: platformv1.PlatformAnalyzerFacts{
					Scope: "biometric_login_difference", CollectedAt: now,
					Evidence:    []protocol.Evidence{},
					ProbeErrors: []platformv1.ProbeError{{ProbeID: "fprintd.enrollment", Message: "D-Bus unavailable"}},
				},
				wantID: "fprintd_readiness_unknown", wantSev: "informational", wantCnf: "unknown",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pfCopy := tc.pf
				rep, err := analyze.NewEngine().Analyze(context.Background(), analyze.EngineConfig{
					Root: root, ServiceName: "display-manager", PlatformFacts: &pfCopy,
				})
				if err != nil {
					t.Fatalf("Analyze: %v", err)
				}
				validateReportAndFormat(t, rep)
				f, ok := findByID(rep.Findings, tc.wantID)
				if !ok || f.Impact.Severity != tc.wantSev || f.Confidence != tc.wantCnf {
					t.Fatalf("case %s: want (%s, %s, %s), got %+v", tc.name, tc.wantID, tc.wantSev, tc.wantCnf, rep.Findings)
				}
			})
		}
	})
}

func TestIntegration_Analyzer_NoMutation(t *testing.T) {
	tmpDir := t.TempDir()
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte(
		"auth optional pam_kwallet5.so\nauth optional pam_gnome_keyring.so\nauth optional pam_mount.so\n",
	), 0o644)

	userHome := filepath.Join(tmpDir, "home", "bob")
	_ = os.MkdirAll(filepath.Join(userHome, ".config", "autostart"), 0o755)
	_ = os.MkdirAll(filepath.Join(userHome, ".config", "systemd", "user"), 0o755)
	_ = os.MkdirAll(filepath.Join(userHome, ".local", "share", "keyrings"), 0o755)
	_ = os.WriteFile(filepath.Join(userHome, ".config", "kwalletrc"), []byte("[Wallet]\nEnabled=true\n"), 0o644)
	_ = os.WriteFile(filepath.Join(userHome, ".local", "share", "keyrings", "login.keyring"), []byte("encrypted"), 0o600)

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

	rep, err := engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	validateReportAndFormat(t, rep)

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
