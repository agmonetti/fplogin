package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fplogin/internal/core/install"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func TestCLISafeguardsAndHelp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root CLI safeguard tests require an unprivileged user")
	}
	bin := filepath.Join(t.TempDir(), "fplogin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build fplogin: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"install"}, 1, "Error: install requires root privileges"},
		{[]string{"install", "--artifacts-dir", "/nonexistent"}, 1, "Error: install requires root privileges"},
		{[]string{"install", "--yes", "--adapter-dir", "/nonexistent"}, 2, "flag provided but not defined"},
		{[]string{"uninstall"}, 1, "Error: uninstall requires root privileges"},
		{[]string{"uninstall", "--yes"}, 1, "Error: uninstall requires root privileges"},
		{[]string{"uninstall", "--force", "--manifest", "/nonexistent"}, 2, "flag provided but not defined"},
		{[]string{"recover"}, 1, "Error: recover requires root privileges"},
		{[]string{"update"}, 1, "Error: update: requires root privileges"},
		{[]string{"update", "--help"}, 0, "Compares SHA-256 checksums"},
		{[]string{"install", "--dry-run", "--yes"}, 2, "flag provided but not defined"},
		{[]string{"install", "--dry-run", "--adapter-dir=/nonexistent"}, 2, "flag provided but not defined"},
		{[]string{"help"}, 0, "recover"},
		{[]string{"install", "--help"}, 0, "--artifacts-dir"},
		{[]string{"uninstall", "--help"}, 0, "-modified-files"},
		{[]string{"recover", "--help"}, 0, "Reconciles any interrupted"},
		{[]string{"status", "--help"}, 0, "Path to install manifest"},
		{[]string{"analyze", "--help"}, 0, "Output report as JSON"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, tc.args...)
			cmd.Dir = t.TempDir()
			out, err := cmd.CombinedOutput()
			if err != nil && cmd.ProcessState == nil {
				t.Fatal(err)
			}
			code := cmd.ProcessState.ExitCode()
			if code != tc.code || !strings.Contains(string(out), tc.want) {
				t.Fatalf("exit %d, output %q; want exit %d and %q", code, out, tc.code, tc.want)
			}
			if entries, err := os.ReadDir(cmd.Dir); err != nil || len(entries) != 0 {
				t.Fatalf("unexpected files in working directory: %v (%v)", entries, err)
			}
		})
	}
}

func TestCLI_AnalyzeOfflineFixtureUsesPasswdAndNonZeroMetadata(t *testing.T) {
	tmpRoot := t.TempDir()
	pamDir := filepath.Join(tmpRoot, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	_ = os.WriteFile(filepath.Join(pamDir, "sddm"), []byte(
		"auth optional pam_gnome_keyring.so\nsession optional pam_gnome_keyring.so auto_start\n",
	), 0o644)

	// Non-standard home path in <root>/etc/passwd to prove passwd resolution is used (not /home/<user>).
	customHome := filepath.Join(tmpRoot, "srv", "users", "alice")
	krDir := filepath.Join(customHome, ".local", "share", "keyrings")
	_ = os.MkdirAll(krDir, 0o755)
	_ = os.WriteFile(filepath.Join(krDir, "login.keyring"), []byte("DO_NOT_LEAK_SECRET"), 0o600)
	_ = os.WriteFile(filepath.Join(tmpRoot, "etc", "passwd"), []byte(
		"alice:x:1000:1000:Alice:/srv/users/alice:/bin/bash\n",
	), 0o644)

	bin := filepath.Join(t.TempDir(), "fplogin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build fplogin: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "analyze", "--root", tmpRoot, "--service", "sddm", "--user", "alice", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("fplogin analyze failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "DO_NOT_LEAK_SECRET") {
		t.Fatalf("secret content leaked in output")
	}

	rep, err := analyzerv1.DecodeReport(out)
	if err != nil {
		t.Fatalf("DecodeReport failed: %v\n%s", err, out)
	}
	if rep.PlatformProvider.ID != "org.fplogin.platform.offline" {
		t.Errorf("expected offline provider ID, got %q", rep.PlatformProvider.ID)
	}
	if rep.PlatformProvider.DescriptorSHA256 == strings.Repeat("0", 64) {
		t.Errorf("provider descriptor_sha256 must not be all zeros")
	}

	foundConfirmed := false
	for _, f := range rep.Findings {
		if f.FindingID == "gnome_keyring_pam_autounlock" && f.Confidence == "confirmed" && f.Impact.Severity == "degraded" {
			foundConfirmed = true
		}
	}
	if !foundConfirmed {
		t.Fatalf("expected confirmed gnome_keyring_pam_autounlock resolved via /etc/passwd, got %+v", rep.Findings)
	}

	hasOfflineLim := false
	for _, lim := range rep.Limitations {
		if lim.Code == "offline_root_mode" {
			hasOfflineLim = true
		}
	}
	if !hasOfflineLim {
		t.Errorf("expected offline_root_mode limitation, got %+v", rep.Limitations)
	}
}

func TestRunInstallPostflight_NonFatalAndSUDOUserAware(t *testing.T) {
	t.Setenv("SUDO_USER", "")

	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	origManifest := []byte(`{"sentinel":"untouched"}`)
	if err := os.WriteFile(manifestPath, origManifest, 0o600); err != nil {
		t.Fatal(err)
	}

	bridge := &cliLiveBridge{
		selectedTgt: adapterv1.DetectedTarget{
			InstanceID:  "sddm.service",
			DMID:        "org.freedesktop.DisplayManager.sddm",
			DisplayName: "SDDM",
		},
		lastPlan: adapterv1.ChangePlan{
			AdapterID: "org.fplogin.adapter.sddm",
		},
	}
	bridge.provider.Descriptor = platformv1.Descriptor{
		PlatformID:      "org.fplogin.platform.arch",
		PlatformVersion: "0.1.0",
	}
	bridge.provider.DescriptorSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	var stdout, stderr bytes.Buffer
	runInstallPostflight(context.Background(), bridge, &install.Result{ManifestPath: manifestPath}, &stdout, &stderr)

	out := stdout.String()
	if !strings.Contains(out, "System Analysis: Password-Derived Facilities") {
		t.Fatalf("expected postflight terminal header, got stdout=%q stderr=%q", out, stderr.String())
	}
	if !strings.Contains(out, "postflight_no_desktop_user") {
		t.Errorf("expected postflight_no_desktop_user limitation when SUDO_USER is empty, got:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "fingerprint login is safe") {
		t.Errorf("postflight output must not contain false safety claim:\n%s", out)
	}

	afterManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterManifest, origManifest) {
		t.Fatalf("postflight mutated committed manifest!")
	}
}
