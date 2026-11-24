package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func TestAnalyzerProber_HealthyAllProbes(t *testing.T) {
	tmpDir := t.TempDir()
	pamFile := filepath.Join(tmpDir, "pam_fprintd.so")
	_ = os.WriteFile(pamFile, []byte("elf"), 0o755)
	fprintdBin := filepath.Join(tmpDir, "fprintd-list")
	_ = os.WriteFile(fprintdBin, []byte("bin"), 0o755)

	dbusDir := filepath.Join(tmpDir, "dbus")
	_ = os.MkdirAll(dbusDir, 0o755)
	_ = os.WriteFile(filepath.Join(dbusDir, "org.freedesktop.secrets.service"), []byte(
		"[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/bin/gnome-keyring-daemon --start --foreground --components=secrets\n",
	), 0o644)
	_ = os.WriteFile(filepath.Join(dbusDir, "org.example.other.service"), []byte(
		"[D-BUS Service]\nName=org.example.Other\nExec=/usr/bin/other\n",
	), 0o644)

	prober := analyzerProber{
		statFile:        os.Stat,
		readDir:         os.ReadDir,
		openFile:        os.Open,
		pamFprintdPath:  pamFile,
		fprintdListPath: fprintdBin,
		dbusServicesDir: dbusDir,
		runCmd: func(_ context.Context, exe string, args ...string) (string, string, error) {
			switch exe {
			case "/usr/bin/pacman-conf":
				return "/var/lib/pacman\n", "", nil
			case "/usr/bin/pacman":
				return "fprintd 1.94.5-1\ngnome-keyring 1:48.0-1\nsddm-fplogin 0.21.0-1\n", "", nil
			case "/usr/bin/systemctl":
				joined := strings.Join(args, " ")
				if strings.Contains(joined, "fprintd.service") {
					return "LoadState=loaded\nActiveState=inactive\nUnitFileState=static\n", "", nil
				}
				return "Id=sddm.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\nId=gdm.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n", "", nil
			case fprintdBin:
				return "found 1 devices\nDevice at /net/reactivated/Fprint/Device/0\nUsing device /net/reactivated/Fprint/Device/0\nFingerprints for user alice on Synaptics:\n - right-index-finger\n - left-index-finger\n", "", nil
			default:
				return "", "", errors.New("unexpected command")
			}
		},
	}

	userJSON, _ := json.Marshal("alice")
	facts := prober.collect(context.Background(), platformv1.CollectAnalyzerFactsPayload{
		Scope:         "biometric_login_difference",
		ProbeIDs:      []string{"fprintd", "packages", "secret_service", "display_managers"},
		TargetContext: protocol.Object{"username": userJSON},
	})

	if err := facts.Validate(); err != nil {
		t.Fatalf("facts.Validate() failed: %v", err)
	}
	if len(facts.ProbeErrors) != 0 {
		t.Fatalf("expected 0 probe errors, got %+v", facts.ProbeErrors)
	}

	assertEvidence := func(kind, subject, substr string) {
		t.Helper()
		for _, ev := range facts.Evidence {
			if ev.Kind == kind && ev.Subject == subject && strings.Contains(ev.ObservedValue, substr) {
				if ev.Source != "platform" {
					t.Errorf("expected source=platform for %s, got %q", subject, ev.Source)
				}
				return
			}
		}
		t.Errorf("missing expected evidence kind=%s subject=%s substr=%q in %+v", kind, subject, substr, facts.Evidence)
	}

	assertEvidence("package", "fprintd", "status=installed")
	assertEvidence("package", "gnome-keyring", "status=installed")
	assertEvidence("package", "kwallet", "status=absent")
	assertEvidence("package", "sddm-fplogin", "role=display-manager")
	assertEvidence("path", pamFile, "status=present")
	assertEvidence("service", "fprintd.service", "load=loaded, active=inactive, enabled=static")
	assertEvidence("command", "fprintd-list", "status=enrolled, reader=present, enrolled_count=2")
	assertEvidence("path", filepath.Join(dbusDir, "org.freedesktop.secrets.service"), "exec=gnome-keyring-daemon")
	assertEvidence("service", "sddm.service", "active=active, enabled=enabled, role=display-manager")
}

func TestAnalyzerProber_NoReaderAndBusFailure(t *testing.T) {
	tmpDir := t.TempDir()
	fprintdBin := filepath.Join(tmpDir, "fprintd-list")
	_ = os.WriteFile(fprintdBin, []byte("bin"), 0o755)

	t.Run("no_reader_reported_explicitly", func(t *testing.T) {
		prober := analyzerProber{
			statFile:        os.Stat,
			readDir:         os.ReadDir,
			openFile:        os.Open,
			pamFprintdPath:  filepath.Join(tmpDir, "missing.so"),
			fprintdListPath: fprintdBin,
			dbusServicesDir: filepath.Join(tmpDir, "no-dbus"),
			runCmd: func(_ context.Context, exe string, _ ...string) (string, string, error) {
				switch exe {
				case "/usr/bin/pacman-conf":
					return "/var/lib/pacman\n", "", nil
				case "/usr/bin/pacman":
					return "fprintd 1.94.5-1\n", "", nil
				case "/usr/bin/systemctl":
					return "LoadState=loaded\nActiveState=inactive\nUnitFileState=static\n", "", nil
				case fprintdBin:
					return "", "Impossible to list: GDBus.Error:net.reactivated.Fprint.Error.NoSuchDevice: No devices available\n", errors.New("exit status 1")
				default:
					return "", "", errors.New("unexpected")
				}
			},
		}

		userJSON, _ := json.Marshal("bob")
		facts := prober.collect(context.Background(), platformv1.CollectAnalyzerFactsPayload{
			Scope:         "biometric_login_difference",
			ProbeIDs:      []string{"fprintd"},
			TargetContext: protocol.Object{"username": userJSON},
		})
		if err := facts.Validate(); err != nil {
			t.Fatalf("facts.Validate: %v", err)
		}
		foundNoReader := false
		foundMissingSO := false
		for _, ev := range facts.Evidence {
			if ev.Subject == "fprintd-list" && strings.Contains(ev.ObservedValue, "status=no_reader") {
				foundNoReader = true
			}
			if strings.HasSuffix(ev.Subject, "missing.so") && ev.ObservedValue == "status=absent" {
				foundMissingSO = true
			}
		}
		if !foundNoReader || !foundMissingSO {
			t.Fatalf("expected no_reader and missing pam_fprintd evidence, got %+v", facts.Evidence)
		}
	})

	t.Run("dbus_error_becomes_probe_error_not_fabricated_absence", func(t *testing.T) {
		prober := analyzerProber{
			statFile:        os.Stat,
			readDir:         os.ReadDir,
			openFile:        os.Open,
			pamFprintdPath:  filepath.Join(tmpDir, "missing.so"),
			fprintdListPath: fprintdBin,
			dbusServicesDir: filepath.Join(tmpDir, "no-dbus"),
			runCmd: func(_ context.Context, exe string, _ ...string) (string, string, error) {
				switch exe {
				case "/usr/bin/pacman-conf":
					return "/var/lib/pacman\n", "", nil
				case "/usr/bin/pacman":
					return "fprintd 1.94.5-1\n", "", nil
				default:
					return "", "System has not been booted with systemd as init system", errors.New("exit status 1")
				}
			},
		}

		userJSON, _ := json.Marshal("bob")
		facts := prober.collect(context.Background(), platformv1.CollectAnalyzerFactsPayload{
			Scope:         "biometric_login_difference",
			ProbeIDs:      []string{"fprintd", "display_managers"},
			TargetContext: protocol.Object{"username": userJSON},
		})
		if err := facts.Validate(); err != nil {
			t.Fatalf("facts.Validate: %v", err)
		}
		if len(facts.ProbeErrors) < 3 {
			t.Fatalf("expected probe errors for fprintd.service, fprintd.enrollment, display_managers; got %+v", facts.ProbeErrors)
		}
	})
}

func TestHandleRequest_CollectAnalyzerFacts_RejectsNonLocalRoot(t *testing.T) {
	payload, _ := json.Marshal(platformv1.CollectAnalyzerFactsPayload{
		Scope:    "biometric_login_difference",
		ProbeIDs: []string{"packages"},
	})
	req := platformv1.Request{
		ProtocolVersion: protocol.Version{Major: 1, Minor: 0},
		RequestID:       "11111111-1111-4111-8111-111111111111",
		Operation:       "CollectAnalyzerFacts",
		CoreVersion:     "0.2.0",
		Context: protocol.HostContext{
			Root:         "/nonlocal-fixture",
			Platform:     protocol.Object{},
			Architecture: "x86_64",
			Locale:       "C",
			DryRun:       true,
			Deadline:     time.Now().Add(5 * time.Second).UTC().Format(time.RFC3339),
		},
		Payload: payload,
	}
	_, err := handleRequest(req)
	var opErr *opError
	if !errors.As(err, &opErr) || opErr.code != "host_read_failed" {
		t.Fatalf("expected host_read_failed for non-/ root, got %v", err)
	}
}
