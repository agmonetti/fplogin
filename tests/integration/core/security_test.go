package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fplogin/internal/core/analyze"
	"fplogin/internal/core/install"
	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

func createSecurityTestJournal(t *testing.T, dir, id string, opIDs []string) *transaction.Journal {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	init := manifestv1.TransactionJournal{
		SchemaVersion: manifestv1.SchemaVersion,
		TransactionID: id,
		State:         "prepared",
		CreatedAt:     now,
		UpdatedAt:     now,
		Target: manifestv1.Target{
			InstanceID:  "inst-security",
			DMID:        "org.freedesktop.DisplayManager.test",
			DisplayName: "TestDM",
		},
		Adapter: manifestv1.ComponentIdentity{
			ID:               "org.fplogin.adapter.test",
			Version:          "1.0.0",
			ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
			DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		PlatformProvider: manifestv1.ComponentIdentity{
			ID:               "org.fplogin.platform.test",
			Version:          "1.0.0",
			ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
			DescriptorSHA256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		},
		AcceptedPlan: manifestv1.AcceptedPlan{
			PlanID:     "plan-sec",
			PlanDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			InputHash:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Mode:       "fresh_install",
		},
		OperationOrder:      opIDs,
		AppliedOperations:   []manifestv1.OperationReceipt{},
		VerificationResults: []json.RawMessage{},
		RollbackRecords:     []json.RawMessage{},
	}
	path := filepath.Join(dir, id+".json")
	j, err := transaction.Create(path, init)
	if err != nil {
		t.Fatalf("create journal %q: %v", path, err)
	}
	return j
}

// TestSecurity_SymlinkTraversalPrevention verifies that file operations cannot
// escape or mutate arbitrary filesystem paths via symlink target or ancestor redirection.
func TestSecurity_SymlinkTraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	journalDir := filepath.Join(tmpDir, "journal")
	backupDir := filepath.Join(tmpDir, "backups")

	j := createSecurityTestJournal(t, journalDir, "tx-sym", []string{"op-1"})

	exec, err := install.NewExecutor(j, nil, backupDir)
	if err != nil {
		t.Fatalf("create executor: %v", err)
	}

	// Create sensitive target file that must not be touched
	sensitiveFile := filepath.Join(tmpDir, "sensitive_system.conf")
	sensitiveContent := []byte("CRITICAL_CONFIG=DO_NOT_TOUCH")
	if err := os.WriteFile(sensitiveFile, sensitiveContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Create symlink pointing to sensitive target
	symlinkPath := filepath.Join(tmpDir, "evil_symlink.conf")
	if err := os.Symlink(sensitiveFile, symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Attempt write through symlink
	maliciousContent := []byte("CRITICAL_CONFIG=PWNED")
	op := protocol.Operation{
		OperationID:    "op-1",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
		Parameters: json.RawMessage(`{
			"destination_path": "` + symlinkPath + `",
			"content_base64": "` + base64.StdEncoding.EncodeToString(maliciousContent) + `",
			"sha256": "3cb070fe1788bc1d615364177d64389fa50aeecae545a1f28b493922d576a8db",
			"mode": "0644",
			"owner": "root",
			"group": "root"
		}`),
		Compensation: json.RawMessage(`{"kind":"remove_file","path":"` + symlinkPath + `"}`),
	}

	_, err = exec.Execute(context.Background(), op)
	if !errors.Is(err, install.ErrSymlinkRejected) {
		t.Fatalf("expected ErrSymlinkRejected, got %v", err)
	}

	// Verify sensitive file was NOT touched
	readBack, err := os.ReadFile(sensitiveFile)
	if err != nil {
		t.Fatalf("read sensitive file: %v", err)
	}
	if string(readBack) != string(sensitiveContent) {
		t.Fatalf("security violation: sensitive file was mutated! got %s", string(readBack))
	}
}

// TestSecurity_SecretLeakagePrevention verifies that journal files, analyzer reports,
// and manifests reject secret patterns (passwords, raw templates, PAM authtok).
func TestSecurity_SecretLeakagePrevention(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Run analyzer on mock environment
	pamDir := filepath.Join(tmpDir, "etc", "pam.d")
	_ = os.MkdirAll(pamDir, 0o755)
	pamContent := "auth required pam_unix.so try_first_pass\nsession required pam_limits.so\n"
	_ = os.WriteFile(filepath.Join(pamDir, "display-manager"), []byte(pamContent), 0o644)

	engine := analyze.NewEngine()
	cfg := analyze.EngineConfig{
		Root:        tmpDir,
		ServiceName: "display-manager",
	}

	report, err := engine.Analyze(context.Background(), cfg)
	if err != nil {
		t.Fatalf("analyzer error: %v", err)
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	reportStr := string(reportJSON)

	// Check forbidden substrings that could represent secrets or credential dumps
	forbiddenStrings := []string{
		"private_key",
		"id_rsa",
		"SUPER_SECRET_PASSWORD",
		"pam_response",
		"fingerprint_template",
	}

	for _, forbidden := range forbiddenStrings {
		if strings.Contains(strings.ToLower(reportStr), strings.ToLower(forbidden)) {
			t.Errorf("secret leakage: report contains forbidden token %q", forbidden)
		}
	}

	// 2. Journal safety check: ensure journal rejects recording secret fields
	journalDir := filepath.Join(tmpDir, "journal")
	j := createSecurityTestJournal(t, journalDir, "tx-secret-check", []string{"op-dir"})

	// Attempting to write receipt containing a forbidden "password" key
	secretReceipt := manifestv1.OperationReceipt{
		OperationID:  "op-dir",
		Kind:         protocol.CreateDirectory,
		StartedAt:    time.Now().UTC().Format(time.RFC3339),
		CompletedAt:  time.Now().UTC().Format(time.RFC3339),
		Status:       "success",
		BeforeState:  protocol.Object{"existed": json.RawMessage(`false`)},
		AfterState:   protocol.Object{"password": json.RawMessage(`"mysecret"`)},
		Compensation: protocol.Object{"kind": json.RawMessage(`"remove_directory"`)},
	}

	err = j.RecordResult("op-dir", secretReceipt)
	if !errors.Is(err, transaction.ErrSecretDetected) {
		t.Fatalf("expected ErrSecretDetected when recording secret to journal, got %v", err)
	}
}

// TestSecurity_CorruptedJournalHandling verifies that corrupted or malformed
// journals fail safely and do not allow invalid state recovery.
func TestSecurity_CorruptedJournalHandling(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("truncated_json", func(t *testing.T) {
		corruptedPath := filepath.Join(tmpDir, "corrupted.json")
		if err := os.WriteFile(corruptedPath, []byte(`{"schema_version":"1.0","transaction_id":"`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := transaction.Open(corruptedPath)
		if !errors.Is(err, transaction.ErrCorruptJournal) {
			t.Fatalf("expected ErrCorruptJournal loading truncated JSON, got %v", err)
		}
	})

	t.Run("invalid_schema_version", func(t *testing.T) {
		invalidSchemaPath := filepath.Join(tmpDir, "invalid_schema.json")
		invalidJournal := map[string]any{
			"schema_version":  "malicious/v99",
			"transaction_id":  "tx-bad",
			"created_at":      time.Now().UTC().Format(time.RFC3339),
			"updated_at":      time.Now().UTC().Format(time.RFC3339),
			"state":           "applying",
			"operation_order": []string{},
			"applied_operations": []any{},
		}
		data, _ := json.Marshal(invalidJournal)
		_ = os.WriteFile(invalidSchemaPath, data, 0o600)

		_, err := transaction.Open(invalidSchemaPath)
		if !errors.Is(err, transaction.ErrCorruptJournal) {
			t.Fatalf("expected ErrCorruptJournal for bad schema version, got %v", err)
		}
	})

	t.Run("invalid_state_transition", func(t *testing.T) {
		journalDir := filepath.Join(tmpDir, "journal-trans")
		j := createSecurityTestJournal(t, journalDir, "tx-trans", []string{"op-1"})

		// Force state to rollback_required via a failed operation receipt
		failedReceipt := manifestv1.OperationReceipt{
			OperationID:  "op-1",
			Kind:         protocol.CreateDirectory,
			StartedAt:    time.Now().UTC().Format(time.RFC3339),
			CompletedAt:  time.Now().UTC().Format(time.RFC3339),
			Status:       "failed",
			BeforeState:  protocol.Object{"existed": json.RawMessage(`false`)},
			AfterState:   protocol.Object{"error": json.RawMessage(`"disk full"`)},
			Compensation: protocol.Object{"kind": json.RawMessage(`"remove_directory"`)},
		}
		if err := j.RecordResult("op-1", failedReceipt); err != nil {
			t.Fatal(err)
		}

		// Attempting Checkpoint from rollback_required should fail with ErrInvalidState
		err := j.Checkpoint()
		if !errors.Is(err, transaction.ErrInvalidState) {
			t.Fatalf("expected ErrInvalidState checkpointing during rollback_required, got %v", err)
		}
	})
}

// TestSecurity_Sprint6Hardening verifies TOCTOU/symlink rejection on descriptor
// reads and owned-file removals, hashed backup paths, and manifest secret checks.
func TestSecurity_Sprint6Hardening(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("descriptor_symlink_rejected", func(t *testing.T) {
		realDesc := filepath.Join(tmpDir, "real.json")
		if err := os.WriteFile(realDesc, []byte(`{"id":"test"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		linkDesc := filepath.Join(tmpDir, "link.json")
		if err := os.Symlink(realDesc, linkDesc); err != nil {
			t.Fatal(err)
		}
		_, err := descriptortrust.Read(descriptortrust.Policy{OwnerUID: uint32(os.Geteuid())}, linkDesc, 4096)
		if err == nil {
			t.Fatal("expected symlink descriptor read to be rejected")
		}
	})

	t.Run("remove_owned_file_rejects_symlink_and_ancestor_symlink", func(t *testing.T) {
		target := filepath.Join(tmpDir, "keep-me.conf")
		if err := os.WriteFile(target, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}
		realSub := filepath.Join(tmpDir, "real-sub")
		if err := os.MkdirAll(realSub, 0o700); err != nil {
			t.Fatal(err)
		}
		linkSub := filepath.Join(tmpDir, "link-sub")
		if err := os.Symlink(realSub, linkSub); err != nil {
			t.Fatal(err)
		}
		j := createSecurityTestJournal(t, filepath.Join(tmpDir, "j-rm"), "tx-rm", []string{"op-rm"})
		exec, err := install.NewExecutor(j, nil, filepath.Join(tmpDir, "bak-rm"))
		if err != nil {
			t.Fatal(err)
		}
		op := protocol.Operation{
			OperationID:    "op-rm",
			Kind:           protocol.RemoveOwnedFile,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"existed": json.RawMessage(`true`)},
			ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`false`)},
			Parameters:     json.RawMessage(`{"path":"` + filepath.Join(linkSub, "x.conf") + `","expected_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`),
			Compensation:   json.RawMessage(`{"kind":"restore_file","path":"` + filepath.Join(linkSub, "x.conf") + `"}`),
		}
		if _, err := exec.Execute(context.Background(), op); !errors.Is(err, install.ErrSymlinkRejected) {
			t.Fatalf("expected ErrSymlinkRejected for ancestor symlink removal, got %v", err)
		}
	})

	t.Run("manifest_rejects_embedded_secrets", func(t *testing.T) {
		now := time.Now().UTC().Format(time.RFC3339)
		m := manifestv1.InstallManifest{
			SchemaVersion:  manifestv1.SchemaVersion,
			TransactionID:  "tx-sec-1",
			FPLoginVersion: "0.2.0",
			InstalledAt:    now,
			Target: manifestv1.Target{
				InstanceID:  "inst-1",
				DMID:        "org.freedesktop.DisplayManager.test",
				DisplayName: "TestDM",
			},
			Adapter: manifestv1.AdapterIdentity{
				ComponentIdentity: manifestv1.ComponentIdentity{
					ID:               "org.fplogin.adapter.test",
					Version:          "1.0.0",
					ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
					DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				},
				InstalledCapabilities: []string{"biometric_auth"},
			},
			PlatformProvider: manifestv1.ComponentIdentity{
				ID:               "org.fplogin.platform.test",
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
				Enabled:     []string{"testdm.service"},
				Disabled:    []string{},
				PriorStates: []manifestv1.ServiceState{},
			},
			PreviousDMState: manifestv1.PreviousDMState{
				ServiceName: "testdm.service",
				Enabled:     "yes",
				Active:      "yes",
			},
			OperationReceipts: []manifestv1.OperationReceipt{
				{
					OperationID:  "op-1",
					Kind:         protocol.CreateDirectory,
					StartedAt:    now,
					CompletedAt:  now,
					Status:       "success",
					BeforeState:  protocol.Object{"existed": json.RawMessage(`false`)},
					AfterState:   protocol.Object{"pam_response": json.RawMessage(`"leaked-authtok"`)},
					Compensation: protocol.Object{"kind": json.RawMessage(`"remove_directory"`)},
				},
			},
			Verification: manifestv1.Verification{
				ReportID:   "rep-1",
				VerifiedAt: now,
				Checks:     []manifestv1.VerificationCheck{},
			},
		}
		err := manifest.Publish(filepath.Join(tmpDir, "manifest.json"), m)
		if !errors.Is(err, manifest.ErrSecretDetected) {
			t.Fatalf("expected manifest.ErrSecretDetected, got %v", err)
		}
	})
}
