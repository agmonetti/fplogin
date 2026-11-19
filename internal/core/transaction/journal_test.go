package transaction

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

func validInitialJournal(id string, opIDs []string) manifestv1.TransactionJournal {
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.TransactionJournal{
		SchemaVersion: manifestv1.SchemaVersion,
		TransactionID: id,
		State:         "prepared",
		CreatedAt:     now,
		UpdatedAt:     now,
		Target: manifestv1.Target{
			InstanceID:  "inst-1",
			DMID:        "org.freedesktop.DisplayManager.sddm",
			DisplayName: "SDDM",
		},
		Adapter: manifestv1.ComponentIdentity{
			ID:               "org.fplogin.adapter.sddm",
			Version:          "1.0.0",
			ProtocolVersion:  protocol.Version{Major: 1, Minor: 0},
			DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		PlatformProvider: manifestv1.ComponentIdentity{
			ID:               "org.fplogin.platform.arch",
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
		OperationOrder:      opIDs,
		AppliedOperations:   []manifestv1.OperationReceipt{},
		VerificationResults: []json.RawMessage{},
		RollbackRecords:     []json.RawMessage{},
	}
}

func makeReceipt(opID string, kind protocol.OperationKind, status string) manifestv1.OperationReceipt {
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.OperationReceipt{
		OperationID:  opID,
		Kind:         kind,
		StartedAt:    now,
		CompletedAt:  now,
		Status:       status,
		BeforeState:  protocol.Object{"existed": json.RawMessage(`false`)},
		AfterState:   protocol.Object{"existed": json.RawMessage(`true`)},
		Compensation: protocol.Object{"action": json.RawMessage(`"remove"`)},
	}
}

type failingSyncer struct {
	err error
}

func (f failingSyncer) WriteAndSync(path string, data []byte, perm os.FileMode) error {
	return f.err
}

func TestCreateAndOpen(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tx-123.json")

	init := validInitialJournal("tx-123", []string{"op-1", "op-2"})
	j, err := Create(path, init)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if j.State() != "prepared" {
		t.Errorf("expected state 'prepared', got %q", j.State())
	}

	// Double create must fail
	_, err = Create(path, init)
	if !errors.Is(err, ErrJournalExists) {
		t.Fatalf("expected ErrJournalExists, got %v", err)
	}

	// Open existing
	opened, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if opened.State() != "prepared" {
		t.Errorf("expected opened state 'prepared', got %q", opened.State())
	}
	if len(opened.Data().OperationOrder) != 2 {
		t.Errorf("expected 2 operations, got %d", len(opened.Data().OperationOrder))
	}
}

func TestOpen_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "does-not-exist.json")

	_, err := Open(path)
	if !errors.Is(err, ErrJournalNotFound) {
		t.Fatalf("expected ErrJournalNotFound, got %v", err)
	}
}

func TestOpen_CorruptJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "corrupted.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": "1.0", "transaction_id": `), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Open(path)
	if !errors.Is(err, ErrCorruptJournal) {
		t.Fatalf("expected ErrCorruptJournal, got %v", err)
	}
}

func TestRecordIntentAndResultFlow(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tx-flow.json")

	init := validInitialJournal("tx-flow", []string{"op-1", "op-2"})
	j, err := Create(path, init)
	if err != nil {
		t.Fatal(err)
	}

	// Unknown operation rejected
	err = j.RecordIntent("op-unknown")
	if !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("expected ErrUnknownOperation, got %v", err)
	}

	// Record intent for op-1
	if err := j.RecordIntent("op-1"); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}
	if j.State() != "applying" {
		t.Errorf("expected state 'applying', got %q", j.State())
	}

	// Record successful result for op-1
	r1 := makeReceipt("op-1", protocol.OperationKind("write_file_atomic"), "success")
	if err := j.RecordResult("op-1", r1); err != nil {
		t.Fatalf("RecordResult failed: %v", err)
	}

	// Record intent for op-2
	if err := j.RecordIntent("op-2"); err != nil {
		t.Fatalf("RecordIntent op-2 failed: %v", err)
	}

	// Record failure for op-2
	r2 := makeReceipt("op-2", protocol.OperationKind("create_directory"), "failed")
	if err := j.RecordResult("op-2", r2); err != nil {
		t.Fatalf("RecordResult op-2 failed: %v", err)
	}
	if j.State() != "rollback_required" {
		t.Errorf("expected state 'rollback_required', got %q", j.State())
	}

	// Reopen from disk to verify durable state
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	if reopened.State() != "rollback_required" {
		t.Errorf("reopened state expected 'rollback_required', got %q", reopened.State())
	}
	if len(reopened.Data().AppliedOperations) != 2 {
		t.Fatalf("expected 2 applied operations on disk, got %d", len(reopened.Data().AppliedOperations))
	}
}

func TestRecovery_ReverseOrder(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tx-rec.json")

	init := validInitialJournal("tx-rec", []string{"op-1", "op-2", "op-3"})
	j, err := Create(path, init)
	if err != nil {
		t.Fatal(err)
	}

	_ = j.RecordIntent("op-1")
	_ = j.RecordResult("op-1", makeReceipt("op-1", protocol.OperationKind("create_directory"), "success"))

	_ = j.RecordIntent("op-2")
	_ = j.RecordResult("op-2", makeReceipt("op-2", protocol.OperationKind("write_file_atomic"), "success"))

	_ = j.RecordIntent("op-3")
	_ = j.RecordResult("op-3", makeReceipt("op-3", protocol.OperationKind("install_package_artifact"), "failed"))

	toCompensate, err := j.Recovery()
	if err != nil {
		t.Fatalf("Recovery failed: %v", err)
	}

	// Should contain op-2 then op-1 (reverse order), excluding failed op-3
	if len(toCompensate) != 2 {
		t.Fatalf("expected 2 operations to compensate, got %d", len(toCompensate))
	}
	if toCompensate[0].OperationID != "op-2" {
		t.Errorf("expected first compensation to be op-2, got %q", toCompensate[0].OperationID)
	}
	if toCompensate[1].OperationID != "op-1" {
		t.Errorf("expected second compensation to be op-1, got %q", toCompensate[1].OperationID)
	}

	// Now record rollback for op-2
	rollReceipt2 := makeReceipt("op-2", protocol.OperationKind("write_file_atomic"), "rolled_back")
	if err := j.RecordRollback("op-2", rollReceipt2); err != nil {
		t.Fatalf("RecordRollback failed: %v", err)
	}

	// Recovery should now only return op-1
	toCompensate2, err := j.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	if len(toCompensate2) != 1 || toCompensate2[0].OperationID != "op-1" {
		t.Fatalf("expected only op-1 to remain for compensation, got %v", toCompensate2)
	}

	// Rollback op-1 and mark completed
	rollReceipt1 := makeReceipt("op-1", protocol.OperationKind("create_directory"), "rolled_back")
	_ = j.RecordRollback("op-1", rollReceipt1)
	if err := j.MarkRolledBack(); err != nil {
		t.Fatalf("MarkRolledBack failed: %v", err)
	}
	if j.State() != "rolled_back" {
		t.Errorf("expected state 'rolled_back', got %q", j.State())
	}
}

func TestCheckpoint_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tx-ckpt.json")

	init := validInitialJournal("tx-ckpt", []string{"op-1"})
	j, err := Create(path, init)
	if err != nil {
		t.Fatal(err)
	}

	_ = j.RecordIntent("op-1")
	_ = j.RecordResult("op-1", makeReceipt("op-1", protocol.OperationKind("create_directory"), "success"))

	if err := j.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}
	if j.State() != "completed" {
		t.Errorf("expected state 'completed', got %q", j.State())
	}

	// Cannot record intent from completed state
	err = j.RecordIntent("op-1")
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestFsyncFailure_Injected(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tx-fsync.json")

	init := validInitialJournal("tx-fsync", []string{"op-1"})
	j, err := Create(path, init)
	if err != nil {
		t.Fatal(err)
	}

	// Inject syncer failure
	injectedErr := errors.New("simulated disk I/O / fsync failure")
	j.SetSyncer(failingSyncer{err: injectedErr})

	err = j.RecordIntent("op-1")
	if err == nil || !errors.Is(err, injectedErr) {
		t.Fatalf("expected injected error %v, got %v", injectedErr, err)
	}
	j.SetSyncer(diskSyncer{})
	if err := j.Checkpoint(); !errors.Is(err, injectedErr) {
		t.Fatalf("checkpoint after failed sync returned %v", err)
	}
	if _, err := j.Recovery(); !errors.Is(err, injectedErr) {
		t.Fatalf("recovery used speculative journal state: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.State() != "prepared" {
		t.Fatalf("on-disk state overwritten: %s", reopened.State())
	}
}

func TestSecretsRejection(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tx-secret.json")

	init := validInitialJournal("tx-secret", []string{"op-1"})
	j, err := Create(path, init)
	if err != nil {
		t.Fatal(err)
	}

	_ = j.RecordIntent("op-1")

	// Create receipt containing a forbidden key / secret in before_state
	r := makeReceipt("op-1", protocol.OperationKind("write_file_atomic"), "success")
	r.BeforeState = protocol.Object{
		"user":     json.RawMessage(`"alice"`),
		"password": json.RawMessage(`"super-secret-password-123"`),
	}

	err = j.RecordResult("op-1", r)
	if !errors.Is(err, ErrSecretDetected) {
		t.Fatalf("expected ErrSecretDetected, got %v", err)
	}
}
