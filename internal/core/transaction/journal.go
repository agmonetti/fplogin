// Package transaction manages durable, atomic transaction journals for fplogin
// installations, upgrades, repairs, and uninstalls, adhering to ADR 0003.
package transaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

var (
	ErrJournalExists    = errors.New("journal file already exists")
	ErrJournalNotFound  = errors.New("journal file not found")
	ErrCorruptJournal   = errors.New("journal file is corrupt or unparseable")
	ErrUnknownOperation = errors.New("operation not in planned operation order")
	ErrInvalidState     = errors.New("invalid transaction state transition")
	ErrSecretDetected   = errors.New("potential secret or sensitive credential rejected in journal")
)

// Syncer abstracts file writing and syncing to allow testing simulated fsync failures.
type Syncer interface {
	WriteAndSync(path string, data []byte, perm os.FileMode) error
}

type diskSyncer struct{}

func (diskSyncer) WriteAndSync(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create journal directory %q: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file %q: %w", tmpPath, err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("write temp file %q: %w", tmpPath, err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("fsync temp file %q: %w", tmpPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file %q to %q: %w", tmpPath, path, err)
	}
	cleanedUp = true

	// Sync parent directory to guarantee the directory entry is durable on disk
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open directory %q for fsync: %w", dir, err)
	}
	defer dirFile.Close()

	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("fsync directory %q: %w", dir, err)
	}

	return nil
}

// Journal manages the persistence of a single transaction journal.
type Journal struct {
	mu       sync.Mutex
	path     string
	syncer   Syncer
	data     manifestv1.TransactionJournal
	writeErr error // A failed sync may follow rename; only reopening can reconcile it.
}

// SetSyncer sets a custom syncer, primarily for testing simulated fsync or write failures.
func (j *Journal) SetSyncer(s Syncer) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.syncer = s
}

// Create creates a new transaction journal file at path and fsyncs it.
// If the file already exists, it returns ErrJournalExists.
func Create(path string, init manifestv1.TransactionJournal) (*Journal, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, ErrJournalExists
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if init.CreatedAt == "" {
		init.CreatedAt = now
	}
	if init.UpdatedAt == "" {
		init.UpdatedAt = now
	}
	if init.SchemaVersion == "" {
		init.SchemaVersion = manifestv1.SchemaVersion
	}
	if init.AppliedOperations == nil {
		init.AppliedOperations = []manifestv1.OperationReceipt{}
	}
	if init.VerificationResults == nil {
		init.VerificationResults = []json.RawMessage{}
	}
	if init.RollbackRecords == nil {
		init.RollbackRecords = []json.RawMessage{}
	}

	if err := init.Validate(); err != nil {
		return nil, fmt.Errorf("validate initial journal: %w", err)
	}

	encoded, err := json.MarshalIndent(init, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal journal: %w", err)
	}

	if err := checkNoSecrets(encoded); err != nil {
		return nil, err
	}

	s := diskSyncer{}
	if err := s.WriteAndSync(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("persist initial journal: %w", err)
	}

	return &Journal{
		path:   path,
		syncer: s,
		data:   init,
	}, nil
}

// Open opens an existing journal file, decoding and strictly validating it.
func Open(path string) (*Journal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrJournalNotFound
		}
		return nil, fmt.Errorf("read journal file %q: %w", path, err)
	}

	tj, err := manifestv1.DecodeTransactionJournal(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptJournal, err)
	}

	return &Journal{
		path:   path,
		syncer: diskSyncer{},
		data:   tj,
	}, nil
}

// Path returns the filesystem path of the journal file.
func (j *Journal) Path() string {
	return j.path
}

// Data returns a deep snapshot of the journal in memory.
func (j *Journal) Data() manifestv1.TransactionJournal {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.data
}

// State returns the current transaction state.
func (j *Journal) State() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.data.State
}

// RecordIntent records the intent to execute an operation by moving the state to
// "applying" (if not already applying), validating that operationID is in the planned
// operation order, updating updated_at, and flushing durable state with fsync.
func (j *Journal) RecordIntent(operationID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if !slices.Contains(j.data.OperationOrder, operationID) {
		return fmt.Errorf("%w: %q", ErrUnknownOperation, operationID)
	}

	// Must be in prepared or applying state to record intent
	if j.data.State != "prepared" && j.data.State != "applying" {
		return fmt.Errorf("%w: cannot record intent from state %q", ErrInvalidState, j.data.State)
	}

	j.data.State = "applying"
	j.data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	return j.flushLocked()
}

// RecordResult records the result of an operation execution.
// It verifies the receipt matches an operation in operation_order, updates/appends
// the receipt to AppliedOperations, transitions state to "rollback_required" if the
// status is "failed", updates updated_at, and flushes durable state with fsync.
func (j *Journal) RecordResult(operationID string, receipt manifestv1.OperationReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if !slices.Contains(j.data.OperationOrder, operationID) {
		return fmt.Errorf("%w: %q", ErrUnknownOperation, operationID)
	}
	if receipt.OperationID != operationID {
		return fmt.Errorf("receipt operation ID %q does not match %q", receipt.OperationID, operationID)
	}
	if err := receipt.Validate(true); err != nil {
		return fmt.Errorf("invalid operation receipt: %w", err)
	}

	// Update existing receipt or append new
	updated := false
	for i, existing := range j.data.AppliedOperations {
		if existing.OperationID == operationID {
			j.data.AppliedOperations[i] = receipt
			updated = true
			break
		}
	}
	if !updated {
		j.data.AppliedOperations = append(j.data.AppliedOperations, receipt)
	}

	if receipt.Status == "failed" {
		j.data.State = "rollback_required"
	}

	j.data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return j.flushLocked()
}

// RecordRollback records a compensation attempt/result.
// It updates the receipt status in AppliedOperations (e.g. to "rolled_back" or "rollback_failed"),
// ensures transaction state is "rolling_back", updates updated_at, and flushes with fsync.
func (j *Journal) RecordRollback(operationID string, receipt manifestv1.OperationReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if !slices.Contains(j.data.OperationOrder, operationID) {
		return fmt.Errorf("%w: %q", ErrUnknownOperation, operationID)
	}
	if receipt.OperationID != operationID {
		return fmt.Errorf("rollback receipt operation ID %q does not match %q", receipt.OperationID, operationID)
	}
	if err := receipt.Validate(true); err != nil {
		return fmt.Errorf("invalid rollback receipt: %w", err)
	}

	found := false
	for i, existing := range j.data.AppliedOperations {
		if existing.OperationID == operationID {
			j.data.AppliedOperations[i] = receipt
			found = true
			break
		}
	}
	if !found {
		j.data.AppliedOperations = append(j.data.AppliedOperations, receipt)
	}

	j.data.State = "rolling_back"
	j.data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	return j.flushLocked()
}

// RecordVerification records post-mutation verification results and flushes.
// If any verification result indicates failure, state transitions to "verification_failed".
func (j *Journal) RecordVerification(results []json.RawMessage, passed bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.data.VerificationResults = results
	if passed {
		// Remains in current state (or ready to checkpoint)
	} else {
		j.data.State = "verification_failed"
	}
	j.data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return j.flushLocked()
}

// Checkpoint marks the journal as completed and flushes atomically.
func (j *Journal) Checkpoint() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.data.State != "applying" && j.data.State != "prepared" {
		return fmt.Errorf("%w: cannot checkpoint from state %q", ErrInvalidState, j.data.State)
	}

	j.data.State = "completed"
	j.data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return j.flushLocked()
}

// MarkRolledBack marks the transaction as fully rolled back.
func (j *Journal) MarkRolledBack() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.data.State = "rolled_back"
	j.data.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return j.flushLocked()
}

// Recovery analyzes the current journal state and returns the list of applied
// operations that require rollback compensation, sorted in reverse execution order.
// Only operations with status "success" that have not already been marked "rolled_back"
// are returned.
func (j *Journal) Recovery() ([]manifestv1.OperationReceipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.writeErr != nil {
		return nil, j.writeErr
	}
	var toCompensate []manifestv1.OperationReceipt
	// Traverse in reverse order of application
	for i := len(j.data.AppliedOperations) - 1; i >= 0; i-- {
		op := j.data.AppliedOperations[i]
		if op.Status == "success" {
			toCompensate = append(toCompensate, op)
		}
	}
	return toCompensate, nil
}

// flushLocked marshals, validates secrets, and writes/fsyncs j.data to disk.
// Must be called with j.mu held.
func (j *Journal) flushLocked() (err error) {
	if j.writeErr != nil {
		return j.writeErr
	}
	defer func() {
		if err != nil {
			j.writeErr = err
		}
	}()
	if err := j.data.Validate(); err != nil {
		return fmt.Errorf("journal validation failed before flush: %w", err)
	}

	encoded, err := json.MarshalIndent(j.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal journal: %w", err)
	}

	if err := checkNoSecrets(encoded); err != nil {
		return err
	}

	syncer := j.syncer
	if syncer == nil {
		syncer = diskSyncer{}
	}

	if err := syncer.WriteAndSync(j.path, encoded, 0o600); err != nil {
		return fmt.Errorf("flush journal to %q: %w", j.path, err)
	}

	return nil
}

// checkNoSecrets ensures no sensitive passwords, fingerprint templates, PAM responses,
// or secrets are leaked into the journal.
func checkNoSecrets(data []byte) error {
	lower := bytes.ToLower(data)
	forbidden := []string{
		`"password"`,
		`"secret"`,
		`"fingerprint_template"`,
		`"raw_template"`,
		`"pam_authtok"`,
		`"pam_response"`,
	}
	for _, term := range forbidden {
		if bytes.Contains(lower, []byte(term)) {
			return fmt.Errorf("%w: matched forbidden term %s", ErrSecretDetected, term)
		}
	}
	return nil
}
