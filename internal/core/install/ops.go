// Package install implements the closed vocabulary of atomic operations,
// compensation tracking, and the installer orchestrator for fplogin.
package install

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

var (
	ErrHashMismatch    = errors.New("file checksum mismatch against expected sha256")
	ErrPrecondition    = errors.New("operation precondition violated")
	ErrRollbackFailed  = errors.New("rollback compensation failed")
	ErrUnsupportedKind = errors.New("unsupported operation kind")
	ErrSymlinkRejected = errors.New("destination path or target cannot be a symlink")
	ErrInvalidPath     = errors.New("path must be canonical and absolute")
)

// PlatformApplier abstracts the execution of platform-specific operations
// (packages, services) by a platform provider.
type PlatformApplier interface {
	ApplyOperation(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error)
}

// Executor coordinates the execution of operations with pre-mutation journaling,
// rollback compensation, and backup persistence.
type Executor struct {
	Journal     *transaction.Journal
	Platform    PlatformApplier
	BackupDir   string
	allowFile   func(path string) bool
	systemFiles bool
}

// NewExecutor creates a new Executor. If backupDir is empty, a directory
// alongside the journal or in the system temp directory is used.
func NewExecutor(j *transaction.Journal, platform PlatformApplier, backupDir string) (*Executor, error) {
	if j == nil {
		return nil, errors.New("journal is required")
	}
	if backupDir == "" {
		backupDir = filepath.Join(filepath.Dir(j.Path()), "backups", j.Data().TransactionID)
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup directory %q: %w", backupDir, err)
	}
	return &Executor{
		Journal:   j,
		Platform:  platform,
		BackupDir: backupDir,
	}, nil
}

// Execute performs pre-mutation journaling, runs the operation, records the
// receipt (or failure receipt), and returns the receipt.
func (e *Executor) Execute(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error) {
	if err := op.Validate(); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("validate operation %q: %w", op.OperationID, err)
	}

	if e.Journal.Data().FileRecovery {
		return e.executeRecoverableFile(op)
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)

	// Step 1: Write intent to journal and fsync BEFORE any mutation
	if err := e.Journal.RecordIntent(op.OperationID); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("record intent for %q: %w", op.OperationID, err)
	}

	var receipt manifestv1.OperationReceipt
	var execErr error

	switch op.Kind {
	case protocol.CreateDirectory:
		receipt, execErr = e.execCreateDirectory(op, startedAt)
	case protocol.WriteFileAtomic:
		receipt, execErr = e.execWriteFileAtomic(op, startedAt)
	case protocol.RemoveOwnedFile:
		receipt, execErr = e.execRemoveOwnedFile(op, startedAt)
	case protocol.InstallPackageArtifact,
		protocol.RemoveOwnedPackage,
		protocol.SetServiceEnabled,
		protocol.SetServiceActive,
		protocol.RestoreServiceState:
		if e.Platform == nil {
			execErr = fmt.Errorf("no platform provider configured for %s", op.Kind)
		} else {
			receipt, execErr = e.Platform.ApplyOperation(ctx, op)
		}
	default:
		execErr = fmt.Errorf("%w: %s", ErrUnsupportedKind, op.Kind)
	}

	completedAt := time.Now().UTC().Format(time.RFC3339)

	if execErr != nil {
		// Create failure receipt
		failedReceipt := manifestv1.OperationReceipt{
			OperationID:  op.OperationID,
			Kind:         op.Kind,
			StartedAt:    startedAt,
			CompletedAt:  completedAt,
			Status:       "failed",
			BeforeState:  receipt.BeforeState,
			AfterState:   protocol.Object{"error": json.RawMessage(fmt.Sprintf("%q", execErr.Error()))},
			Compensation: toObject(op.Compensation),
		}
		if failedReceipt.BeforeState == nil {
			failedReceipt.BeforeState = protocol.Object{"existed": json.RawMessage(`false`)}
		}
		if err := e.Journal.RecordResult(op.OperationID, failedReceipt); err != nil {
			return failedReceipt, errors.Join(execErr, fmt.Errorf("record failed receipt for %q: %w", op.OperationID, err))
		}
		return failedReceipt, execErr
	}

	receipt.StartedAt = startedAt
	receipt.CompletedAt = completedAt
	if receipt.Status == "" {
		receipt.Status = "success"
	}
	if receipt.Compensation == nil {
		receipt.Compensation = toObject(op.Compensation)
	}

	if err := e.Journal.RecordResult(op.OperationID, receipt); err != nil {
		return receipt, fmt.Errorf("record receipt for %q: %w", op.OperationID, err)
	}

	return receipt, nil
}

// Rollback executes compensation for all operations that succeeded, in reverse order.
func (e *Executor) Rollback(ctx context.Context) ([]manifestv1.OperationReceipt, error) {
	toCompensate, err := e.Journal.Recovery()
	if err != nil {
		return nil, fmt.Errorf("recover operations to compensate: %w", err)
	}

	var rollbackReceipts []manifestv1.OperationReceipt
	var rollbackErrors []error

	for _, receipt := range toCompensate {
		startedAt := time.Now().UTC().Format(time.RFC3339)
		var compErr error
		if e.Journal.Data().FileRecovery {
			compErr = e.restoreFile(receipt)
		} else {
			compErr = e.compensateOperation(ctx, receipt)
		}
		completedAt := time.Now().UTC().Format(time.RFC3339)

		status := "rolled_back"
		if compErr != nil {
			status = "rollback_failed"
			rollbackErrors = append(rollbackErrors, fmt.Errorf("compensate %q: %w", receipt.OperationID, compErr))
		}

		rbReceipt := manifestv1.OperationReceipt{
			OperationID:  receipt.OperationID,
			Kind:         receipt.Kind,
			StartedAt:    startedAt,
			CompletedAt:  completedAt,
			Status:       status,
			BeforeState:  receipt.AfterState,
			AfterState:   receipt.BeforeState,
			Compensation: receipt.Compensation,
		}

		if err := e.Journal.RecordRollback(receipt.OperationID, rbReceipt); err != nil {
			return rollbackReceipts, errors.Join(errors.Join(rollbackErrors...), fmt.Errorf("record rollback for %q: %w", receipt.OperationID, err))
		}

		rollbackReceipts = append(rollbackReceipts, rbReceipt)
		if compErr != nil && e.Journal.Data().FileRecovery {
			return rollbackReceipts, errors.Join(rollbackErrors...)
		}
	}

	if len(rollbackErrors) > 0 {
		return rollbackReceipts, errors.Join(rollbackErrors...)
	}

	if err := e.Journal.MarkRolledBack(); err != nil {
		return rollbackReceipts, fmt.Errorf("mark rolled back: %w", err)
	}

	return rollbackReceipts, nil
}

// validateSafePath verifies that a target path is absolute, clean, and not a symlink.
func validateSafePath(p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%w: path %q must be absolute and clean", ErrInvalidPath, p)
	}

	// Check if the path itself is a symlink
	if fi, err := os.Lstat(p); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: path %q is a symlink", ErrSymlinkRejected, p)
		}
	}

	// Check if any existing ancestor directory is a symlink
	curr := filepath.Dir(p)
	for curr != "/" && curr != "." && curr != "" {
		if fi, err := os.Lstat(curr); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: ancestor directory %q is a symlink", ErrSymlinkRejected, curr)
			}
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	return nil
}

// ---------------------------------------------------------------------------
// Local atomic operations
// ---------------------------------------------------------------------------

func (e *Executor) execCreateDirectory(op protocol.Operation, startedAt string) (manifestv1.OperationReceipt, error) {
	var params struct {
		Path  string `json:"path"`
		Mode  string `json:"mode"`
		Owner string `json:"owner"`
		Group string `json:"group"`
	}
	if err := json.Unmarshal(op.Parameters, &params); err != nil {
		return manifestv1.OperationReceipt{}, err
	}

	if err := validateSafePath(params.Path); err != nil {
		return manifestv1.OperationReceipt{}, err
	}

	info, statErr := os.Stat(params.Path)
	existed := statErr == nil

	modeVal, err := strconv.ParseUint(params.Mode, 8, 32)
	if err != nil {
		modeVal = 0o755
	}

	if err := os.MkdirAll(params.Path, os.FileMode(modeVal)); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("mkdir %q: %w", params.Path, err)
	}

	beforeState := protocol.Object{
		"path":    json.RawMessage(fmt.Sprintf("%q", params.Path)),
		"existed": json.RawMessage(fmt.Sprintf("%t", existed)),
	}
	if existed {
		beforeState["mode"] = json.RawMessage(fmt.Sprintf("%q", info.Mode().String()))
	}

	afterState := protocol.Object{
		"path":    json.RawMessage(fmt.Sprintf("%q", params.Path)),
		"existed": json.RawMessage(`true`),
		"mode":    json.RawMessage(fmt.Sprintf("%q", params.Mode)),
	}

	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		BeforeState:  beforeState,
		AfterState:   afterState,
		Compensation: toObject(op.Compensation),
	}, nil
}

func (e *Executor) execWriteFileAtomic(op protocol.Operation, startedAt string) (manifestv1.OperationReceipt, error) {
	var params struct {
		DestinationPath string `json:"destination_path"`
		ContentBase64   string `json:"content_base64"`
		SHA256          string `json:"sha256"`
		Mode            string `json:"mode"`
		Owner           string `json:"owner"`
		Group           string `json:"group"`
	}
	if err := json.Unmarshal(op.Parameters, &params); err != nil {
		return manifestv1.OperationReceipt{}, err
	}

	if err := validateSafePath(params.DestinationPath); err != nil {
		return manifestv1.OperationReceipt{}, err
	}

	content, err := base64.StdEncoding.DecodeString(params.ContentBase64)
	if err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("decode content_base64: %w", err)
	}

	computedHash := sha256Hex(content)
	if computedHash != params.SHA256 {
		return manifestv1.OperationReceipt{}, fmt.Errorf("%w: content computed %s != expected %s",
			ErrHashMismatch, computedHash, params.SHA256)
	}

	// Capture before state & backup existing file if present
	beforeState := protocol.Object{
		"destination_path": json.RawMessage(fmt.Sprintf("%q", params.DestinationPath)),
		"existed":          json.RawMessage(`false`),
	}

	var backupPath string
	if origInfo, err := os.Stat(params.DestinationPath); err == nil && !origInfo.IsDir() {
		origBytes, readErr := os.ReadFile(params.DestinationPath)
		if readErr != nil {
			return manifestv1.OperationReceipt{}, fmt.Errorf("read existing file for backup: %w", readErr)
		}
		origHash := sha256Hex(origBytes)
		backupPath = filepath.Join(e.BackupDir, filepath.Base(params.DestinationPath)+"-"+op.OperationID+".bak")
		if err := os.WriteFile(backupPath, origBytes, 0o600); err != nil {
			return manifestv1.OperationReceipt{}, fmt.Errorf("write backup %q: %w", backupPath, err)
		}
		beforeState["existed"] = json.RawMessage(`true`)
		beforeState["sha256"] = json.RawMessage(fmt.Sprintf("%q", origHash))
		beforeState["backup_path"] = json.RawMessage(fmt.Sprintf("%q", backupPath))
	}

	// Write atomically via temporary file and rename
	destDir := filepath.Dir(params.DestinationPath)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("mkdir %q: %w", destDir, err)
	}

	tmpFile, err := os.CreateTemp(destDir, filepath.Base(params.DestinationPath)+".tmp.*")
	if err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("create temp file in %q: %w", destDir, err)
	}
	tmpPath := tmpFile.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	modeVal, err := strconv.ParseUint(params.Mode, 8, 32)
	if err != nil {
		modeVal = 0o644
	}
	if err := tmpFile.Chmod(os.FileMode(modeVal)); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("chmod %q: %w", tmpPath, err)
	}

	if _, err := tmpFile.Write(content); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("write %q: %w", tmpPath, err)
	}
	if err := tmpFile.Sync(); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("sync %q: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("close %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, params.DestinationPath); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("rename %q -> %q: %w", tmpPath, params.DestinationPath, err)
	}
	cleanedUp = true

	// Sync parent directory
	if d, err := os.Open(destDir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	afterState := protocol.Object{
		"destination_path": json.RawMessage(fmt.Sprintf("%q", params.DestinationPath)),
		"existed":          json.RawMessage(`true`),
		"sha256":           json.RawMessage(fmt.Sprintf("%q", params.SHA256)),
		"mode":             json.RawMessage(fmt.Sprintf("%q", params.Mode)),
	}

	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		BeforeState:  beforeState,
		AfterState:   afterState,
		Compensation: toObject(op.Compensation),
	}, nil
}

func (e *Executor) execRemoveOwnedFile(op protocol.Operation, startedAt string) (manifestv1.OperationReceipt, error) {
	var params struct {
		Path           string `json:"path"`
		ExpectedSHA256 string `json:"expected_sha256"`
	}
	if err := json.Unmarshal(op.Parameters, &params); err != nil {
		return manifestv1.OperationReceipt{}, err
	}

	if err := validateSafePath(params.Path); err != nil {
		return manifestv1.OperationReceipt{}, err
	}

	data, err := os.ReadFile(params.Path)
	if err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("read file to remove %q: %w", params.Path, err)
	}

	actualHash := sha256Hex(data)
	if actualHash != params.ExpectedSHA256 {
		return manifestv1.OperationReceipt{}, fmt.Errorf("%w: file %q actual %s != expected %s; refusing removal",
			ErrHashMismatch, params.Path, actualHash, params.ExpectedSHA256)
	}

	// Backup before removal
	backupPath := filepath.Join(e.BackupDir, filepath.Base(params.Path)+"-"+op.OperationID+".bak")
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("write backup %q: %w", backupPath, err)
	}

	if err := os.Remove(params.Path); err != nil {
		return manifestv1.OperationReceipt{}, fmt.Errorf("remove file %q: %w", params.Path, err)
	}

	beforeState := protocol.Object{
		"path":        json.RawMessage(fmt.Sprintf("%q", params.Path)),
		"existed":     json.RawMessage(`true`),
		"sha256":      json.RawMessage(fmt.Sprintf("%q", actualHash)),
		"backup_path": json.RawMessage(fmt.Sprintf("%q", backupPath)),
	}
	afterState := protocol.Object{
		"path":    json.RawMessage(fmt.Sprintf("%q", params.Path)),
		"existed": json.RawMessage(`false`),
	}

	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		BeforeState:  beforeState,
		AfterState:   afterState,
		Compensation: toObject(op.Compensation),
	}, nil
}

// ---------------------------------------------------------------------------
// Compensation execution
// ---------------------------------------------------------------------------

func (e *Executor) compensateOperation(ctx context.Context, receipt manifestv1.OperationReceipt) error {
	switch receipt.Kind {
	case protocol.CreateDirectory:
		var comp struct {
			Kind string `json:"kind"`
			Path string `json:"path"`
		}
		raw, _ := json.Marshal(receipt.Compensation)
		if err := json.Unmarshal(raw, &comp); err != nil {
			return err
		}
		// If directory existed beforehand, do not remove it
		var before struct {
			Existed bool `json:"existed"`
		}
		rawBefore, _ := json.Marshal(receipt.BeforeState)
		_ = json.Unmarshal(rawBefore, &before)
		if before.Existed {
			return nil
		}
		// Only remove if it was created during this transaction
		_ = os.Remove(comp.Path)
		return nil

	case protocol.WriteFileAtomic:
		var before struct {
			Existed    bool   `json:"existed"`
			BackupPath string `json:"backup_path"`
		}
		rawBefore, _ := json.Marshal(receipt.BeforeState)
		_ = json.Unmarshal(rawBefore, &before)

		var after struct {
			DestinationPath string `json:"destination_path"`
		}
		rawAfter, _ := json.Marshal(receipt.AfterState)
		_ = json.Unmarshal(rawAfter, &after)

		if !before.Existed {
			// Did not exist prior to transaction; remove it
			_ = os.Remove(after.DestinationPath)
			return nil
		}

		// Existed prior: restore from backup
		if before.BackupPath == "" {
			return errors.New("no backup path recorded for restoration")
		}
		return copyFile(before.BackupPath, after.DestinationPath)

	case protocol.RemoveOwnedFile:
		var before struct {
			Path       string `json:"path"`
			BackupPath string `json:"backup_path"`
		}
		rawBefore, _ := json.Marshal(receipt.BeforeState)
		_ = json.Unmarshal(rawBefore, &before)

		if before.BackupPath == "" {
			return errors.New("no backup path recorded to restore removed file")
		}
		return copyFile(before.BackupPath, before.Path)

	case protocol.InstallPackageArtifact,
		protocol.RemoveOwnedPackage,
		protocol.SetServiceEnabled,
		protocol.SetServiceActive,
		protocol.RestoreServiceState:
		if e.Platform == nil {
			return errors.New("no platform provider configured for compensation")
		}
		// Platform compensation is dispatched via ApplyOperation with compensation payload
		compRaw, err := json.Marshal(receipt.Compensation)
		if err != nil {
			return err
		}
		compOp := protocol.Operation{
			OperationID:    receipt.OperationID + "-rollback",
			Kind:           protocol.RestoreServiceState,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: receipt.AfterState,
			ExpectedAfter:  receipt.BeforeState,
			Parameters:     compRaw,
			Compensation:   json.RawMessage(`{"kind":"none"}`),
		}
		_, err = e.Platform.ApplyOperation(ctx, compOp)
		return err

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedKind, receipt.Kind)
	}
}

func toObject(raw json.RawMessage) protocol.Object {
	if len(raw) == 0 {
		return protocol.Object{}
	}
	var obj protocol.Object
	if err := json.Unmarshal(raw, &obj); err != nil {
		return protocol.Object{"raw": raw}
	}
	return obj
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
