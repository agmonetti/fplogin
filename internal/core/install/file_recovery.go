package install

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

func isolatedFilePolicy(lab, state string, paths []string) func(string) bool {
	info, err := os.Lstat(lab)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || validateSafePath(lab) != nil || validateSafePath(state) != nil {
		return nil
	}
	allowed := make(map[string]bool, len(paths))
	for _, path := range paths {
		if !strings.HasPrefix(path, lab+"/") || path == state || strings.HasPrefix(path, state+"/") || validateSafePath(path) != nil {
			return nil
		}
		allowed[path] = true
	}
	return func(path string) bool {
		if !allowed[path] || validateSafePath(path) != nil {
			return false
		}
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 ||
				info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
				return false
			}
			if dir == lab {
				return true
			}
		}
	}
}

type fileParameters struct {
	Destination string `json:"destination_path"`
	Path        string `json:"path"`
	Content     string `json:"content_base64"`
	SHA256      string `json:"sha256"`
	Expected    string `json:"expected_sha256"`
	Mode        string `json:"mode"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
}

func recoverableFile(op protocol.Operation) (fileParameters, string, error) {
	var p fileParameters
	if err := json.Unmarshal(op.Parameters, &p); err != nil {
		return p, "", err
	}
	switch op.Kind {
	case protocol.WriteFileAtomic:
		return p, p.Destination, nil
	case protocol.RemoveOwnedFile:
		return p, p.Path, nil
	default:
		return p, "", ErrUnsupportedKind
	}
}

const (
	systemStateRoot = "/var/lib/fplogin"
	systemThemeFile = "/etc/sddm.conf.d/90-fplogin.conf"
	systemThemeData = "[Theme]\nCurrent=fplogin\n"
)

func filePolicy(root string, paths []string) func(string) bool {
	if descriptortrust.Elevated() {
		if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getegid() != 0 || root != systemStateRoot || len(paths) != 0 || descriptortrust.ValidatePackagedDir(filepath.Dir(root)) != nil {
			return nil
		}
		return func(path string) bool {
			if path != systemThemeFile || descriptortrust.ValidatePackagedDir(filepath.Dir(path)) != nil {
				return false
			}
			err := descriptortrust.ValidatePackagedFile(path)
			return err == nil || errors.Is(err, os.ErrNotExist)
		}
	}
	if root == systemStateRoot || len(paths) == 0 {
		return nil
	}
	return isolatedFilePolicy(filepath.Dir(root), root, paths)
}

// beginFileTransaction runs under the shared lock for file-only transactions.
func beginFileTransaction(root string, paths []string, init manifestv1.TransactionJournal, ops []protocol.Operation) (*Executor, error) {
	for _, op := range ops {
		if !manifestv1.IsRecoverableFileKind(op.Kind) {
			return nil, fmt.Errorf("prepare rollback for operation %q: %w", op.OperationID, ErrUnsupportedKind)
		}
	}
	return beginTransaction(root, paths, init, ops, nil)
}

// beginTransaction runs under the shared lock and persists durable file backups
// and the prepared journal before any file, package, or service mutation.
func beginTransaction(root string, paths []string, init manifestv1.TransactionJournal, ops []protocol.Operation, platform PlatformApplier) (*Executor, error) {
	allow := filePolicy(root, paths)
	if allow == nil {
		return nil, ErrPrivilegesRequired
	}
	if err := transaction.CheckNoUnresolved(filepath.Join(root, "transactions")); err != nil {
		return nil, err
	}
	backups, err := transaction.OpenBackupDir(root, init.TransactionID)
	if err != nil {
		return nil, err
	}
	e := &Executor{Platform: platform, BackupDir: backups, allowFile: allow, systemFiles: root == systemStateRoot}
	init.FileRecovery = true
	init.OperationOrder = make([]string, len(ops))
	var preparedFiles []manifestv1.OperationReceipt
	for i, op := range ops {
		if err := op.Validate(); err != nil {
			return nil, err
		}
		init.OperationOrder[i] = op.OperationID
		switch {
		case manifestv1.IsRecoverableFileKind(op.Kind):
			receipt, _, _, _, err := e.prepareFile(op, true)
			if err != nil {
				return nil, fmt.Errorf("prepare rollback for operation %q: %w", op.OperationID, err)
			}
			preparedFiles = append(preparedFiles, receipt)
		case manifestv1.IsRecoverableKind(op.Kind):
			if platform == nil {
				return nil, fmt.Errorf("prepare rollback for operation %q: no platform provider configured", op.OperationID)
			}
			if op.Kind == protocol.InstallPackageArtifact || op.Kind == protocol.RemoveOwnedPackage {
				if _, err := approvedPackageUndo(op); err != nil {
					return nil, fmt.Errorf("prepare rollback for operation %q: %w", op.OperationID, err)
				}
			}
		default:
			return nil, fmt.Errorf("prepare rollback for operation %q: %w", op.OperationID, ErrUnsupportedKind)
		}
	}
	if len(preparedFiles) > 0 {
		init.PreparedFiles = preparedFiles
	}
	j, err := transaction.Create(filepath.Join(root, "transactions", init.TransactionID+".json"), init)
	if err != nil {
		// Rename can succeed before directory sync fails; keep the backups.
		return nil, fmt.Errorf("%w: persist prepared transaction %q: %w", ErrRecoveryRequired, init.TransactionID, err)
	}
	e.Journal = j
	return e, nil
}

// RecoverFiles rolls back file-only transactions under the same destination policy used for apply.
func RecoverFiles(ctx context.Context, root, id string, paths []string) error {
	return RecoverTransaction(ctx, root, id, paths, nil)
}

// RecoverTransaction rolls back an interrupted recoverable transaction (packages, files, services)
// from disk under the shared lock and destination policy.
func RecoverTransaction(ctx context.Context, root, id string, paths []string, platform PlatformApplier) error {
	allow := filePolicy(root, paths)
	if allow == nil {
		return ErrPrivilegesRequired
	}
	return recoverTransaction(ctx, root, id, allow, platform)
}

func recoverFiles(ctx context.Context, root, id string, allow func(string) bool) error {
	return recoverTransaction(ctx, root, id, allow, nil)
}

func recoverTransaction(ctx context.Context, root, id string, allow func(string) bool, platform PlatformApplier) error {
	lock, err := transaction.AcquireLock(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	j, err := transaction.OpenLocked(root, id)
	if err != nil {
		return err
	}
	data := j.Data()
	if !data.FileRecovery || (root == systemStateRoot && data.PreparedFiles == nil && hasAppliedFileOp(data)) || data.State == "completed" || data.State == "aborted" || data.State == "planned" {
		return transaction.ErrInvalidState
	}
	if data.State == "rolled_back" {
		return nil
	}
	// Manifest publication is not yet part of the transaction.
	if _, err := os.Lstat(filepath.Join(root, "manifest.json")); !errors.Is(err, os.ErrNotExist) {
		return ErrRecoveryRequired
	}
	e, err := newFileExecutor(j, root, allow)
	if err != nil {
		return err
	}
	e.Platform = platform
	_, err = e.Rollback(ctx)
	if err != nil {
		return errors.Join(ErrRecoveryRequired, err)
	}
	return nil
}

func hasAppliedFileOp(data manifestv1.TransactionJournal) bool {
	for _, r := range data.AppliedOperations {
		if manifestv1.IsRecoverableFileKind(r.Kind) {
			return true
		}
	}
	return false
}

// The caller holds the shared lock and supplies a policy for a trusted isolated tree.
func newFileExecutor(j *transaction.Journal, root string, allow func(string) bool) (*Executor, error) {
	if allow == nil || !j.Data().FileRecovery {
		return nil, transaction.ErrInvalidState
	}
	backups, err := transaction.OpenBackupDir(root, j.Data().TransactionID)
	if err != nil {
		return nil, err
	}
	return &Executor{Journal: j, BackupDir: backups, allowFile: allow, systemFiles: root == systemStateRoot}, nil
}

type fileState = manifestv1.FileState

func (e *Executor) inspectFile(path string) (fileState, []byte, error) {
	state := fileState{Path: path}
	if e.allowFile == nil || !e.allowFile(path) {
		return state, nil, fmt.Errorf("file destination not allowed: %q", path)
	}
	data, mode, err := readOrdinaryFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// Never create unjournaled parent directories.
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil || !parent.IsDir() {
			return state, nil, fmt.Errorf("destination parent is unavailable: %q", path)
		}
		return state, nil, nil
	}
	if err != nil {
		return state, nil, err
	}
	state.Exists, state.SHA256, state.Mode = true, sha256Hex(data), fmt.Sprintf("%04o", mode)
	return state, data, nil
}

func readOrdinaryFile(path string) ([]byte, os.FileMode, error) {
	if err := validateSafePath(path); err != nil {
		return nil, 0, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode() != info.Mode().Perm() || st.Nlink != 1 ||
		st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) {
		return nil, 0, fmt.Errorf("unsupported file metadata: %q", path)
	}
	if n, err := syscall.Listxattr(path, nil); n != 0 || err != nil {
		return nil, 0, fmt.Errorf("cannot back up extended attributes for %q (count %d, error %v)", path, n, err)
	}
	data, err := os.ReadFile(path)
	return data, info.Mode().Perm(), err
}

func syncFileParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func replaceFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".fplogin-file-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	staged, stagedMode, err := readOrdinaryFile(f.Name())
	if err != nil {
		return err
	}
	if stagedMode != mode || !bytes.Equal(staged, data) {
		return fmt.Errorf("staged file does not match intended state: %q", path)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncFileParent(path)
}

func (e *Executor) backupPath(id string) string {
	return filepath.Join(e.BackupDir, sha256Hex([]byte(id))+".bak")
}

func verifyBackup(path, digest string) ([]byte, error) {
	data, mode, err := readOrdinaryFile(path)
	if err != nil {
		return nil, err
	}
	if mode != 0o600 || sha256Hex(data) != digest {
		return nil, fmt.Errorf("unsafe or corrupt backup %q", path)
	}
	return data, nil
}

func (e *Executor) prepareFile(op protocol.Operation, createBackup bool) (receipt manifestv1.OperationReceipt, content []byte, before, after fileState, err error) {
	params, path, err := recoverableFile(op)
	if err != nil {
		return
	}
	var original []byte
	before, original, err = e.inspectFile(path)
	if err != nil {
		return
	}
	after = fileState{Path: path}
	var mode uint64
	if op.Kind == protocol.WriteFileAtomic {
		content, err = base64.StdEncoding.DecodeString(params.Content)
		if err != nil || sha256Hex(content) != params.SHA256 {
			err = ErrHashMismatch
			return
		}
		mode, err = strconv.ParseUint(params.Mode, 8, 9)
		if err != nil {
			return
		}
		if e.systemFiles && (string(content) != systemThemeData || mode != 0o644 || params.Owner != "root" || params.Group != "root") {
			err = ErrPrecondition
			return
		}
		after = fileState{Path: path, Exists: true, SHA256: params.SHA256, Mode: fmt.Sprintf("%04o", mode)}
	} else if e.systemFiles {
		err = ErrUnsupportedKind
		return
	} else if !before.Exists || before.SHA256 != params.Expected {
		err = ErrHashMismatch
		return
	}
	if before.Exists {
		path := e.backupPath(op.OperationID)
		if createBackup {
			if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				err = fmt.Errorf("backup already exists or cannot be inspected: %q", path)
				return
			}
			if err = replaceFile(path, original, 0o600); err != nil {
				return
			}
		}
		if _, err = verifyBackup(path, before.SHA256); err != nil {
			return
		}
	}
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	now := time.Now().UTC().Format(time.RFC3339)
	receipt = manifestv1.OperationReceipt{OperationID: op.OperationID, Kind: op.Kind, StartedAt: now, CompletedAt: now,
		Status: "pending", BeforeState: toObject(b), AfterState: toObject(a), Compensation: protocol.Object{}}
	return
}

func (e *Executor) executeRecoverableFile(op protocol.Operation) (manifestv1.OperationReceipt, error) {
	receipt, content, before, after, err := e.prepareFile(op, e.Journal.Data().PreparedFiles == nil)
	if err != nil {
		return receipt, err
	}
	path := before.Path
	if err := e.Journal.RecordFileIntent(receipt); err != nil {
		return receipt, err
	}
	if observed, _, checkErr := e.inspectFile(path); checkErr != nil || observed != before {
		err = errors.Join(ErrPrecondition, checkErr)
	} else if after.Exists {
		mode, _ := strconv.ParseUint(after.Mode, 8, 9)
		err = replaceFile(path, content, os.FileMode(mode))
	} else {
		err = removeAndSync(path)
	}
	if err == nil {
		err = e.verifyFile(after)
	}
	receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	receipt.Status = "success"
	if err != nil {
		receipt.Status = "failed"
	}
	return receipt, errors.Join(err, e.Journal.RecordResult(op.OperationID, receipt))
}

func removeAndSync(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncFileParent(path)
}

func (e *Executor) verifyFile(expected fileState) error {
	actual, _, err := e.inspectFile(expected.Path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("file state differs from journal: %q", expected.Path)
	}
	return nil
}

func (e *Executor) restoreFile(receipt manifestv1.OperationReceipt) error {
	before, err := manifestv1.DecodeFileState(receipt.BeforeState)
	if err != nil {
		return errors.Join(transaction.ErrCorruptJournal, err)
	}
	after, err := manifestv1.DecodeFileState(receipt.AfterState)
	if err != nil {
		return errors.Join(transaction.ErrCorruptJournal, err)
	}
	if before.Path != after.Path || (receipt.Kind == protocol.WriteFileAtomic && !after.Exists) ||
		(receipt.Kind == protocol.RemoveOwnedFile && (!before.Exists || after.Exists)) {
		return transaction.ErrCorruptJournal
	}
	actual, _, err := e.inspectFile(before.Path)
	if err != nil {
		return err
	}
	if actual == before {
		return syncFileParent(before.Path)
	}
	if actual != after {
		return fmt.Errorf("file changed independently: %q", before.Path)
	}
	if before.Exists {
		data, err := verifyBackup(e.backupPath(receipt.OperationID), before.SHA256)
		if err != nil {
			return err
		}
		mode, _ := strconv.ParseUint(before.Mode, 8, 9)
		err = replaceFile(before.Path, data, os.FileMode(mode))
		if err != nil {
			return err
		}
	} else if err := removeAndSync(before.Path); err != nil {
		return err
	}
	return e.verifyFile(before)
}
