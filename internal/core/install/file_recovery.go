package install

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

// recoverFiles is the internal recovery entry point for isolated file transactions.
func recoverFiles(ctx context.Context, root, id string, allow func(string) bool) error {
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
	if !data.FileRecovery || data.State == "completed" || data.State == "aborted" || data.State == "planned" {
		return transaction.ErrInvalidState
	}
	if data.State == "rolled_back" {
		return nil
	}
	// Manifest publication is not yet part of the file transaction.
	if _, err := os.Lstat(filepath.Join(root, "manifest.json")); !errors.Is(err, os.ErrNotExist) {
		return ErrRecoveryRequired
	}
	e, err := newFileExecutor(j, root, allow)
	if err != nil {
		return err
	}
	_, err = e.Rollback(ctx)
	if err != nil {
		return errors.Join(ErrRecoveryRequired, err)
	}
	return nil
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
	return &Executor{Journal: j, BackupDir: backups, allowFile: allow}, nil
}

// fileState describes an ordinary single-link file in an isolated, trusted tree.
type fileState struct {
	Path   string `json:"destination_path"`
	Exists bool   `json:"existed"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

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

func (e *Executor) executeRecoverableFile(op protocol.Operation) (receipt manifestv1.OperationReceipt, err error) {
	var params struct {
		Destination string `json:"destination_path"`
		Path        string `json:"path"`
		Content     string `json:"content_base64"`
		SHA256      string `json:"sha256"`
		Expected    string `json:"expected_sha256"`
		Mode        string `json:"mode"`
	}
	if err := json.Unmarshal(op.Parameters, &params); err != nil {
		return receipt, err
	}
	path := params.Destination
	if op.Kind == protocol.RemoveOwnedFile {
		path = params.Path
	} else if op.Kind != protocol.WriteFileAtomic {
		return receipt, ErrUnsupportedKind
	}
	before, original, err := e.inspectFile(path)
	if err != nil {
		return receipt, err
	}
	after := fileState{Path: path}
	var content []byte
	var mode uint64
	if op.Kind == protocol.WriteFileAtomic {
		content, err = base64.StdEncoding.DecodeString(params.Content)
		if err != nil || sha256Hex(content) != params.SHA256 {
			return receipt, ErrHashMismatch
		}
		mode, err = strconv.ParseUint(params.Mode, 8, 9)
		if err != nil {
			return receipt, err
		}
		after = fileState{Path: path, Exists: true, SHA256: params.SHA256, Mode: fmt.Sprintf("%04o", mode)}
	} else if !before.Exists || before.SHA256 != params.Expected {
		return receipt, ErrHashMismatch
	}
	if before.Exists {
		path := e.backupPath(op.OperationID)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return receipt, fmt.Errorf("backup already exists or cannot be inspected: %q", path)
		}
		if err := replaceFile(path, original, 0o600); err != nil {
			return receipt, err
		}
		if _, err := verifyBackup(path, before.SHA256); err != nil {
			return receipt, err
		}
	}
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	now := time.Now().UTC().Format(time.RFC3339)
	receipt = manifestv1.OperationReceipt{OperationID: op.OperationID, Kind: op.Kind, StartedAt: now, CompletedAt: now,
		Status: "pending", BeforeState: toObject(b), AfterState: toObject(a), Compensation: protocol.Object{}}
	if err := e.Journal.RecordFileIntent(receipt); err != nil {
		return receipt, err
	}
	if observed, _, checkErr := e.inspectFile(path); checkErr != nil || observed != before {
		err = errors.Join(ErrPrecondition, checkErr)
	} else if after.Exists {
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
	before, err := decodeFileState(receipt.BeforeState)
	if err != nil {
		return err
	}
	after, err := decodeFileState(receipt.AfterState)
	if err != nil {
		return err
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

func decodeFileState(obj protocol.Object) (fileState, error) {
	var s fileState
	b, err := json.Marshal(obj)
	if err != nil {
		return s, err
	}
	if err := protocol.DecodeStrict(b, &s, "destination_path", "existed"); err != nil {
		return s, err
	}
	if s.Exists {
		mode, err := strconv.ParseUint(s.Mode, 8, 9)
		if err != nil || s.Mode != fmt.Sprintf("%04o", mode) || len(s.SHA256) != 64 || !validFileDigest(s.SHA256) {
			return s, transaction.ErrCorruptJournal
		}
	} else if s.Mode != "" || s.SHA256 != "" {
		return s, transaction.ErrCorruptJournal
	}
	return s, nil
}

func validFileDigest(digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return err == nil && hex.EncodeToString(decoded) == digest
}
