package install

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
)

const fileTx = "tx-file-crash"

func TestReplaceFileRejectsInheritedACLBeforeRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	// Linux ACL v2: user_obj, named user, group_obj, mask, other.
	acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 2, 0, 4, 0, 254, 255, 0, 0,
		4, 0, 5, 0, 255, 255, 255, 255, 16, 0, 5, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	if err := syscall.Setxattr(dir, "system.posix_acl_default", acl, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) {
			t.Skip("filesystem has no POSIX ACL support")
		}
		t.Fatal(err)
	}
	if err := replaceFile(path, []byte("do not publish"), 0o644); err == nil {
		t.Fatal("staged file with inherited ACL was accepted")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination changed: %v", err)
	}
}

// Stop at the result sync, after the destination changed and its parent synced.
type stopBeforeResult struct{}

func (stopBeforeResult) WriteAndSync(_ string, data []byte, _ os.FileMode) error {
	var j struct {
		Applied []struct{ Status string } `json:"applied_operations"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	if len(j.Applied) == 1 && j.Applied[0].Status == "success" {
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
	return errors.New("unexpected journal write")
}

// Use the real journal Syncer for intent; intercept only the result write.
func TestFileRecoveryChild(t *testing.T) {
	root := os.Getenv("FPL_FILE_RECOVERY_CHILD")
	if root == "" {
		return
	}
	lock, err := transaction.AcquireLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	j, err := transaction.OpenLocked(root, fileTx)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(root), "target")
	e, err := newFileExecutor(j, root, func(p string) bool { return p == path })
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	e.allowFile = func(p string) bool {
		checked++
		if checked == 2 {
			j.SetSyncer(stopBeforeResult{})
		}
		return p == path
	}
	newContent := []byte("new bytes")
	params, _ := json.Marshal(map[string]string{"destination_path": path, "content_base64": base64.StdEncoding.EncodeToString(newContent),
		"sha256": sha256Hex(newContent), "mode": "0644", "owner": "root", "group": "root"})
	_, err = e.Execute(context.Background(), protocol.Operation{OperationID: "op-file", Kind: protocol.WriteFileAtomic,
		Dependencies: []string{}, Preconditions: []json.RawMessage{}, ExpectedBefore: protocol.Object{}, ExpectedAfter: protocol.Object{},
		Parameters: params, Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"restore_file","path":%q}`, path))})
	t.Fatalf("expected SIGKILL at result persistence, got %v", err)
}

func TestFileRecoveryAfterSIGKILL(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt_backup=%t", corrupt), func(t *testing.T) {
			dir := t.TempDir()
			root, path := filepath.Join(dir, "state"), filepath.Join(dir, "target")
			original := []byte("original bytes")
			if err := os.WriteFile(path, original, 0o640); err != nil {
				t.Fatal(err)
			}
			lock, err := transaction.AcquireLock(root)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			init := validTestJournal(t, dir, fileTx, []string{"op-file"}).Data()
			init.FileRecovery = true
			if _, err := transaction.Create(filepath.Join(root, "transactions", fileTx+".json"), init); err != nil {
				t.Fatal(err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileRecoveryChild$")
			cmd.Env = append(os.Environ(), "FPL_FILE_RECOVERY_CHILD="+root)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			reader := bufio.NewReader(stdout)
			if line, err := reader.ReadString('\n'); line != "ready\n" || err != nil {
				rest, _ := io.ReadAll(reader)
				t.Fatalf("worker did not reach mutation boundary: %q %s (%v)", line, rest, err)
			}
			allow := func(p string) bool { return p == path }
			if err := recoverFiles(ctx, root, fileTx, allow); !errors.Is(err, transaction.ErrTransactionBusy) {
				t.Fatalf("recovery ignored shared lock: %v", err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			var exit *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("not killed by SIGKILL: %v", err)
			}
			journalPath := filepath.Join(root, "transactions", fileTx+".json")
			checkStatus := func(want string) {
				t.Helper()
				j, err := transaction.Open(journalPath)
				if err != nil {
					t.Fatal(err)
				}
				receipts := j.Data().AppliedOperations
				if len(receipts) != 1 || receipts[0].Status != want {
					t.Fatalf("expected %s on disk, got %v", want, receipts)
				}
			}
			checkStatus("pending")
			if got, _ := os.ReadFile(path); string(got) != "new bytes" {
				t.Fatalf("forward mutation not found: %q", got)
			}
			if corrupt {
				backup := filepath.Join(root, "backups", fileTx, sha256Hex([]byte("op-file"))+".bak")
				if err := os.WriteFile(backup, []byte("corruption"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := recoverFiles(ctx, root, fileTx, allow); !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("corrupt backup not rejected: %v", err)
				}
				checkStatus("rollback_failed")
				if got, _ := os.ReadFile(path); string(got) != "new bytes" {
					t.Fatalf("corrupt backup modified destination: %q", got)
				}
				if err := replaceFile(backup, original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoverFiles(ctx, root, fileTx, allow); err != nil {
				t.Fatal(err)
			}
			checkStatus("rolled_back")
			got, mode, err := readOrdinaryFile(path)
			if err != nil || string(got) != string(original) || mode != 0o640 {
				t.Fatalf("original state not restored: %q %o %v", got, mode, err)
			}
		})
	}
}
