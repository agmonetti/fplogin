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
type stopBeforeResult string

func (status stopBeforeResult) WriteAndSync(_ string, data []byte, _ os.FileMode) error {
	var j struct {
		Applied []struct{ Status string } `json:"applied_operations"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	if len(j.Applied) == 1 && j.Applied[0].Status == string(status) {
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
	if os.Getenv("FPL_FILE_RECOVERY_RUN") == "1" {
		cfg, adapter, _ := setupTestFixtures(filepath.Dir(root))
		adapter.beforeVerify = func() {
			fmt.Println("ready")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
		_, err := Run(context.Background(), cfg)
		t.Fatalf("expected SIGKILL before verification completed, got %v", err)
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
	if os.Getenv("FPL_FILE_RECOVERY_SYSTEM") == "1" {
		e, err := newFileExecutor(j, root, filePolicy(root, nil))
		if err != nil {
			t.Fatal(err)
		}
		allow := e.allowFile
		checks := 0
		e.allowFile = func(path string) bool {
			checks++
			if checks == 2 {
				j.SetSyncer(stopBeforeResult("success"))
			}
			return allow(path)
		}
		_, err = e.Execute(context.Background(), systemWrite(systemThemeFile, systemThemeData))
		t.Fatalf("expected SIGKILL at result persistence, got %v", err)
	}
	e, err := newFileExecutor(j, root, func(p string) bool { return p == path })
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("FPL_FILE_RECOVERY_ROLLBACK") == "1" {
		j.SetSyncer(stopBeforeResult("rolled_back"))
		_, err = e.Rollback(context.Background())
		t.Fatalf("expected SIGKILL after restore, got %v", err)
	}
	checked := 0
	e.allowFile = func(p string) bool {
		checked++
		if checked == 2 {
			j.SetSyncer(stopBeforeResult("success"))
		}
		return p == path
	}
	newContent := []byte("new bytes")
	kind := protocol.WriteFileAtomic
	params, _ := json.Marshal(map[string]string{"destination_path": path, "content_base64": base64.StdEncoding.EncodeToString(newContent),
		"sha256": sha256Hex(newContent), "mode": "0644", "owner": "root", "group": "root"})
	if os.Getenv("FPL_FILE_RECOVERY_REMOVE") == "1" {
		kind = protocol.RemoveOwnedFile
		params, _ = json.Marshal(map[string]string{"path": path, "expected_sha256": sha256Hex([]byte("original bytes"))})
	}
	_, err = e.Execute(context.Background(), protocol.Operation{OperationID: "op-file", Kind: kind,
		Dependencies: []string{}, Preconditions: []json.RawMessage{}, ExpectedBefore: protocol.Object{}, ExpectedAfter: protocol.Object{},
		Parameters: params, Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"restore_file","path":%q}`, path))})
	t.Fatalf("expected SIGKILL at result persistence, got %v", err)
}

func runUntilKilled(t *testing.T, ctx context.Context, env []string, whileBlocked func()) {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileRecoveryChild$")
	cmd.Env = env
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
		t.Fatalf("worker did not reach persistence boundary: %q %s (%v)", line, rest, err)
	}
	if whileBlocked != nil {
		whileBlocked()
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := cmd.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("not killed by SIGKILL: %v", err)
	}
}

func TestRunRecoveryAfterSIGKILL(t *testing.T) {
	requireUnprivilegedLab(t)
	dir := t.TempDir()
	cfg, _, _ := setupTestFixtures(dir)
	root := filepath.Dir(cfg.JournalDir)
	path := cfg.IsolatedFiles[0]
	if err := os.WriteFile(path, []byte("baseline"), 0o640); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runUntilKilled(t, ctx, append(os.Environ(), "FPL_FILE_RECOVERY_CHILD="+root, "FPL_FILE_RECOVERY_RUN=1"), nil)
	entries, err := os.ReadDir(cfg.JournalDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one interrupted journal: %v %v", entries, err)
	}
	name := entries[0].Name()
	if data, err := os.ReadFile(path); err != nil || string(data) != "a" {
		t.Fatalf("did not run approved write: %q %v", data, err)
	}
	id := name[:len(name)-len(filepath.Ext(name))]
	j, err := transaction.Open(filepath.Join(cfg.JournalDir, name))
	if err != nil {
		t.Fatal(err)
	}
	data := j.Data()
	if len(data.PreparedFiles) != 1 || len(data.AppliedOperations) != 1 || !data.MatchesPreparedFile(0, data.AppliedOperations[0]) {
		t.Fatalf("durable plan does not match intent: %+v", data)
	}
	backup := filepath.Join(root, "backups", id, sha256Hex([]byte("op-1"))+".bak")
	if data, err := verifyBackup(backup, sha256Hex([]byte("baseline"))); err != nil || string(data) != "baseline" {
		t.Fatalf("durable backup: %q, %v", data, err)
	}
	if err := RecoverFiles(ctx, root, id, []string{path + "-other"}); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("recovery accepted an unlisted destination: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "a" {
		t.Fatalf("denied recovery modified the destination: %q %v", data, err)
	}
	if err := RecoverFiles(ctx, root, id, cfg.IsolatedFiles); err != nil {
		t.Fatal(err)
	}
	if data, mode, err := readOrdinaryFile(path); err != nil || string(data) != "baseline" || mode != 0o640 {
		t.Fatalf("recovery did not restore baseline: %q %o %v", data, mode, err)
	}
}

func TestFileRecoveryAfterSIGKILL(t *testing.T) {
	for _, tc := range []struct {
		name            string
		remove, corrupt bool
	}{
		{name: "replace"}, {name: "corrupt_backup", corrupt: true}, {name: "remove", remove: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			env := append(os.Environ(), "FPL_FILE_RECOVERY_CHILD="+root)
			if tc.remove {
				env = append(env, "FPL_FILE_RECOVERY_REMOVE=1")
			}
			allow := func(p string) bool { return p == path }
			runUntilKilled(t, ctx, env, func() {
				if err := recoverFiles(ctx, root, fileTx, allow); !errors.Is(err, transaction.ErrTransactionBusy) {
					t.Fatalf("recovery ignored shared lock: %v", err)
				}
			})
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
			got, readErr := os.ReadFile(path)
			if (!tc.remove && (readErr != nil || string(got) != "new bytes")) || (tc.remove && !errors.Is(readErr, os.ErrNotExist)) {
				t.Fatalf("forward mutation not found: %q, %v", got, readErr)
			}
			if tc.corrupt {
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
			if tc.remove {
				// Kill again after rollback has restored the file but before the rollback receipt.
				runUntilKilled(t, ctx, append(env, "FPL_FILE_RECOVERY_ROLLBACK=1"), nil)
				checkStatus("pending")
				if got, err := os.ReadFile(path); err != nil || string(got) != string(original) {
					t.Fatalf("rollback did not restore the file: %q, %v", got, err)
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
