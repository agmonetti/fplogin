package transaction

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestLockAcrossProcesses(t *testing.T) {
	const childRoot = "FPLOGIN_TEST_LOCK_ROOT"
	if root := os.Getenv(childRoot); root != "" {
		lock, err := AcquireLock(root)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		fmt.Println("locked")
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			t.Fatal(err)
		}
		return
	}

	root := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), childRoot+"="+root)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if ready, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || ready != "locked\n" {
		t.Fatalf("child did not acquire its lock: %q, %v", ready, err)
	}
	if contender, err := AcquireLock(root); !errors.Is(err, ErrTransactionBusy) {
		if contender != nil {
			_ = contender.Close()
		}
		t.Fatalf("contender: got %v, want ErrTransactionBusy", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := cmd.Wait(); !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("lock holder did not die from SIGKILL: %v", err)
	}
	lock, err := AcquireLock(root)
	if err != nil {
		t.Fatalf("acquire after SIGKILL: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLockRetriesDirectorySync(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	want := []string{filepath.Join(root, "transactions"), root, parent}
	var synced []string
	syncFailure := errors.New("injected parent fsync failure")
	syncDir := func(dir *os.File) error {
		synced = append(synced, dir.Name())
		if dir.Name() == parent {
			return syncFailure
		}
		return dir.Sync()
	}
	lock, err := acquireLock(root, syncDir)
	if lock != nil {
		_ = lock.Close()
		t.Fatal("returned a lock despite a parent fsync failure")
	}
	if !errors.Is(err, syncFailure) || !reflect.DeepEqual(synced, want) {
		t.Fatalf("got sync sequence %v and error %v, want %v and injected error", synced, err, want)
	}

	synced = nil
	lock, err = acquireLock(root, func(dir *os.File) error {
		synced = append(synced, dir.Name())
		return dir.Sync()
	})
	if err != nil {
		t.Fatalf("retry after sync failure: %v", err)
	}
	defer lock.Close()
	if !reflect.DeepEqual(synced, want) {
		t.Fatalf("retry synced %v, want %v", synced, want)
	}
}

func TestLockRejectsUnsafeState(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(path string) error
	}{
		{"state", func(path string) error { return os.Symlink(t.TempDir(), path) }},
		{"state/transactions", func(path string) error { return os.Symlink(t.TempDir(), path) }},
		{"state/transaction.lock", func(path string) error { return os.WriteFile(path, []byte("not private"), 0o644) }},
		{"state/transaction.lock", func(path string) error { return os.Symlink(filepath.Join(t.TempDir(), "missing"), path) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, tc.name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := tc.make(path); err != nil {
				t.Fatal(err)
			}
			if lock, err := AcquireLock(filepath.Join(parent, "state")); err == nil {
				_ = lock.Close()
				t.Fatal("acquired a lock with unsafe state")
			} else if errors.Is(err, ErrTransactionBusy) {
				t.Fatal("unsafe state misreported as lock contention")
			}
		})
	}
}
