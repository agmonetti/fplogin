package install

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
)

func systemWrite(path, text string) protocol.Operation {
	return protocol.Operation{OperationID: "write-theme", Kind: protocol.WriteFileAtomic,
		Dependencies: []string{}, Preconditions: []json.RawMessage{}, ExpectedBefore: protocol.Object{}, ExpectedAfter: protocol.Object{},
		Parameters:   json.RawMessage(fmt.Sprintf(`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`, path, base64.StdEncoding.EncodeToString([]byte(text)), sha256Hex([]byte(text)))),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"restore_file","path":%q}`, path))}
}

type syncFailure struct{}

func (syncFailure) WriteAndSync(string, []byte, os.FileMode) error { return syscall.EIO }

func TestSystemFileTransaction(t *testing.T) {
	if os.Getenv("FPL_ISOLATED_ADAPTER_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable root Arch fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	root := systemStateRoot
	if filePolicy(root, []string{systemThemeFile}) != nil || filePolicy(t.TempDir(), nil) != nil {
		t.Fatal("accepted custom elevated destinations or state root")
	}
	baseline := []byte("[Theme]\nCurrent=stock\n")
	if err := os.WriteFile(systemThemeFile, baseline, 0o640); err != nil {
		t.Fatal(err)
	}
	lock, err := transaction.AcquireLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	init := validTestJournal(t, t.TempDir(), fileTx, []string{"write-theme"}).Data()
	op := systemWrite(systemThemeFile, systemThemeData)
	for _, denied := range []protocol.Operation{
		systemWrite("/etc/sddm.conf", systemThemeData),
		systemWrite(systemThemeFile, "[General]\nDisplayServer=x11\n"),
	} {
		if _, err := beginFileTransaction(root, nil, init, []protocol.Operation{denied}); err == nil {
			t.Fatal("accepted unsafe elevated write")
		}
	}
	e, err := beginFileTransaction(root, nil, init, []protocol.Operation{op})
	if err != nil {
		t.Fatal(err)
	}
	e.Journal.SetSyncer(syncFailure{})
	if _, err := e.Execute(ctx, op); !errors.Is(err, syscall.EIO) {
		t.Fatalf("expected sync failure, got %v", err)
	}
	if data, err := os.ReadFile(systemThemeFile); err != nil || string(data) != string(baseline) {
		t.Fatalf("target changed despite failed intent sync: %q %v", data, err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	runUntilKilled(t, ctx, append(os.Environ(), "FPL_FILE_RECOVERY_CHILD="+root, "FPL_FILE_RECOVERY_SYSTEM=1"), func() {
		if _, err := transaction.AcquireLock(root); !errors.Is(err, transaction.ErrTransactionBusy) {
			t.Fatalf("second process did not contend for lock: %v", err)
		}
	})
	lock, err = transaction.AcquireLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	init.TransactionID = "second-system-tx"
	if _, err := beginFileTransaction(root, nil, init, []protocol.Operation{op}); !errors.Is(err, transaction.ErrUnresolvedTransaction) {
		t.Fatalf("started another transaction before recovery: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(systemThemeFile); err != nil || string(data) != systemThemeData {
		t.Fatalf("approved change did not reach disk: %q %v", data, err)
	}
	// A changed destination must remain untouched, including when retrying recovery.
	if err := os.Remove(systemThemeFile); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(systemThemeFile), "other.conf")
	if err := os.WriteFile(other, []byte(systemThemeData), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, systemThemeFile); err != nil {
		t.Fatal(err)
	}
	if err := RecoverFiles(ctx, root, fileTx, nil); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("recovery followed a substituted destination: %v", err)
	}
	if data, err := os.ReadFile(other); err != nil || string(data) != systemThemeData {
		t.Fatalf("unlisted file changed: %q %v", data, err)
	}
	if err := os.Rename(other, systemThemeFile); err != nil {
		t.Fatal(err)
	}
	if err := RecoverFiles(ctx, root, fileTx, nil); err != nil {
		t.Fatal(err)
	}
	if data, mode, err := readOrdinaryFile(systemThemeFile); err != nil || string(data) != string(baseline) || mode != 0o640 {
		t.Fatalf("baseline not restored: %q %o %v", data, mode, err)
	}
}
