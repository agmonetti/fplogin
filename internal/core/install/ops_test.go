package install

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

func validTestJournal(t *testing.T, dir, id string, opIDs []string) *transaction.Journal {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	init := manifestv1.TransactionJournal{
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
	path := filepath.Join(dir, id+".json")
	j, err := transaction.Create(path, init)
	if err != nil {
		t.Fatalf("create journal %q: %v", path, err)
	}
	return j
}

func testSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type fakePlatformApplier struct {
	calledOps []protocol.Operation
	retErr    error
}

func (f *fakePlatformApplier) ApplyOperation(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error) {
	f.calledOps = append(f.calledOps, op)
	if f.retErr != nil {
		return manifestv1.OperationReceipt{}, f.retErr
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return manifestv1.OperationReceipt{
		OperationID:  op.OperationID,
		Kind:         op.Kind,
		StartedAt:    now,
		CompletedAt:  now,
		Status:       "success",
		BeforeState:  protocol.Object{"state": json.RawMessage(`"disabled"`)},
		AfterState:   protocol.Object{"state": json.RawMessage(`"enabled"`)},
		Compensation: protocol.Object{"restore": json.RawMessage(`"disabled"`)},
	}, nil
}

func TestExecute_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	j := validTestJournal(t, tmpDir, "tx-dir", []string{"op-dir"})
	exec, err := NewExecutor(j, nil, filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}

	targetDir := filepath.Join(tmpDir, "test-created-dir")
	params := map[string]string{
		"path":  targetDir,
		"mode":  "0755",
		"owner": "root",
		"group": "root",
	}
	paramsJSON, _ := json.Marshal(params)
	compJSON := json.RawMessage(`{"kind":"remove_directory","path":"` + targetDir + `"}`)

	op := protocol.Operation{
		OperationID:    "op-dir",
		Kind:           protocol.CreateDirectory,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
		Parameters:     paramsJSON,
		Compensation:   compJSON,
	}

	receipt, err := exec.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if receipt.Status != "success" {
		t.Errorf("expected status 'success', got %q", receipt.Status)
	}

	if _, err := os.Stat(targetDir); err != nil {
		t.Errorf("directory was not created: %v", err)
	}

	// Now test rollback: directory should be removed
	rbReceipts, err := exec.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if len(rbReceipts) != 1 || rbReceipts[0].Status != "rolled_back" {
		t.Errorf("expected rolled_back receipt, got %v", rbReceipts)
	}

	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Errorf("expected directory to be removed on rollback, got err: %v", err)
	}
}

func TestExecute_WriteFileAtomic_NewAndRollback(t *testing.T) {
	tmpDir := t.TempDir()
	j := validTestJournal(t, tmpDir, "tx-write", []string{"op-write"})
	exec, err := NewExecutor(j, nil, filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(tmpDir, "dest", "hello.txt")
	content := []byte("Hello, atomic fplogin!")
	contentB64 := base64.StdEncoding.EncodeToString(content)
	contentHash := testSHA256(content)

	params := map[string]string{
		"destination_path": filePath,
		"content_base64":   contentB64,
		"sha256":           contentHash,
		"mode":             "0644",
		"owner":            "root",
		"group":            "root",
	}
	paramsJSON, _ := json.Marshal(params)
	compJSON := json.RawMessage(`{"kind":"remove_file","path":"` + filePath + `"}`)

	op := protocol.Operation{
		OperationID:    "op-write",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
		Parameters:     paramsJSON,
		Compensation:   compJSON,
	}

	receipt, err := exec.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("Execute write failed: %v", err)
	}
	if receipt.Status != "success" {
		t.Errorf("expected status 'success', got %q", receipt.Status)
	}

	written, err := os.ReadFile(filePath)
	if err != nil || string(written) != string(content) {
		t.Fatalf("unexpected written file content: %s, err: %v", string(written), err)
	}

	// Rollback: new file should be deleted
	_, err = exec.Rollback(context.Background())
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected file to be removed after rollback, err: %v", err)
	}
}

func TestExecute_WriteFileAtomic_OverwritesExistingAndRestoresBackup(t *testing.T) {
	tmpDir := t.TempDir()
	j := validTestJournal(t, tmpDir, "tx-overwrite", []string{"op-ow"})
	exec, err := NewExecutor(j, nil, filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(tmpDir, "existing.txt")
	originalContent := []byte("Original file before fplogin")
	if err := os.WriteFile(filePath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	newContent := []byte("Replaced by fplogin")
	newHash := testSHA256(newContent)

	params := map[string]string{
		"destination_path": filePath,
		"content_base64":   base64.StdEncoding.EncodeToString(newContent),
		"sha256":           newHash,
		"mode":             "0644",
		"owner":            "root",
		"group":            "root",
	}
	paramsJSON, _ := json.Marshal(params)
	compJSON := json.RawMessage(`{"kind":"restore_file","path":"` + filePath + `"}`)

	op := protocol.Operation{
		OperationID:    "op-ow",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`true`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`true`)},
		Parameters:     paramsJSON,
		Compensation:   compJSON,
	}

	receipt, err := exec.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("Execute overwrite failed: %v", err)
	}
	if receipt.Status != "success" {
		t.Fatalf("status not success: %s", receipt.Status)
	}

	// Verify file has new content
	cur, _ := os.ReadFile(filePath)
	if string(cur) != string(newContent) {
		t.Errorf("expected %q, got %q", string(newContent), string(cur))
	}

	// Rollback: original content should be restored
	_, err = exec.Rollback(context.Background())
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	restored, err := os.ReadFile(filePath)
	if err != nil || string(restored) != string(originalContent) {
		t.Fatalf("expected restored content %q, got %q (err: %v)", string(originalContent), string(restored), err)
	}
}

func TestExecute_RemoveOwnedFile_AndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	j := validTestJournal(t, tmpDir, "tx-rm", []string{"op-rm"})
	exec, err := NewExecutor(j, nil, filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(tmpDir, "to-remove.txt")
	fileContent := []byte("Remove me cleanly")
	if err := os.WriteFile(filePath, fileContent, 0o644); err != nil {
		t.Fatal(err)
	}
	expectedHash := testSHA256(fileContent)

	params := map[string]string{
		"path":            filePath,
		"expected_sha256": expectedHash,
	}
	paramsJSON, _ := json.Marshal(params)
	compJSON := json.RawMessage(`{"kind":"restore_file","path":"` + filePath + `"}`)

	op := protocol.Operation{
		OperationID:    "op-rm",
		Kind:           protocol.RemoveOwnedFile,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`true`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`false`)},
		Parameters:     paramsJSON,
		Compensation:   compJSON,
	}

	receipt, err := exec.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("RemoveOwnedFile failed: %v", err)
	}
	if receipt.Status != "success" {
		t.Errorf("status not success: %s", receipt.Status)
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("file should have been removed, got err: %v", err)
	}

	// Rollback: file should be restored from backup
	_, err = exec.Rollback(context.Background())
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	restored, err := os.ReadFile(filePath)
	if err != nil || string(restored) != string(fileContent) {
		t.Fatalf("expected restored content %q, got %q", string(fileContent), string(restored))
	}
}

func TestExecute_RemoveOwnedFile_HashMismatchRejected(t *testing.T) {
	tmpDir := t.TempDir()
	j := validTestJournal(t, tmpDir, "tx-rm-bad", []string{"op-rm-bad"})
	exec, err := NewExecutor(j, nil, filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}

	filePath := filepath.Join(tmpDir, "modified.txt")
	_ = os.WriteFile(filePath, []byte("User modified content!"), 0o644)

	params := map[string]string{
		"path":            filePath,
		"expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}
	paramsJSON, _ := json.Marshal(params)
	compJSON := json.RawMessage(`{"kind":"restore_file","path":"` + filePath + `"}`)

	op := protocol.Operation{
		OperationID:    "op-rm-bad",
		Kind:           protocol.RemoveOwnedFile,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"existed": json.RawMessage(`true`)},
		ExpectedAfter:  protocol.Object{"existed": json.RawMessage(`false`)},
		Parameters:     paramsJSON,
		Compensation:   compJSON,
	}

	_, err = exec.Execute(context.Background(), op)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("expected ErrHashMismatch, got %v", err)
	}

	// File must NOT have been removed
	if _, err := os.Stat(filePath); err != nil {
		t.Errorf("file should not have been removed on hash mismatch: %v", err)
	}
}

func TestExecute_PlatformDelegation(t *testing.T) {
	tmpDir := t.TempDir()
	j := validTestJournal(t, tmpDir, "tx-plat", []string{"op-svc"})
	fakePlat := &fakePlatformApplier{}
	exec, err := NewExecutor(j, fakePlat, filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatal(err)
	}

	params := map[string]any{
		"service_reference": "sddm.service",
		"enabled":           true,
	}
	paramsJSON, _ := json.Marshal(params)
	compJSON := json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":false}`)

	op := protocol.Operation{
		OperationID:    "op-svc",
		Kind:           protocol.SetServiceEnabled,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"state": json.RawMessage(`"disabled"`)},
		ExpectedAfter:  protocol.Object{"state": json.RawMessage(`"enabled"`)},
		Parameters:     paramsJSON,
		Compensation:   compJSON,
	}

	receipt, err := exec.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("Execute platform op failed: %v", err)
	}
	if receipt.Status != "success" {
		t.Errorf("status not success: %s", receipt.Status)
	}
	if len(fakePlat.calledOps) != 1 {
		t.Errorf("expected 1 platform call, got %d", len(fakePlat.calledOps))
	}
}
