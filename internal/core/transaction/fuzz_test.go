package transaction_test

import (
	"os"
	"path/filepath"
	"testing"

	"fplogin/internal/core/transaction"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

// FuzzDecodeTransactionJournal tests that arbitrary byte inputs never panic the journal decoder.
func FuzzDecodeTransactionJournal(f *testing.F) {
	// Seed corpus with valid and invalid variants
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":"1.0","transaction_id":"tx-1"}`))
	f.Add([]byte(`{"schema_version":"malicious","password":"evil"}`))
	f.Add([]byte(`\x00\xff\xfe\x00`))
	f.Add([]byte(`{"state":"applying","operation_order":["op1"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_, _ = manifestv1.DecodeTransactionJournal(data)
	})
}

// FuzzJournalOpen tests that loading arbitrary disk data into Journal never panics.
func FuzzJournalOpen(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"schema_version":"1.0","transaction_id":"tx-fuzz","state":"prepared"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "fuzz_journal.json")
		if err := os.WriteFile(filePath, data, 0o600); err != nil {
			return
		}
		// Must not panic
		_, _ = transaction.Open(filePath)
	})
}
