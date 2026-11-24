package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

// The five backup entries from the pinned signed sddm 0.21.0-7 x86_64 archive.
const stockArchive = "927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a"

var stockFiles = []struct {
	path, digest string
	mode         os.FileMode
}{
	{"/etc/pam.d/sddm", "d7394292a65ae463926c2c3d2cb4e67bbfeb20995450c8e4c92fe5a28e7c4254", 0644},
	{"/etc/pam.d/sddm-autologin", "1a84cf752782b03b53f66188013bf7e4af4f5e6feb7266bfe58c3faaa20777b4", 0644},
	{"/etc/pam.d/sddm-greeter", "3406bce46be8450e28ddbccfbcd0e1f8fa585d57da8833ff7294cf3aee84bb46", 0644},
	{"/usr/share/sddm/scripts/Xsetup", "497170ab2048d0ba0949a3086e45b1a9dfd9eb5744a9cb6c06b1747212385cc2", 0755},
	{"/usr/share/sddm/scripts/Xstop", "1b3e15216082763fa6d388248c78d864d8a3bcf4c3fb21b1feb9e9c31a30fac0", 0755},
}

func verifyStock(req platformv1.Request) (json.RawMessage, error) {
	var p platformv1.VerifyOperationPayload
	if err := json.Unmarshal(req.Payload, &p); err != nil {
		return nil, err
	}
	if (p.Phase != "pre_apply" && p.Phase != "post_rollback") || req.Context.Root != "/" || len(p.ExpectedPostcondition) != 1 || string(p.ExpectedPostcondition["stock_backup_files_match_archive"]) != `"`+stockArchive+`"` {
		return nil, notImplemented(req.Operation)
	}
	if err := checkStockFiles(); err != nil {
		return nil, err
	}
	return json.Marshal(platformv1.PlatformVerificationReport{ReportID: p.OperationID, VerifiedAt: time.Now().UTC().Format(time.RFC3339), Checks: []platformv1.VerificationCheck{{CheckID: "stock_backup_files_match_archive", Status: "passed", Severity: "info", Evidence: []protocol.Evidence{evidence("package", "sddm", "stock backup files match pinned archive")}}}})
}

func checkStockFiles() error {
	for _, entry := range stockFiles {
		path, err := filepath.EvalSymlinks(entry.path)
		if err != nil || path != entry.path {
			return fmt.Errorf("stock backup path not intact: %s", entry.path)
		}
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		if info.Mode() != entry.mode || st.Uid != 0 || st.Gid != 0 || info.Size() > 4096 {
			return fmt.Errorf("stock backup metadata differs: %s", path)
		}
		h := sha256.New()
		if _, err := io.Copy(h, io.LimitReader(f, 4097)); err != nil {
			return err
		}
		if fmt.Sprintf("%x", h.Sum(nil)) != entry.digest {
			return fmt.Errorf("stock backup contents differ: %s", path)
		}
	}
	return nil
}
