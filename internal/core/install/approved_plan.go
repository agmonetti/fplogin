package install

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

// persistApprovedPlan is called under the transaction lock after approval.
// Names and contents are core-owned. Request fields never select a directory.
func persistApprovedPlan(stateRoot, txID, digest string, plan adapterv1.ChangePlan) error {
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
		return fmt.Errorf("approved plan changed")
	}
	dir, err := transaction.OpenBackupDir(stateRoot, txID)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "approved-plan.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Read only through a locked journal, not through adapter-supplied staging paths.
func loadApprovedPlan(stateRoot, txID string) (adapterv1.ChangePlan, error) {
	j, err := transaction.OpenLocked(stateRoot, txID)
	if err != nil {
		return adapterv1.ChangePlan{}, err
	}
	digest := j.Data().AcceptedPlan.PlanDigest
	if err := protocol.ValidDigest(digest); err != nil {
		return adapterv1.ChangePlan{}, err
	}
	p := filepath.Join(stateRoot, "backups", txID, "approved-plan.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return adapterv1.ChangePlan{}, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
		return adapterv1.ChangePlan{}, fmt.Errorf("stored plan does not match journal approval")
	}
	return adapterv1.DecodeChangePlan(data)
}
