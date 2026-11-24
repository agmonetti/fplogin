package install

import (
	"encoding/json"
	"fmt"
	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	"os"
	"path/filepath"
	"testing"
)

func TestStageApprovedArchives(t *testing.T) {
	for _, test := range []string{"success", "stock missing", "stock corrupt", "symlink", "stock signature missing", "stock signature symlink", "extra"} {
		t.Run(test, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			cache := t.TempDir()
			lock, err := transaction.AcquireLock(root)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			_, a, _ := setupTestFixtures(root)
			plan := a.plan
			op := plan.Operations[0]
			op.Kind = protocol.InstallPackageArtifact
			for _, id := range []string{"candidate", "stock"} {
				ref := adapterv1.ArtifactReference{ArtifactID: id, Size: int64(len(id)), SHA256: sha256Hex([]byte(id)), MediaType: "application/octet-stream", Role: "package", CanonicalPath: "/ignore/adapter/path"}
				plan.ArtifactReferences = append(plan.ArtifactReferences, ref)
				path := filepath.Join(cache, ref.SHA256)
				body := id
				if id == "stock" {
					switch test {
					case "stock missing":
						continue
					case "stock corrupt":
						body = "wrong"
					case "symlink":
						if err := os.Symlink("/dev/null", path); err != nil {
							t.Fatal(err)
						}
						continue
					}
				}
				if id == "stock" && test == "stock signature symlink" {
					if err := os.Symlink(path, path+".sig"); err != nil {
						t.Fatal(err)
					}
				} else if id != "stock" || test != "stock signature missing" {
					if err := os.WriteFile(path+".sig", []byte("signature:"+id), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			op.Parameters = json.RawMessage(fmt.Sprintf(`{"package_reference":"candidate","artifact_id":"candidate","sha256":%q}`, plan.ArtifactReferences[0].SHA256))
			op.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"stock","artifact_id":"stock","sha256":%q}`, plan.ArtifactReferences[1].SHA256))
			plan.Operations = []protocol.Operation{op}
			if test == "extra" {
				r := plan.ArtifactReferences[0]
				r.ArtifactID = "unused"
				plan.ArtifactReferences = append(plan.ArtifactReferences, r)
			}
			digest, err := changePlanDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			id := "tx-stage"
			dir := filepath.Join(root, "transactions")
			j := validTestJournal(t, dir, "template", []string{op.OperationID})
			data := j.Data()
			data.TransactionID = id
			data.AcceptedPlan.PlanDigest = digest
			if _, err := transaction.Create(filepath.Join(dir, id+".json"), data); err != nil {
				t.Fatal(err)
			}
			if err := persistApprovedPlan(root, id, digest, plan); err != nil {
				t.Fatal(err)
			}
			payload, err := stageApprovedArchives(root, id, cache)
			if test != "success" {
				if err == nil || len(payload.ArtifactReferences) != 0 {
					t.Fatalf("published rejected stage: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(payload.ArtifactReferences) != 2 || payload.PlanDigest != digest || len(payload.OperationIDs) != 1 || payload.OperationIDs[0] != op.OperationID {
				t.Fatal("unbound preparation")
			}
			for _, ref := range payload.ArtifactReferences {
				if err := os.WriteFile(filepath.Join(cache, ref.SHA256), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(cache, ref.SHA256+".sig")); err != nil {
					t.Fatal(err)
				}
				sig, err := os.ReadFile(ref.CanonicalPath + ".sig")
				if err != nil || string(sig) != "signature:"+ref.ArtifactID {
					t.Fatal("private signature missing")
				}
				b, err := os.ReadFile(ref.CanonicalPath)
				if err != nil || string(b) != ref.ArtifactID {
					t.Fatal("stage aliases cache")
				}
			}
			if _, err := stageApprovedArchives(root, id, cache); err == nil {
				t.Fatal("overwrote existing stage")
			}
		})
	}
}
