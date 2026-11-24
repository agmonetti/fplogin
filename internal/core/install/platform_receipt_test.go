package install

import (
	"context"
	"encoding/json"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	"testing"
)

func TestPinnedPackageCompensation(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	comp := json.RawMessage(`{"kind":"install_package","package_reference":"sddm","artifact_id":"stock","sha256":"` + digest + `"}`)
	for _, kind := range []protocol.OperationKind{protocol.InstallPackageArtifact, protocol.RemoveOwnedPackage} {
		op := protocol.Operation{OperationID: "package", Kind: kind, Compensation: comp}
		r := manifestv1.OperationReceipt{OperationID: op.OperationID, Kind: kind, Status: "success", BeforeState: protocol.Object{"artifact_id": json.RawMessage(`"untrusted"`)}, AfterState: protocol.Object{}, Compensation: toObject(comp)}
		r.Compensation["artifact_id"] = json.RawMessage(`"substitute"`)
		if _, err := (&Executor{Platform: reportedReceipt{r}}).applyPlatform(context.Background(), op); err == nil {
			t.Fatal("accepted substituted package compensation")
		}
		r.Compensation = nil
		accepted, err := (&Executor{Platform: reportedReceipt{r}}).applyPlatform(context.Background(), op)
		if err != nil {
			t.Fatal(err)
		}
		undo, err := buildPlatformCompensationOperation(accepted)
		if err != nil {
			t.Fatal(err)
		}
		var got protocol.PackageArtifactParameters
		if err := json.Unmarshal(undo.Parameters, &got); err != nil || undo.Kind != protocol.InstallPackageArtifact || got.ArtifactID != "stock" || got.SHA256 != digest || got.PackageReference != "sddm" || undo.Validate() != nil {
			t.Fatalf("unexpected reinstall: %+v, %+v, %v", undo, got, err)
		}
	}
}

type reportedReceipt struct{ manifestv1.OperationReceipt }

func (r reportedReceipt) ApplyOperation(context.Context, protocol.Operation) (manifestv1.OperationReceipt, error) {
	return r.OperationReceipt, nil
}

func TestProviderCannotReplaceRollbackBaseline(t *testing.T) {
	op := protocol.Operation{OperationID: "enable", Kind: protocol.SetServiceEnabled, ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`false`)}, ExpectedAfter: protocol.Object{"enabled": json.RawMessage(`true`)}}
	for _, before := range []protocol.Object{{}, op.ExpectedAfter} {
		r := manifestv1.OperationReceipt{OperationID: op.OperationID, Kind: op.Kind, Status: "success", BeforeState: before, AfterState: op.ExpectedAfter}
		if _, err := (&Executor{Platform: reportedReceipt{r}}).applyPlatform(context.Background(), op); err == nil {
			t.Fatal("accepted a missing or changed rollback baseline")
		}
	}
}

func TestPlatformRollbackNeedsMatchingSuccessReceipt(t *testing.T) {
	op := protocol.Operation{OperationID: "enable-rollback", Kind: protocol.SetServiceEnabled, ExpectedAfter: protocol.Object{"enabled": json.RawMessage(`false`)}, Compensation: json.RawMessage(`{"kind":"set_service_enabled"}`)}
	for _, tc := range []struct {
		id, status, enabled string
		good                bool
	}{{op.OperationID, "success", "false", true}, {op.OperationID, "failed", "false", false}, {"other", "success", "false", false}, {op.OperationID, "success", "true", false}} {
		r := manifestv1.OperationReceipt{OperationID: tc.id, Kind: op.Kind, Status: tc.status, BeforeState: protocol.Object{}, AfterState: protocol.Object{"enabled": json.RawMessage(tc.enabled)}, Compensation: protocol.Object{"unapproved": json.RawMessage(`true`)}}
		got, err := (&Executor{Platform: reportedReceipt{r}}).applyPlatform(context.Background(), op)
		if (err == nil) != tc.good {
			t.Fatalf("case %+v: %v", tc, err)
		}
		if err == nil && string(got.Compensation["kind"]) != `"set_service_enabled"` {
			t.Fatal("accepted provider-authored compensation")
		}
	}
}
