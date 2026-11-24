package install

import (
	"context"
	"encoding/json"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	"testing"
)

type reportedReceipt struct{ manifestv1.OperationReceipt }

func (r reportedReceipt) ApplyOperation(context.Context, protocol.Operation) (manifestv1.OperationReceipt, error) {
	return r.OperationReceipt, nil
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
