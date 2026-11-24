package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"fplogin/internal/core/discovery"
	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	a "fplogin/internal/protocol/adapter/v1"
	m "fplogin/internal/protocol/manifest/v1"
	p "fplogin/internal/protocol/platform/v1"
	"os"
	"path/filepath"
	"testing"
)

type refusalProvider struct {
	*fakePlatformInvoker
	t        *testing.T
	refusal  error
	prepared bool
}

func (f *refusalProvider) PrepareArtifactInstall(_ context.Context, _ discovery.Provider, payload p.PrepareArtifactInstallPayload, _ protocol.HostContext) error {
	f.prepared = true
	if len(payload.ArtifactReferences) != 2 {
		f.t.Fatal("missing rollback archive")
	}
	for _, r := range payload.ArtifactReferences {
		b, err := os.ReadFile(r.CanonicalPath)
		if err != nil || string(b) != r.ArtifactID {
			f.t.Fatal("not staged")
		}
	}
	return f.refusal
}
func (f *refusalProvider) ApplyOperation(context.Context, protocol.Operation) (m.OperationReceipt, error) {
	f.t.Fatal("mutation before preparation and recovery support")
	panic("unreachable")
}
func TestRunPackagePreparationPrecedesMutation(t *testing.T) {
	requireUnprivilegedLab(t)
	for _, refuse := range []bool{true, false} {
		t.Run(fmt.Sprint(refuse), func(t *testing.T) {
			cfg, ad, pv := setupTestFixtures(t.TempDir())
			cfg.IsolatedArchiveCache = t.TempDir()
			f := &refusalProvider{fakePlatformInvoker: pv, t: t}
			cfg.PlatformInvoker = f
			want := ErrUnsupportedKind
			if refuse {
				f.refusal = errors.New("signature rejected")
				want = f.refusal
			}
			plan := &ad.plan
			file := plan.Operations[0]
			pkg := file
			pkg.OperationID = "package"
			pkg.Kind = protocol.InstallPackageArtifact
			for _, id := range []string{"candidate", "stock"} {
				hash := sha256Hex([]byte(id))
				plan.ArtifactReferences = append(plan.ArtifactReferences, a.ArtifactReference{ArtifactID: id, Size: int64(len(id)), SHA256: hash, MediaType: "application/octet-stream", Role: "package", CanonicalPath: "/ignored"})
				path := filepath.Join(cfg.IsolatedArchiveCache, hash)
				for _, suffix := range []string{"", ".sig"} {
					if err := os.WriteFile(path+suffix, []byte(id), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			pkg.Parameters = json.RawMessage(fmt.Sprintf(`{"package_reference":"candidate","artifact_id":"candidate","sha256":%q}`, plan.ArtifactReferences[0].SHA256))
			pkg.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"stock","artifact_id":"stock","sha256":%q}`, plan.ArtifactReferences[1].SHA256))
			svc := file
			svc.Kind = protocol.SetServiceActive
			svc.OperationID = "start"
			svc.Parameters = json.RawMessage(`{"service_reference":"sddm.service","active":true}`)
			svc.Compensation = json.RawMessage(`{"kind":"set_service_active","service_reference":"sddm.service","active":false}`)
			plan.Operations = []protocol.Operation{pkg, file, svc}
			_, err := Run(context.Background(), cfg)
			if !errors.Is(err, want) || !f.prepared {
				t.Fatalf("prepared %t: %v", f.prepared, err)
			}
			if _, err = os.Stat(cfg.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unexpected file change")
			}
			if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
				t.Fatal(err)
			}
		})
	}
}
