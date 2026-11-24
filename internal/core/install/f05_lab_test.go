//go:build f05lab

package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"fplogin/internal/core/discovery"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	a "fplogin/internal/protocol/adapter/v1"
	p "fplogin/internal/protocol/platform/v1"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type labPreparation struct {
	*refusalProvider
	client platformclient.Client
}

func (l labPreparation) PrepareArtifactInstall(ctx context.Context, provider discovery.Provider, payload p.PrepareArtifactInstallPayload, h protocol.HostContext) error {
	provider.ExecutablePath = "/provider"
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	id, err := protocol.NewRequestID()
	if err != nil {
		return err
	}
	r, err := l.client.Invoke(ctx, provider, p.Request{ProtocolVersion: provider.ProtocolVersion, RequestID: id, Operation: "PrepareArtifactInstall", CoreVersion: "0.2.0", Context: h, Payload: raw})
	if err != nil {
		return err
	}
	if !r.OK {
		return errors.New(r.Error.Message)
	}
	return nil
}

func TestF05LabInstallerPreparation(t *testing.T) {
	requireUnprivilegedLab(t)
	dir := t.TempDir()
	cfg, ad, pv := setupTestFixtures(dir)
	runner, err := processrunner.New(processrunner.Config{Timeout: time.Minute, MaxInputBytes: 1 << 20, MaxStdoutBytes: 1 << 20, MaxStderrBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	client, err := platformclient.New(platformclient.Config{Runner: runner, DescriptorMaxBytes: 65536, ProtocolMajor: 1, CoreVersion: "0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PlatformInvoker = labPreparation{&refusalProvider{fakePlatformInvoker: pv, t: t}, client}
	b, err := os.ReadFile("/request.json")
	if err != nil {
		t.Fatal(err)
	}
	var req p.Request
	if err = json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	cfg.Host = req.Context
	cfg.Host.Deadline = time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	cfg.IsolatedArchiveCache = "/cache"
	files, err := filepath.Glob("/cache/*.sig")
	if err != nil || len(files) != 7 {
		t.Fatalf("fixture: %v", err)
	}
	plan := &ad.plan
	file := plan.Operations[0]
	plan.Operations = nil
	const stock = "927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a"
	const candidate = "675904869fa349291eddd348e47fa376b5e07dace2e3f8d86d3bf60390e31be0"
	for _, sig := range files {
		digest := strings.TrimSuffix(filepath.Base(sig), ".sig")
		st, err := os.Stat(filepath.Join("/cache", digest))
		if err != nil {
			t.Fatal(err)
		}
		name, err := os.ReadFile(filepath.Join("/cache", digest+".name"))
		if err != nil {
			t.Fatal(err)
		}
		id := string(name)
		plan.ArtifactReferences = append(plan.ArtifactReferences, a.ArtifactReference{ArtifactID: id, Role: "package", SHA256: digest, Size: st.Size(), CanonicalPath: "/ignored", MediaType: "application/octet-stream"})
		if digest == stock {
			continue
		}
		op := file
		op.Kind = protocol.InstallPackageArtifact
		op.OperationID = id
		op.Parameters = json.RawMessage(fmt.Sprintf(`{"package_reference":%q,"artifact_id":%q,"sha256":%q}`, id, id, digest))
		op.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"remove_package","package_reference":%q}`, id))
		if digest == candidate {
			op.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"sddm","artifact_id":"sddm","sha256":%q}`, stock))
		}
		plan.Operations = append(plan.Operations, op)
	}
	plan.Operations = append(plan.Operations, file)
	svc := file
	svc.OperationID = "start"
	svc.Kind = protocol.SetServiceActive
	svc.Parameters = json.RawMessage(`{"service_reference":"sddm.service","active":true}`)
	svc.Compensation = json.RawMessage(`{"kind":"set_service_active","service_reference":"sddm.service","active":false}`)
	plan.Operations = append(plan.Operations, svc)
	_, err = Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), os.Getenv("EXPECTED_ERROR")) || os.Getenv("EXPECTED_ERROR") == "" {
		t.Fatalf("unexpected installer outcome: %v", err)
	}
	if _, err := os.Stat(cfg.IsolatedFiles[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file mutated")
	}
}
