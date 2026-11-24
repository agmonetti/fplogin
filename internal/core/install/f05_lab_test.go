//go:build f05lab

package install

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fplogin/internal/core/discovery"
	"fplogin/internal/core/transaction"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	a "fplogin/internal/protocol/adapter/v1"
	m "fplogin/internal/protocol/manifest/v1"
	p "fplogin/internal/protocol/platform/v1"
)

type labPlatform struct {
	*fakePlatformInvoker
	client   platformclient.Client
	provider discovery.Provider
	host     protocol.HostContext
	failOpID string
}

func (l labPlatform) PrepareArtifactInstall(ctx context.Context, _ discovery.Provider, payload p.PrepareArtifactInstallPayload, h protocol.HostContext) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	id, err := protocol.NewRequestID()
	if err != nil {
		return err
	}
	r, err := l.client.Invoke(ctx, l.provider, p.Request{
		ProtocolVersion: l.provider.ProtocolVersion,
		RequestID:       id,
		Operation:       "PrepareArtifactInstall",
		CoreVersion:     "0.2.0",
		Context:         h,
		Payload:         raw,
	})
	if err != nil {
		return err
	}
	if !r.OK {
		return errors.New(r.Error.Message)
	}
	return nil
}

func (l labPlatform) ApplyPreparedOperation(ctx context.Context, req PlatformOperationRequest) (m.OperationReceipt, error) {
	if l.failOpID != "" && req.Operation.OperationID == l.failOpID {
		return m.OperationReceipt{}, fmt.Errorf("injected service failure on %s", req.Operation.OperationID)
	}
	payload := p.ApplyOperationPayload{
		Operation:  req.Operation,
		PlanDigest: req.PlanDigest,
	}
	if req.Operation.Kind == protocol.InstallPackageArtifact {
		var params protocol.PackageArtifactParameters
		if err := json.Unmarshal(req.Operation.Parameters, &params); err != nil {
			return m.OperationReceipt{}, err
		}
		refBytes, err := json.Marshal(map[string]string{
			"canonical_path": filepath.Join(req.StageDir, params.SHA256),
			"sha256":         params.SHA256,
		})
		if err != nil {
			return m.OperationReceipt{}, err
		}
		payload.PreparedArtifactReference = refBytes
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return m.OperationReceipt{}, err
	}
	id, err := protocol.NewRequestID()
	if err != nil {
		return m.OperationReceipt{}, err
	}
	r, err := l.client.Invoke(ctx, l.provider, p.Request{
		ProtocolVersion: l.provider.ProtocolVersion,
		RequestID:       id,
		Operation:       "ApplyOperation",
		CoreVersion:     "0.2.0",
		Context:         l.host,
		Payload:         raw,
	})
	if err != nil {
		return m.OperationReceipt{}, err
	}
	if !r.OK {
		return m.OperationReceipt{}, errors.New(r.Error.Message)
	}
	var pr p.OperationReceipt
	if err := json.Unmarshal(r.Result, &pr); err != nil {
		return m.OperationReceipt{}, err
	}
	return m.OperationReceipt{
		OperationID:  pr.OperationID,
		Kind:         pr.Kind,
		StartedAt:    pr.StartedAt,
		CompletedAt:  pr.CompletedAt,
		Status:       pr.Status,
		BeforeState:  pr.BeforeState,
		AfterState:   pr.AfterState,
		Compensation: pr.Compensation,
		Error:        pr.Error,
	}, nil
}

func buildLabFixture(t *testing.T) (Config, *fakeAdapterInvoker, labPlatform) {
	t.Helper()
	elevated := os.Geteuid() == 0
	dir := t.TempDir()
	cfg, ad, pv := setupTestFixtures(dir)
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        2 * time.Minute,
		MaxInputBytes:  1 << 20,
		MaxStdoutBytes: 1 << 20,
		MaxStderrBytes: 65536,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := platformclient.New(platformclient.Config{
		Runner:             runner,
		DescriptorMaxBytes: 65536,
		ProtocolMajor:      1,
		CoreVersion:        "0.2.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("/request.json")
	if err != nil {
		t.Fatal(err)
	}
	var req p.Request
	if err = json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	cfg.Host = req.Context
	cfg.Host.Deadline = time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339)
	cfg.IsolatedArchiveCache = "/cache"

	var provider discovery.Provider
	themePath := cfg.IsolatedFiles[0]
	if elevated {
		provider, err = client.LoadDescriptor("/usr/lib/fplogin/platforms/platform.json")
		if err != nil {
			t.Fatalf("load packaged provider: %v", err)
		}
		cfg.JournalDir = filepath.Join(systemStateRoot, "transactions")
		cfg.ManifestPath = filepath.Join(systemStateRoot, "manifest.json")
		cfg.IsolatedFiles = nil
		cfg.AdapterDirs = nil
		cfg.ProviderDirs = nil
		cfg.Host.Elevated = true
		cfg.Host.InvokingUID = 0
		cfg.Host.InvokingGID = 0
		themePath = systemThemeFile
	} else {
		provider = discovery.Provider{
			ExecutablePath:  "/usr/lib/fplogin/platforms/bin/fplogin-platform-arch",
			ProtocolVersion: protocol.Version{Major: 1, Minor: 0},
		}
	}

	lp := labPlatform{fakePlatformInvoker: pv, client: client, provider: provider, host: cfg.Host}
	cfg.PlatformInvoker = lp

	files, err := filepath.Glob("/cache/*.sig")
	if err != nil || len(files) != 7 {
		t.Fatalf("fixture: %v (%d)", err, len(files))
	}
	byName := map[string]a.ArtifactReference{}
	for _, sig := range files {
		digest := strings.TrimSuffix(filepath.Base(sig), ".sig")
		st, err := os.Stat(filepath.Join("/cache", digest))
		if err != nil {
			t.Fatal(err)
		}
		nameBytes, err := os.ReadFile(filepath.Join("/cache", digest+".name"))
		if err != nil {
			t.Fatal(err)
		}
		id := string(nameBytes)
		byName[id] = a.ArtifactReference{
			ArtifactID: id, Role: "package", SHA256: digest, Size: st.Size(),
			CanonicalPath: "/ignored", MediaType: "application/octet-stream",
		}
	}

	const stock = "927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a"
	installOrder := []string{"qt5-translations", "qt5-base", "qt5-declarative", "qt5-quickcontrols2", "qt5-svg", "sddm-fplogin"}
	plan := &ad.plan
	plan.ArtifactReferences = nil
	plan.Operations = nil
	for _, name := range append(append([]string(nil), installOrder...), "sddm") {
		ref, ok := byName[name]
		if !ok {
			t.Fatalf("missing archive %q", name)
		}
		plan.ArtifactReferences = append(plan.ArtifactReferences, ref)
	}
	for _, name := range installOrder {
		ref := byName[name]
		op := protocol.Operation{
			OperationID:    "pkg-" + name,
			Kind:           protocol.InstallPackageArtifact,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"installed": json.RawMessage(`false`)},
			ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`true`)},
			Parameters:     json.RawMessage(fmt.Sprintf(`{"package_reference":%q,"artifact_id":%q,"sha256":%q}`, name, name, ref.SHA256)),
			Compensation:   json.RawMessage(fmt.Sprintf(`{"kind":"remove_package","package_reference":%q}`, name)),
		}
		if name == "sddm-fplogin" {
			op.ExpectedAfter["version"] = json.RawMessage(`"0.21.0-3.1"`)
			op.Compensation = json.RawMessage(fmt.Sprintf(`{"kind":"install_package","package_reference":"sddm","artifact_id":"sddm","sha256":%q}`, stock))
		}
		plan.Operations = append(plan.Operations, op)
	}
	themeContent := []byte(systemThemeData)
	fileOp := protocol.Operation{
		OperationID:    "write-theme",
		Kind:           protocol.WriteFileAtomic,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{},
		ExpectedAfter:  protocol.Object{},
		Parameters: json.RawMessage(fmt.Sprintf(
			`{"destination_path":%q,"content_base64":%q,"sha256":%q,"mode":"0644","owner":"root","group":"root"}`,
			themePath, base64.StdEncoding.EncodeToString(themeContent), sha256Hex(themeContent),
		)),
		Compensation: json.RawMessage(fmt.Sprintf(`{"kind":"remove_file","path":%q}`, themePath)),
	}
	svcOp := protocol.Operation{
		OperationID:    "enable-sddm",
		Kind:           protocol.SetServiceEnabled,
		Dependencies:   []string{},
		Preconditions:  []json.RawMessage{},
		ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`false`)},
		ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`true`)},
		Parameters:     json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`),
		Compensation:   json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":false}`),
	}
	plan.Operations = append(plan.Operations, fileOp, svcOp)
	return cfg, ad, lp
}

func assertSDDMDisabled(t *testing.T) {
	t.Helper()
	out, _ := exec.Command("/usr/bin/systemctl", "is-enabled", "sddm.service").CombinedOutput()
	if strings.TrimSpace(string(out)) != "disabled" {
		t.Fatalf("expected sddm.service disabled, got %q", strings.TrimSpace(string(out)))
	}
}

func TestF05LabInstallerTransaction(t *testing.T) {
	mode := os.Getenv("F05_CASE")
	if mode == "" {
		t.Skip("F05_CASE not set")
	}
	cfg, ad, lp := buildLabFixture(t)
	ctx := context.Background()

	switch mode {
	case "prepare-refuse":
		_, err := Run(ctx, cfg)
		want := os.Getenv("EXPECTED_ERROR")
		if err == nil || want == "" || !strings.Contains(err.Error(), want) {
			t.Fatalf("unexpected preparation outcome: %v (want %q)", err, want)
		}
		target := systemThemeFile
		if len(cfg.IsolatedFiles) > 0 {
			target = cfg.IsolatedFiles[0]
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("theme file mutated despite preparation refusal")
		}
		if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
			t.Fatalf("unresolved journal after preparation refusal: %v", err)
		}

	case "pkg-fail":
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted, got %v", err)
		}
		assertSDDMDisabled(t)
		if _, err := os.Stat(systemThemeFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("theme file exists after package failure")
		}
		if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
			t.Fatalf("unresolved journal after package rollback: %v", err)
		}

	case "verify-fail":
		ad.beforeVerify = func() {
			assertSDDMDisabled(t)
			data, err := os.ReadFile(systemThemeFile)
			if err != nil || string(data) != systemThemeData {
				t.Fatalf("theme file not written before verify: %q %v", data, err)
			}
		}
		ad.verifyReport.Checks[0].Status = "failed"
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("expected ErrVerificationFailed, got %v", err)
		}
		assertSDDMDisabled(t)
		if _, err := os.Stat(systemThemeFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("theme file not removed on verification rollback")
		}
		if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
			t.Fatalf("unresolved journal after verification rollback: %v", err)
		}

	case "svc-fail":
		// Append a follow-up service op after real enable-sddm succeeds, then fail it
		// to prove real rollback of systemctl disable + theme file + stock sddm + qt5-*.
		followOp := protocol.Operation{
			OperationID:    "confirm-sddm",
			Kind:           protocol.SetServiceEnabled,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`true`)},
			ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`true`)},
			Parameters:     json.RawMessage(`{"service_reference":"sddm.service","enabled":true}`),
			Compensation:   json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":true}`),
		}
		ad.plan.Operations = append(ad.plan.Operations, followOp)
		lp.failOpID = "confirm-sddm"
		cfg.PlatformInvoker = lp
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted, got %v", err)
		}
		assertSDDMDisabled(t)
		if _, err := os.Stat(systemThemeFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("theme file not removed after service failure")
		}
		if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
			t.Fatalf("unresolved journal after service rollback: %v", err)
		}

	case "success":
		ad.beforeVerify = func() {
			assertSDDMDisabled(t)
			data, err := os.ReadFile(systemThemeFile)
			if err != nil || string(data) != systemThemeData {
				t.Fatalf("theme file not written before verify: %q %v", data, err)
			}
		}
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("Run failed: %v", err)
		}
		if len(res.AppliedReceipts) != 8 {
			t.Fatalf("expected 8 applied receipts, got %d", len(res.AppliedReceipts))
		}
		j, err := transaction.Open(res.JournalPath)
		if err != nil || j.State() != "completed" {
			t.Fatalf("unexpected final journal: %v %+v", err, j)
		}
		data, mode, err := readOrdinaryFile(systemThemeFile)
		if err != nil || string(data) != systemThemeData || mode != 0o644 {
			t.Fatalf("unexpected theme file: %q %o %v", data, mode, err)
		}
		out, err := exec.Command("/usr/bin/systemctl", "is-enabled", "sddm.service").Output()
		if err != nil || strings.TrimSpace(string(out)) != "enabled" {
			t.Fatalf("expected sddm.service enabled, got %q (%v)", string(out), err)
		}

	case "sigkill-child":
		ad.beforeVerify = func() {
			fmt.Println("F05_READY")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
		_, err := Run(ctx, cfg)
		t.Fatalf("expected SIGKILL before verify completed, got %v", err)

	case "sigkill-recover":
		if _, err := os.Stat(systemThemeFile); err != nil {
			t.Fatalf("expected theme file present after SIGKILL: %v", err)
		}
		// Second Run must be refused until recovery finishes.
		if _, err := Run(ctx, cfg); !errors.Is(err, transaction.ErrUnresolvedTransaction) {
			t.Fatalf("expected unresolved transaction refusal, got %v", err)
		}
		entries, err := os.ReadDir(cfg.JournalDir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("expected one interrupted journal, got %v %v", entries, err)
		}
		txID := strings.TrimSuffix(entries[0].Name(), ".json")
		if err := RecoverTransaction(ctx, systemStateRoot, txID, nil, lp); err != nil {
			t.Fatalf("RecoverTransaction failed: %v", err)
		}
		assertSDDMDisabled(t)
		if _, err := os.Stat(systemThemeFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("theme file not removed during crash recovery")
		}
		if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
			t.Fatalf("journal still unresolved after recovery: %v", err)
		}

	default:
		t.Fatalf("unknown F05_CASE %q", mode)
	}
}
