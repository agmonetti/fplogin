package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

// TestE2E_Subprocess_PlatformAndAdapter builds the real cmd binaries and executes
// the protocol handshake and operations over real OS stdin/stdout pipes.
func TestE2E_Subprocess_PlatformAndAdapter(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	platformBin := filepath.Join(binDir, "fplogin-platform-arch")
	adapterBin := filepath.Join(binDir, "fplogin-adapter-sddm")

	// Compile the two binaries into test temp directory
	cmdPlat := exec.Command("go", "build", "-o", platformBin, "fplogin/cmd/fplogin-platform-arch")
	if out, err := cmdPlat.CombinedOutput(); err != nil {
		t.Fatalf("compile platform binary: %v, output: %s", err, string(out))
	}

	cmdAdap := exec.Command("go", "build", "-o", adapterBin, "fplogin/cmd/fplogin-adapter-sddm")
	if out, err := cmdAdap.CombinedOutput(); err != nil {
		t.Fatalf("compile adapter binary: %v, output: %s", err, string(out))
	}

	// 1. Set up Platform Provider test tree
	platformDir := filepath.Join(tmpDir, "platform")
	_ = os.MkdirAll(filepath.Join(platformDir, "bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(platformDir, "assets"), 0o755)

	repoRoot, err := filepath.Abs("../../../")
	if err != nil {
		t.Fatal(err)
	}

	platTargetBin := filepath.Join(platformDir, "bin", "fplogin-platform-arch")
	copyFile(t, platformBin, platTargetBin, 0o755)

	// Copy real platform.json descriptor
	platDescPath := filepath.Join(platformDir, "platform.json")
	copyFile(t, filepath.Join(repoRoot, "platforms/arch/platform.json"), platDescPath, 0o600)

	// 2. Set up SDDM Adapter test tree
	adapterDir := filepath.Join(tmpDir, "adapter")
	_ = os.MkdirAll(filepath.Join(adapterDir, "bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(adapterDir, "assets"), 0o755)

	adapTargetBin := filepath.Join(adapterDir, "bin", "fplogin-adapter-sddm")
	copyFile(t, adapterBin, adapTargetBin, 0o755)

	// Copy real adapter.json descriptor
	adapDescPath := filepath.Join(adapterDir, "adapter.json")
	copyFile(t, filepath.Join(repoRoot, "adapters/sddm/adapter.json"), adapDescPath, 0o600)

	// 3. Test Platform Client Discovery and Invoke over real pipes
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        5 * time.Second,
		MaxInputBytes:  1 << 20,
		MaxStdoutBytes: 1 << 20,
		MaxStderrBytes: 4096,
		Environment:    os.Environ(),
	})
	if err != nil {
		t.Fatal(err)
	}

	trustPolicy := descriptortrust.Policy{OwnerUID: uint32(os.Getuid())}

	pClient, err := platformclient.New(platformclient.Config{
		Runner:             runner,
		TrustPolicy:        trustPolicy,
		DescriptorMaxBytes: 1 << 20,
		ProtocolMajor:      1,
		CoreVersion:        "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	hostCtx := protocol.HostContext{
		Root:         "/",
		Platform:     protocol.Object{"os": json.RawMessage(`"linux"`)},
		Architecture: runtime.GOARCH,
		InvokingUID:  uint32(os.Getuid()),
		InvokingGID:  uint32(os.Getgid()),
		Locale:       "C",
		Deadline:     time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
	}

	discoveredPlatforms, err := pClient.Discover(context.Background(), []string{platDescPath}, hostCtx)
	if err != nil {
		t.Fatalf("platformclient Discover failed: %v", err)
	}
	if len(discoveredPlatforms) != 1 {
		t.Fatalf("expected 1 discovered platform, got %d", len(discoveredPlatforms))
	}

	// Invoke InspectHost on real platform subprocess
	reqID, _ := protocol.NewRequestID()
	platResp, err := pClient.Invoke(context.Background(), discoveredPlatforms[0], platformv1.Request{
		ProtocolVersion: protocol.Version{Major: 1, Minor: 0},
		RequestID:       reqID,
		Operation:       "InspectHost",
		CoreVersion:     "0.1.0",
		Context:         hostCtx,
		Payload:         json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("platformclient Invoke InspectHost failed: %v", err)
	}
	if !platResp.OK {
		t.Fatalf("expected OK platform response, got error: %v", platResp.Error)
	}

	// 4. Test Adapter Client Discovery and Invoke over real pipes
	aClient, err := adapterclient.New(adapterclient.Config{
		Runner:             runner,
		TrustPolicy:        trustPolicy,
		DescriptorMaxBytes: 1 << 20,
		ProtocolMajor:      1,
		CoreVersion:        "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	discoveredAdapters, err := aClient.Discover(context.Background(), []string{adapDescPath}, hostCtx)
	if err != nil {
		t.Fatalf("adapterclient Discover failed: %v", err)
	}
	if len(discoveredAdapters) != 1 {
		t.Fatalf("expected 1 discovered adapter, got %d", len(discoveredAdapters))
	}

	// Invoke Detect on real adapter subprocess
	reqID2, _ := protocol.NewRequestID()
	adapResp, err := aClient.Invoke(context.Background(), discoveredAdapters[0], adapterv1.Request{
		ProtocolVersion: protocol.Version{Major: 1, Minor: 0},
		RequestID:       reqID2,
		Operation:       "Detect",
		CoreVersion:     "0.1.0",
		Context:         hostCtx,
		Payload:         json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("adapterclient Invoke Detect failed: %v", err)
	}
	// Without a supported host and inventory, Detect cannot propose a target.
	if adapResp.OK {
		t.Fatalf("Detect must fail closed without preflight facts, got OK result %s", string(adapResp.Result))
	}
	if adapResp.Error == nil || !strings.Contains(adapResp.Error.Message, "requires read-only Arch") {
		t.Fatalf("expected explicit host-context error, got %+v", adapResp.Error)
	}

	// No mutation may report success: ApplyOperation must refuse with a contract code.
	reqID3, _ := protocol.NewRequestID()
	applyResp, err := pClient.Invoke(context.Background(), discoveredPlatforms[0], platformv1.Request{
		ProtocolVersion: protocol.Version{Major: 1, Minor: 0},
		RequestID:       reqID3,
		Operation:       "ApplyOperation",
		CoreVersion:     "0.1.0",
		Context:         hostCtx,
		Payload: json.RawMessage(`{"operation":{"operation_id":"op-1","kind":"create_directory","dependencies":[],` +
			`"parameters":{"path":"/var/lib/fplogin-e2e-never-created","mode":"0755","owner":"root","group":"root"},"preconditions":[],"expected_before":{},` +
			`"expected_after":{},"compensation":{"kind":"remove_directory","path":"/var/lib/fplogin-e2e-never-created"}},` +
			`"plan_digest":"4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}`),
	})
	if err != nil {
		t.Fatalf("platformclient Invoke ApplyOperation failed: %v", err)
	}
	if applyResp.OK || applyResp.Error == nil || applyResp.Error.Code != "unsupported_operation" {
		t.Fatalf("ApplyOperation must refuse with unsupported_operation, got OK=%v err=%+v", applyResp.OK, applyResp.Error)
	}
}

func copyFile(t *testing.T, src, dst string, perm os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, perm); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
