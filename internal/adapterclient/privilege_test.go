package adapterclient_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

// Run only in the isolated fixture built by tests/integration/s4-adapter-privilege.sh.
func TestElevatedAdapterHandshake(t *testing.T) {
	if os.Getenv("FPL_ISOLATED_ADAPTER_TEST") != "1" {
		t.Skip("requires disposable Arch container fixture")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("test must start elevated")
	}
	runner, err := processrunner.New(processrunner.Config{
		Timeout: 5 * time.Second, MaxInputBytes: 1 << 20, MaxStdoutBytes: 1 << 20, MaxStderrBytes: 4096,
		Environment: []string{"FPL_UNSAFE_ENV=present"}, Arguments: []string{"unexpected-argument"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := adapterclient.Config{Runner: runner, DescriptorMaxBytes: 1 << 20, ProtocolMajor: 1, CoreVersion: "0.2.0"}
	client, err := adapterclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	paths := []string{"/usr/lib/fplogin/adapters/sddm.json"}
	host := protocol.HostContext{Root: "/", Platform: protocol.Object{}, Architecture: "x86_64", InvokingUID: 1000,
		InvokingGID: 1000, Elevated: true, Locale: "C", DryRun: true, Deadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	if os.Getenv("FPL_EXPECT_NO_IDENTITY") == "1" {
		if _, err := client.Discover(ctx, paths, host); !errors.Is(err, adapterclient.ErrElevatedAdapter) {
			t.Fatalf("missing or conflicting identity did not prevent handshake: %v", err)
		}
		return
	}
	found, err := client.Discover(ctx, paths, host)
	if err != nil || len(found) != 1 {
		t.Fatalf("credential-checked handshake: %d adapters, %v", len(found), err)
	}
	forged := found[0]
	forged.ExecutablePath = "/usr/bin/false"
	if _, err := client.Invoke(ctx, forged, adapterv1.Request{}); !errors.Is(err, adapterclient.ErrIdentityMismatch) {
		t.Fatalf("forged adapter executable not rejected: %v", err)
	}
}
