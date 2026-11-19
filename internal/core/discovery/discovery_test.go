package discovery

// White-box tests: we are inside the package so we can call unexported helpers
// (collectDescriptorPaths, selectProvider, hasCapabilities) directly.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fplogin/internal/adapterclient"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/platformclient"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeFile writes content to path, creating parent directories.
func makeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// stubProvider builds a minimal platformclient.Discovered with the given ID
// and capabilities, all with status "native".
func stubProvider(id string, caps []string) platformclient.Discovered {
	capabilities := make([]protocol.Capability, 0, len(caps))
	for _, c := range caps {
		capabilities = append(capabilities, protocol.Capability{
			ID:                   c,
			Status:               "native",
			Level:                []byte(`"standard"`),
			Constraints:          protocol.Object{},
			EvidenceRequirements: []string{},
		})
	}
	return platformclient.Discovered{
		Descriptor: platformv1.Descriptor{
			PlatformID:   id,
			Capabilities: capabilities,
		},
	}
}

// stubProviderUnsupported builds a provider where capID has status "unsupported".
func stubProviderUnsupported(id, capID string) platformclient.Discovered {
	return platformclient.Discovered{
		Descriptor: platformv1.Descriptor{
			PlatformID: id,
			Capabilities: []protocol.Capability{
				{
					ID:                   capID,
					Status:               "unsupported",
					Level:                []byte(`"none"`),
					Constraints:          protocol.Object{},
					EvidenceRequirements: []string{},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// collectDescriptorPaths
// ---------------------------------------------------------------------------

func TestCollectDescriptorPaths_NonExistentDirSkipped(t *testing.T) {
	tmp := t.TempDir()
	nonExistent := filepath.Join(tmp, "does-not-exist")

	paths, err := collectDescriptorPaths([]string{nonExistent})
	if err != nil {
		t.Fatalf("unexpected error for non-existent dir: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths, got %v", paths)
	}
}

func TestCollectDescriptorPaths_LexicographicOrder(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "adapters")
	makeFile(t, filepath.Join(dir, "zzz.json"), `{}`)
	makeFile(t, filepath.Join(dir, "aaa.json"), `{}`)
	makeFile(t, filepath.Join(dir, "mmm.json"), `{}`)

	paths, err := collectDescriptorPaths([]string{dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(paths), paths)
	}
	for i := 1; i < len(paths); i++ {
		if paths[i] < paths[i-1] {
			t.Errorf("paths not sorted: [%d]=%q > [%d]=%q", i-1, paths[i-1], i, paths[i])
		}
	}
}

func TestCollectDescriptorPaths_CrossDirLexicographicOrder(t *testing.T) {
	// Paths from multiple directories must be sorted globally, not per-dir.
	tmp := t.TempDir()
	dir1 := filepath.Join(tmp, "dir1")
	dir2 := filepath.Join(tmp, "dir2")
	makeFile(t, filepath.Join(dir1, "zzz.json"), `{}`)
	makeFile(t, filepath.Join(dir2, "aaa.json"), `{}`)

	paths, err := collectDescriptorPaths([]string{dir1, dir2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	if paths[0] > paths[1] {
		t.Errorf("cross-dir sort failed: %q > %q", paths[0], paths[1])
	}
}

func TestCollectDescriptorPaths_Deduplication(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "adapters")
	makeFile(t, filepath.Join(dir, "a.json"), `{}`)

	// Same directory listed twice → path appears only once.
	paths, err := collectDescriptorPaths([]string{dir, dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 deduplicated path, got %d: %v", len(paths), paths)
	}
}

func TestCollectDescriptorPaths_IgnoresNonJSONFiles(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "adapters")
	makeFile(t, filepath.Join(dir, "good.json"), `{}`)
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths, err := collectDescriptorPaths([]string{dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path (only .json), got %d: %v", len(paths), paths)
	}
}

func TestCollectDescriptorPaths_EmptyDir(t *testing.T) {
	tmp := t.TempDir()
	paths, err := collectDescriptorPaths([]string{tmp})
	if err != nil {
		t.Fatalf("unexpected error for empty dir: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths, got %v", paths)
	}
}

// ---------------------------------------------------------------------------
// selectProvider
// ---------------------------------------------------------------------------

func TestSelectProvider_NoProviders(t *testing.T) {
	_, err := selectProvider(nil, nil)
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("expected ErrNoProvider with zero providers, got: %v", err)
	}
}

func TestSelectProvider_EmptyProviderSlice(t *testing.T) {
	_, err := selectProvider([]platformclient.Discovered{}, []string{"host_inspect"})
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("expected ErrNoProvider with empty slice, got: %v", err)
	}
}

func TestSelectProvider_ExactlyOneEligible(t *testing.T) {
	p := stubProvider("org.fplogin.platform.test", []string{"host_inspect"})
	got, err := selectProvider([]platformclient.Discovered{p}, []string{"host_inspect"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Descriptor.PlatformID != "org.fplogin.platform.test" {
		t.Errorf("unexpected provider: %q", got.Descriptor.PlatformID)
	}
}

func TestSelectProvider_MultipleEligible(t *testing.T) {
	p1 := stubProvider("org.fplogin.platform.a", []string{"host_inspect"})
	p2 := stubProvider("org.fplogin.platform.b", []string{"host_inspect"})
	_, err := selectProvider([]platformclient.Discovered{p1, p2}, []string{"host_inspect"})
	if !errors.Is(err, ErrMultipleProviders) {
		t.Errorf("expected ErrMultipleProviders, got: %v", err)
	}
}

func TestSelectProvider_InsufficientCapabilities(t *testing.T) {
	p := stubProvider("org.fplogin.platform.test", []string{"host_inspect"})
	_, err := selectProvider([]platformclient.Discovered{p}, []string{"host_inspect", "apply_operation"})
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("expected ErrNoProvider for missing capability, got: %v", err)
	}
}

func TestSelectProvider_UnsupportedCapabilityExcluded(t *testing.T) {
	// Status="unsupported" must not count toward required capabilities.
	p := stubProviderUnsupported("org.fplogin.platform.test", "host_inspect")
	_, err := selectProvider([]platformclient.Discovered{p}, []string{"host_inspect"})
	if !errors.Is(err, ErrNoProvider) {
		t.Errorf("expected ErrNoProvider when capability is unsupported, got: %v", err)
	}
}

func TestSelectProvider_EmptyRequiredCapabilities(t *testing.T) {
	// No required capabilities → any single provider is eligible.
	p := stubProvider("org.fplogin.platform.test", nil)
	got, err := selectProvider([]platformclient.Discovered{p}, nil)
	if err != nil {
		t.Fatalf("unexpected error with empty requirements: %v", err)
	}
	if got.Descriptor.PlatformID != "org.fplogin.platform.test" {
		t.Errorf("unexpected provider: %q", got.Descriptor.PlatformID)
	}
}

func TestSelectProvider_OneEligibleOneNot(t *testing.T) {
	// Only p1 has the required capability; p2 lacks it.
	p1 := stubProvider("org.fplogin.platform.a", []string{"host_inspect", "apply_operation"})
	p2 := stubProvider("org.fplogin.platform.b", []string{"host_inspect"})
	got, err := selectProvider([]platformclient.Discovered{p1, p2}, []string{"apply_operation"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Descriptor.PlatformID != "org.fplogin.platform.a" {
		t.Errorf("wrong provider selected: %q", got.Descriptor.PlatformID)
	}
}

// ---------------------------------------------------------------------------
// hasCapabilities
// ---------------------------------------------------------------------------

func TestHasCapabilities_AllPresent(t *testing.T) {
	p := stubProvider("test", []string{"a", "b", "c"})
	if !hasCapabilities(p, []string{"a", "b"}) {
		t.Error("expected true when all capabilities are present")
	}
}

func TestHasCapabilities_OneMissing(t *testing.T) {
	p := stubProvider("test", []string{"a"})
	if hasCapabilities(p, []string{"a", "b"}) {
		t.Error("expected false when a capability is missing")
	}
}

func TestHasCapabilities_EmptyRequired(t *testing.T) {
	p := stubProvider("test", nil)
	if !hasCapabilities(p, nil) {
		t.Error("expected true with empty required capabilities")
	}
}

func TestHasCapabilities_UnsupportedDoesNotCount(t *testing.T) {
	p := stubProviderUnsupported("test", "apply_operation")
	if hasCapabilities(p, []string{"apply_operation"}) {
		t.Error("expected false: unsupported capability must not count")
	}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

type fakeAdapterDiscoverer struct {
	result []adapterclient.Discovered
	err    error
}

func (f *fakeAdapterDiscoverer) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]adapterclient.Discovered, error) {
	return f.result, f.err
}

type fakeProviderDiscoverer struct {
	result []platformclient.Discovered
	err    error
}

func (f *fakeProviderDiscoverer) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]platformclient.Discovered, error) {
	return f.result, f.err
}

func TestRun_RejectsElevatedOverrides(t *testing.T) {
	for _, cfg := range []Config{
		{AdapterDirs: []string{"/usr/lib/fplogin/adapters"}},
		{ProviderDirs: []string{t.TempDir()}},
	} {
		cfg.Host.Elevated = true
		if _, err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "custom component directories") {
			t.Fatalf("expected override refusal before discovery, got %v", err)
		}
	}
}

func TestRun_ActualRootRejectsOverrides(t *testing.T) {
	if !descriptortrust.Elevated() {
		t.Skip("requires an isolated root namespace")
	}
	cfg := Config{AdapterDirs: []string{t.TempDir()}}
	if _, err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "custom component directories") {
		t.Fatalf("expected override refusal without an elevated protocol flag, got %v", err)
	}
}

func TestElevatedAdapterCannotInvoke(t *testing.T) {
	for _, elevated := range []bool{false, true} {
		if !elevated && !descriptortrust.Elevated() {
			continue
		}
		req := adapterv1.Request{Context: protocol.HostContext{InvokingUID: 65534, Elevated: elevated}}
		_, err := (adapterclient.Client{}).Invoke(context.Background(), adapterclient.Discovered{}, req)
		if !errors.Is(err, adapterclient.ErrElevatedAdapter) {
			t.Fatalf("expected refusal before launch (protocol elevated=%t), got %v", elevated, err)
		}
	}
}

func TestElevatedClientsRejectDevelopmentDescriptors(t *testing.T) {
	if !descriptortrust.Elevated() {
		t.Skip("requires an isolated root namespace")
	}
	path := filepath.Join(t.TempDir(), "dev.json")
	makeFile(t, path, `{}`)
	_, adapterErr := (adapterclient.Client{}).LoadDescriptor(path)
	_, providerErr := (platformclient.Client{}).LoadDescriptor(path)
	_, invokeErr := (platformclient.Client{}).Invoke(context.Background(), platformclient.Discovered{DescriptorPath: path}, platformv1.Request{})
	for _, err := range []error{adapterErr, providerErr, invokeErr} {
		if err == nil || !strings.Contains(err.Error(), "outside the fixed") {
			t.Fatalf("expected development descriptor refusal, got %v", err)
		}
	}
}

func TestRun_Success(t *testing.T) {
	if descriptortrust.Elevated() {
		t.Skip("development discovery requires an ordinary user")
	}
	ctx := context.Background()
	tmp := t.TempDir()
	adDir := filepath.Join(tmp, "adapters")
	prDir := filepath.Join(tmp, "providers")
	makeFile(t, filepath.Join(adDir, "sddm.json"), `{}`)
	makeFile(t, filepath.Join(prDir, "arch.json"), `{}`)

	ad := adapterclient.Discovered{
		Descriptor: adapterv1.Descriptor{AdapterID: "org.fplogin.adapter.sddm"},
	}
	pr := stubProvider("org.fplogin.platform.arch", []string{"apply_operation"})

	cfg := Config{
		AdapterDiscoverer:            &fakeAdapterDiscoverer{result: []adapterclient.Discovered{ad}},
		ProviderDiscoverer:           &fakeProviderDiscoverer{result: []platformclient.Discovered{pr}},
		AdapterDirs:                  []string{adDir},
		ProviderDirs:                 []string{prDir},
		RequiredProviderCapabilities: []string{"apply_operation"},
	}

	res, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Adapters) != 1 || res.Adapters[0].Descriptor.AdapterID != "org.fplogin.adapter.sddm" {
		t.Errorf("unexpected adapters: %v", res.Adapters)
	}
	if res.Provider.Descriptor.PlatformID != "org.fplogin.platform.arch" {
		t.Errorf("unexpected provider: %v", res.Provider)
	}
}

func TestRun_NoAdaptersDiscovered(t *testing.T) {
	ctx := context.Background()
	pr := stubProvider("org.fplogin.platform.arch", []string{"apply_operation"})

	cfg := Config{
		AdapterDiscoverer:  &fakeAdapterDiscoverer{result: []adapterclient.Discovered{}},
		ProviderDiscoverer: &fakeProviderDiscoverer{result: []platformclient.Discovered{pr}},
	}

	_, err := Run(ctx, cfg)
	if !errors.Is(err, ErrNoAdapters) {
		t.Fatalf("expected ErrNoAdapters, got %v", err)
	}
}

func TestRun_AdapterDiscoveryError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("boom adapter")

	cfg := Config{
		AdapterDiscoverer:  &fakeAdapterDiscoverer{err: wantErr},
		ProviderDiscoverer: &fakeProviderDiscoverer{},
	}

	_, err := Run(ctx, cfg)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v, got %v", wantErr, err)
	}
}

func TestRun_ProviderDiscoveryError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("boom provider")
	ad := adapterclient.Discovered{
		Descriptor: adapterv1.Descriptor{AdapterID: "org.fplogin.adapter.sddm"},
	}

	cfg := Config{
		AdapterDiscoverer:  &fakeAdapterDiscoverer{result: []adapterclient.Discovered{ad}},
		ProviderDiscoverer: &fakeProviderDiscoverer{err: wantErr},
	}

	_, err := Run(ctx, cfg)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v, got %v", wantErr, err)
	}
}
