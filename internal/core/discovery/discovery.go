// Package discovery scans root-owned descriptor directories, validates trust,
// and performs Describe handshakes with every eligible adapter and platform
// provider. It never makes control-flow decisions based on display-manager
// names or distribution names; those belong to adapters and providers
// respectively.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"fplogin/internal/adapterclient"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/platformclient"
	"fplogin/internal/protocol"
)

// Adapter is a fully validated, handshaked adapter ready for use.
type Adapter = adapterclient.Discovered

// Provider is a fully validated, handshaked platform provider ready for use.
type Provider = platformclient.Discovered

// Result holds everything the installer needs from a successful discovery run.
type Result struct {
	// Adapters contains every adapter that passed trust validation and the
	// Describe handshake, in deterministic lexicographic path order. The
	// installer selects among them using the selection package; discovery
	// never picks a winner.
	Adapters []Adapter

	// Provider is the single eligible platform provider. Selection among
	// providers uses generic capability matching only; no provider ID or
	// distribution name is compared by the core.
	Provider Provider
}

// AdapterDiscoverer discovers and handshakes adapters from paths.
type AdapterDiscoverer interface {
	Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]adapterclient.Discovered, error)
}

// ProviderDiscoverer discovers and handshakes platform providers from paths.
type ProviderDiscoverer interface {
	Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]platformclient.Discovered, error)
}

// Config contains the discoverers and runtime context needed for a discovery run.
type Config struct {
	AdapterDiscoverer  AdapterDiscoverer
	ProviderDiscoverer ProviderDiscoverer

	// AdapterDirs is the ordered list of directory paths that contain adapter
	// descriptor files. Each directory is globbed for "*.json" files. The
	// union of all matching paths is then sorted lexicographically and
	// deduplicated before loading. Non-existent directories are silently
	// skipped; permission errors are returned.
	AdapterDirs []string

	// ProviderDirs is the ordered list of directory paths that contain
	// platform-provider descriptor files. Same semantics as AdapterDirs.
	ProviderDirs []string

	// RequiredProviderCapabilities is the set of generic capability IDs that
	// the selected provider must declare. If empty, the first (and only)
	// successfully handshaked provider is selected.
	RequiredProviderCapabilities []string

	// Host is the context sent to every adapter/provider Describe call.
	Host protocol.HostContext
}

var (
	// ErrNoAdapters is returned when discovery finds no valid, handshaked
	// adapters in the configured directories.
	ErrNoAdapters = errors.New("no valid adapters discovered")

	// ErrNoProvider is returned when no provider satisfies the required
	// capabilities or when zero providers were found.
	ErrNoProvider = errors.New("no eligible platform provider discovered")

	// ErrMultipleProviders is returned when more than one provider satisfies
	// the required capabilities. The core never implicitly picks among them.
	ErrMultipleProviders = errors.New("multiple platform providers satisfy required capabilities; selection is ambiguous")
)

// Run performs a full discovery cycle: scan directories, load and trust-check
// descriptors, run Describe handshakes, and select the provider. It returns a
// Result on success or a wrapped error describing exactly what failed and why.
//
// Run is read-only and makes no changes to the host system.
func Run(ctx context.Context, cfg Config) (Result, error) {
	elevated := cfg.Host.Elevated || descriptortrust.Elevated()
	if elevated {
		if len(cfg.AdapterDirs) != 0 || len(cfg.ProviderDirs) != 0 {
			return Result{}, errors.New("custom component directories are not allowed during elevated discovery")
		}
		cfg.AdapterDirs = descriptortrust.PackagedDirs("adapters")
		cfg.ProviderDirs = descriptortrust.PackagedDirs("platforms")
		for _, dir := range append(cfg.AdapterDirs, cfg.ProviderDirs...) {
			if err := descriptortrust.ValidatePackagedDir(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
				return Result{}, err
			}
		}
	}
	adapterPaths, err := collectDescriptorPaths(cfg.AdapterDirs)
	if err != nil {
		return Result{}, fmt.Errorf("collect adapter descriptors: %w", err)
	}

	providerPaths, err := collectDescriptorPaths(cfg.ProviderDirs)
	if err != nil {
		return Result{}, fmt.Errorf("collect provider descriptors: %w", err)
	}

	adapters, adapterErr := cfg.AdapterDiscoverer.Discover(ctx, adapterPaths, cfg.Host)
	if adapterErr != nil {
		return Result{}, fmt.Errorf("adapter discovery: %w", adapterErr)
	}
	if len(adapters) == 0 {
		return Result{}, ErrNoAdapters
	}

	providers, providerErr := cfg.ProviderDiscoverer.Discover(ctx, providerPaths, cfg.Host)
	if providerErr != nil {
		return Result{}, fmt.Errorf("provider discovery: %w", providerErr)
	}

	provider, err := selectProvider(providers, cfg.RequiredProviderCapabilities)
	if err != nil {
		return Result{}, err
	}

	return Result{Adapters: adapters, Provider: provider}, nil
}

// collectDescriptorPaths returns the sorted, deduplicated set of "*.json"
// paths found under the given directories. Non-existent directories are
// skipped. The resulting order is deterministic: all paths across all
// directories are pooled and sorted lexicographically.
func collectDescriptorPaths(dirs []string) ([]string, error) {
	seen := make(map[string]struct{})
	var paths []string

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read descriptor directory %q: %w", dir, err)
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
		}
	}

	sort.Strings(paths)
	return paths, nil
}

// selectProvider applies generic capability matching to the discovered
// providers and returns exactly one eligible provider. Zero or multiple
// eligible providers are both errors; the core never chooses implicitly.
func selectProvider(providers []Provider, required []string) (Provider, error) {
	if len(providers) == 0 {
		return Provider{}, ErrNoProvider
	}

	eligible := make([]Provider, 0, len(providers))
	for _, p := range providers {
		if hasCapabilities(p, required) {
			eligible = append(eligible, p)
		}
	}

	switch len(eligible) {
	case 0:
		return Provider{}, fmt.Errorf("%w: %d provider(s) found but none offers %v",
			ErrNoProvider, len(providers), required)
	case 1:
		return eligible[0], nil
	default:
		ids := make([]string, len(eligible))
		for i, p := range eligible {
			ids[i] = p.Descriptor.PlatformID
		}
		return Provider{}, fmt.Errorf("%w: %v", ErrMultipleProviders, ids)
	}
}

// hasCapabilities reports whether the provider declares all required capability
// IDs with a status other than "unsupported".
func hasCapabilities(p Provider, required []string) bool {
	if len(required) == 0 {
		return true
	}
	offered := make(map[string]bool, len(p.Descriptor.Capabilities))
	for _, cap := range p.Descriptor.Capabilities {
		offered[cap.ID] = cap.Status != "unsupported"
	}
	for _, id := range required {
		if !offered[id] {
			return false
		}
	}
	return true
}
