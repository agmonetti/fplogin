package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
)

func listComponents() error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return fmt.Errorf("run as an ordinary user")
	}
	const maxBytes = 1 << 20
	runner, err := processrunner.New(processrunner.Config{
		Timeout: 5 * time.Second, MaxInputBytes: maxBytes, MaxStdoutBytes: maxBytes,
		MaxStderrBytes: 4096, Environment: []string{"LC_ALL=C"},
	})
	if err != nil {
		return err
	}
	providers, err := platformclient.New(platformclient.Config{
		Runner: runner, DescriptorMaxBytes: maxBytes, ProtocolMajor: 1, CoreVersion: version,
	})
	if err != nil {
		return err
	}
	adapters, err := adapterclient.New(adapterclient.Config{
		Runner: runner, DescriptorMaxBytes: maxBytes, ProtocolMajor: 1, CoreVersion: version,
	})
	if err != nil {
		return err
	}
	providerPaths, err := packagedDescriptors("/usr/lib/fplogin/platforms")
	if err != nil {
		return err
	}
	adapterPaths, err := packagedDescriptors("/usr/lib/fplogin/adapters")
	if err != nil {
		return err
	}
	if len(providerPaths)+len(adapterPaths) == 0 {
		return fmt.Errorf("no packaged components found")
	}
	ctx := context.Background()
	host := componentHost()
	packageProviders, err := providers.Discover(ctx, providerPaths, host)
	if err != nil {
		return err
	}
	packageAdapters, err := adapters.Discover(ctx, adapterPaths, host)
	if err != nil {
		return err
	}
	for _, p := range packageProviders {
		fmt.Printf("provider %s: %s (assets: %s)\n", p.Descriptor.PlatformID, p.ExecutablePath, p.AssetRootPath)
	}
	for _, a := range packageAdapters {
		fmt.Printf("adapter %s: %s (assets: %s)\n", a.Descriptor.AdapterID, a.ExecutablePath, a.AssetRootPath)
	}
	return nil
}

func componentHost() protocol.HostContext {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "aarch64"
	}
	return protocol.HostContext{
		Root: "/", Platform: protocol.Object{}, Architecture: arch,
		InvokingUID: uint32(os.Getuid()), InvokingGID: uint32(os.Getgid()), Locale: "C", DryRun: true,
		Deadline: time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339),
	}
}

func packagedDescriptors(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, nil
}
