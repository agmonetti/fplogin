// Package platformclient discovers trusted platform descriptors and invokes
// provider protocol processes without loading provider code into the core.
package platformclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"fplogin/internal/descriptortrust"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

var (
	ErrProtocolMismatch       = errors.New("platform protocol major mismatch")
	ErrMalformedOutput        = errors.New("platform provider emitted malformed stdout")
	ErrIdentityMismatch       = errors.New("platform runtime identity does not match descriptor")
	ErrDuplicateID            = errors.New("duplicate platform ID")
	ErrCapabilityInsufficient = errors.New("platform capabilities are insufficient")
)

type Config struct {
	Runner             processrunner.Runner
	TrustPolicy        descriptortrust.Policy
	DescriptorMaxBytes int64
	ProtocolMajor      int
	CoreVersion        string
}
type Client struct{ config Config }
type Discovered struct {
	Descriptor       platformv1.Descriptor
	DescriptorPath   string
	ExecutablePath   string
	AssetRootPath    string
	DescriptorSHA256 string
	ProtocolVersion  protocol.Version
}

func New(config Config) (Client, error) {
	if config.DescriptorMaxBytes <= 0 || config.ProtocolMajor < 1 || config.CoreVersion == "" {
		return Client{}, errors.New("platform client limits, protocol major, and core version are required")
	}
	return Client{config: config}, nil
}

func (c Client) LoadDescriptor(path string) (Discovered, error) {
	policy := c.config.TrustPolicy
	if descriptortrust.Elevated() {
		if err := descriptortrust.CheckPackagedDescriptor("platforms", path); err != nil {
			return Discovered{}, err
		}
		policy = descriptortrust.Policy{}
	}
	trusted, err := descriptortrust.Read(policy, path, c.config.DescriptorMaxBytes)
	if err != nil {
		return Discovered{}, err
	}
	descriptor, err := platformv1.DecodeDescriptor(trusted.DescriptorData)
	if err != nil {
		return Discovered{}, fmt.Errorf("decode descriptor %q: %w", path, err)
	}
	trusted, err = descriptortrust.ValidateReferences(policy, trusted, descriptor.Executable, descriptor.AssetRoot)
	if err != nil {
		return Discovered{}, err
	}
	version, err := selectVersion(descriptor.ProtocolVersions, c.config.ProtocolMajor)
	if err != nil {
		return Discovered{}, err
	}
	return Discovered{descriptor, trusted.DescriptorPath, trusted.ExecutablePath, trusted.AssetRootPath, trusted.SHA256, version}, nil
}

func (c Client) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]Discovered, error) {
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	seen := make(map[string]string, len(ordered))
	loaded := make([]Discovered, 0, len(ordered))
	for _, path := range ordered {
		discovered, err := c.LoadDescriptor(path)
		if err != nil {
			return nil, err
		}
		if previous, exists := seen[discovered.Descriptor.PlatformID]; exists {
			return nil, fmt.Errorf("%w %q in %q and %q", ErrDuplicateID, discovered.Descriptor.PlatformID, previous, path)
		}
		seen[discovered.Descriptor.PlatformID] = path
		loaded = append(loaded, discovered)
	}
	for _, discovered := range loaded {
		if err := c.handshake(ctx, discovered, host); err != nil {
			return nil, fmt.Errorf("platform %q: %w", discovered.Descriptor.PlatformID, err)
		}
	}
	return loaded, nil
}

func (c Client) Invoke(ctx context.Context, provider Discovered, request platformv1.Request) (platformv1.Response, error) {
	if descriptortrust.Elevated() {
		current, err := c.LoadDescriptor(provider.DescriptorPath)
		if err != nil {
			return platformv1.Response{}, err
		}
		if current.DescriptorSHA256 != provider.DescriptorSHA256 || current.ExecutablePath != provider.ExecutablePath {
			return platformv1.Response{}, ErrIdentityMismatch
		}
	}
	if err := request.Validate(); err != nil {
		return platformv1.Response{}, fmt.Errorf("invalid platform request: %w", err)
	}
	if request.Operation == "PrepareArtifactInstall" {
		var payload platformv1.PrepareArtifactInstallPayload
		if err := json.Unmarshal(request.Payload, &payload); err != nil {
			return platformv1.Response{}, err
		}
		if err := ValidateArtifactFiles(payload); err != nil {
			return platformv1.Response{}, err
		}
	}
	if request.ProtocolVersion.Major != provider.ProtocolVersion.Major {
		return platformv1.Response{}, ErrProtocolMismatch
	}
	input, err := json.Marshal(request)
	if err != nil {
		return platformv1.Response{}, err
	}
	deadline, _ := time.Parse(time.RFC3339, request.Context.Deadline)
	invocationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	processResult, err := c.config.Runner.Run(invocationContext, provider.ExecutablePath, input)
	if err != nil {
		if processResult.ExitCode == 65 {
			return platformv1.Response{}, ErrProtocolMismatch
		}
		return platformv1.Response{}, err
	}
	response, err := platformv1.DecodeResponse(processResult.Stdout)
	if err != nil {
		return platformv1.Response{}, fmt.Errorf("%w: %v", ErrMalformedOutput, err)
	}
	if response.RequestID != request.RequestID {
		return platformv1.Response{}, fmt.Errorf("%w: request ID differs", ErrIdentityMismatch)
	}
	if response.ProtocolVersion.Major != request.ProtocolVersion.Major {
		return platformv1.Response{}, ErrProtocolMismatch
	}
	if response.ProtocolVersion.Minor > request.ProtocolVersion.Minor {
		return platformv1.Response{}, fmt.Errorf("provider selected unsupported protocol minor %d", response.ProtocolVersion.Minor)
	}
	return response, nil
}

func (c Client) handshake(ctx context.Context, provider Discovered, host protocol.HostContext) error {
	requestID, err := protocol.NewRequestID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(platformv1.DescribePayload{SupportedProtocolRange: &platformv1.ProtocolRange{MinMajor: c.config.ProtocolMajor, MaxMajor: c.config.ProtocolMajor}})
	if err != nil {
		return err
	}
	response, err := c.Invoke(ctx, provider, platformv1.Request{ProtocolVersion: provider.ProtocolVersion, RequestID: requestID, Operation: "Describe", CoreVersion: c.config.CoreVersion, Context: host, Payload: payload})
	if err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("Describe failed: %s", response.Error.Message)
	}
	runtimeDescriptor, err := platformv1.DecodeDescriptor(response.Result)
	if err != nil {
		return fmt.Errorf("runtime descriptor: %w", err)
	}
	static := provider.Descriptor
	if runtimeDescriptor.PlatformID != static.PlatformID || runtimeDescriptor.PlatformVersion != static.PlatformVersion || runtimeDescriptor.Executable != static.Executable || !sameVersions(runtimeDescriptor.ProtocolVersions, static.ProtocolVersions) {
		return ErrIdentityMismatch
	}
	return nil
}

func SelectByCapabilities(providers []Discovered, required []string) (Discovered, error) {
	eligible := make([]Discovered, 0, len(providers))
	for _, provider := range providers {
		offered := make(map[string]bool, len(provider.Descriptor.Capabilities))
		for _, capability := range provider.Descriptor.Capabilities {
			offered[capability.ID] = capability.Status != "unsupported"
		}
		matches := true
		for _, capability := range required {
			if !offered[capability] {
				matches = false
				break
			}
		}
		if matches {
			eligible = append(eligible, provider)
		}
	}
	if len(eligible) != 1 {
		return Discovered{}, fmt.Errorf("%w: found %d eligible providers", ErrCapabilityInsufficient, len(eligible))
	}
	return eligible[0], nil
}
func ValidateArtifactFiles(payload platformv1.PrepareArtifactInstallPayload) error {
	for _, artifact := range payload.ArtifactReferences {
		if artifact.CanonicalPath == "" {
			return fmt.Errorf("artifact %q has no canonical path", artifact.ArtifactID)
		}
		info, err := os.Lstat(artifact.CanonicalPath)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.ArtifactID, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("artifact %q is not a regular non-symlink file", artifact.ArtifactID)
		}
		resolved, err := filepath.EvalSymlinks(artifact.CanonicalPath)
		if err != nil || filepath.Clean(resolved) != artifact.CanonicalPath {
			return fmt.Errorf("artifact %q path is not canonical", artifact.ArtifactID)
		}
		if info.Size() != artifact.Size {
			return fmt.Errorf("artifact %q size mismatch", artifact.ArtifactID)
		}
		file, err := os.Open(artifact.CanonicalPath)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.ArtifactID, err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("artifact %q: %w", artifact.ArtifactID, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("artifact %q: %w", artifact.ArtifactID, closeErr)
		}
		if fmt.Sprintf("%x", hash.Sum(nil)) != artifact.SHA256 {
			return fmt.Errorf("artifact %q digest mismatch", artifact.ArtifactID)
		}
	}
	return nil
}

func selectVersion(versions []protocol.Version, major int) (protocol.Version, error) {
	selected := protocol.Version{}
	for _, version := range versions {
		if version.Major == major && (selected.Major == 0 || version.Minor > selected.Minor) {
			selected = version
		}
	}
	if selected.Major == 0 {
		return protocol.Version{}, ErrProtocolMismatch
	}
	return selected, nil
}
func sameVersions(left, right []protocol.Version) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[protocol.Version]int, len(left))
	for _, version := range left {
		counts[version]++
	}
	for _, version := range right {
		counts[version]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
