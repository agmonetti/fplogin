// Package adapterclient discovers trusted adapter descriptors and invokes
// adapter protocol processes without loading adapter code into the core.
package adapterclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"fplogin/internal/descriptortrust"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

var (
	ErrProtocolMismatch = errors.New("adapter protocol major mismatch")
	ErrMalformedOutput  = errors.New("adapter emitted malformed stdout")
	ErrIdentityMismatch = errors.New("adapter runtime identity does not match descriptor")
	ErrDuplicateID      = errors.New("duplicate adapter ID")
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
	Descriptor       adapterv1.Descriptor
	DescriptorPath   string
	ExecutablePath   string
	AssetRootPath    string
	DescriptorSHA256 string
	ProtocolVersion  protocol.Version
}

func New(config Config) (Client, error) {
	if config.DescriptorMaxBytes <= 0 || config.ProtocolMajor < 1 || config.CoreVersion == "" {
		return Client{}, errors.New("adapter client limits, protocol major, and core version are required")
	}
	return Client{config: config}, nil
}

func (c Client) LoadDescriptor(path string) (Discovered, error) {
	trusted, err := descriptortrust.Read(c.config.TrustPolicy, path, c.config.DescriptorMaxBytes)
	if err != nil {
		return Discovered{}, err
	}
	descriptor, err := adapterv1.DecodeDescriptor(trusted.DescriptorData)
	if err != nil {
		return Discovered{}, fmt.Errorf("decode descriptor %q: %w", path, err)
	}
	trusted, err = descriptortrust.ValidateReferences(c.config.TrustPolicy, trusted, descriptor.Executable, descriptor.AssetRoot)
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
		if previous, exists := seen[discovered.Descriptor.AdapterID]; exists {
			return nil, fmt.Errorf("%w %q in %q and %q", ErrDuplicateID, discovered.Descriptor.AdapterID, previous, path)
		}
		seen[discovered.Descriptor.AdapterID] = path
		loaded = append(loaded, discovered)
	}
	for _, discovered := range loaded {
		if err := c.handshake(ctx, discovered, host); err != nil {
			return nil, fmt.Errorf("adapter %q: %w", discovered.Descriptor.AdapterID, err)
		}
	}
	return loaded, nil
}

func (c Client) Invoke(ctx context.Context, adapter Discovered, request adapterv1.Request) (adapterv1.Response, error) {
	if err := request.Validate(); err != nil {
		return adapterv1.Response{}, fmt.Errorf("invalid adapter request: %w", err)
	}
	if request.ProtocolVersion.Major != adapter.ProtocolVersion.Major {
		return adapterv1.Response{}, ErrProtocolMismatch
	}
	input, err := json.Marshal(request)
	if err != nil {
		return adapterv1.Response{}, err
	}
	deadline, _ := time.Parse(time.RFC3339, request.Context.Deadline)
	invocationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	processResult, err := c.config.Runner.Run(invocationContext, adapter.ExecutablePath, input)
	if err != nil {
		if processResult.ExitCode == 65 {
			return adapterv1.Response{}, ErrProtocolMismatch
		}
		return adapterv1.Response{}, err
	}
	response, err := adapterv1.DecodeResponse(processResult.Stdout)
	if err != nil {
		return adapterv1.Response{}, fmt.Errorf("%w: %v", ErrMalformedOutput, err)
	}
	if response.RequestID != request.RequestID {
		return adapterv1.Response{}, fmt.Errorf("%w: request ID differs", ErrIdentityMismatch)
	}
	if response.ProtocolVersion.Major != request.ProtocolVersion.Major {
		return adapterv1.Response{}, ErrProtocolMismatch
	}
	if response.ProtocolVersion.Minor > request.ProtocolVersion.Minor {
		return adapterv1.Response{}, fmt.Errorf("adapter selected unsupported protocol minor %d", response.ProtocolVersion.Minor)
	}
	return response, nil
}

func (c Client) handshake(ctx context.Context, adapter Discovered, host protocol.HostContext) error {
	requestID, err := protocol.NewRequestID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(adapterv1.DescribePayload{SupportedProtocolRange: &adapterv1.ProtocolRange{MinMajor: c.config.ProtocolMajor, MaxMajor: c.config.ProtocolMajor}})
	if err != nil {
		return err
	}
	response, err := c.Invoke(ctx, adapter, adapterv1.Request{ProtocolVersion: adapter.ProtocolVersion, RequestID: requestID, Operation: "Describe", CoreVersion: c.config.CoreVersion, Context: host, Payload: payload})
	if err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("Describe failed: %s", response.Error.Message)
	}
	runtimeDescriptor, err := adapterv1.DecodeDescriptor(response.Result)
	if err != nil {
		return fmt.Errorf("runtime descriptor: %w", err)
	}
	static := adapter.Descriptor
	if runtimeDescriptor.AdapterID != static.AdapterID || runtimeDescriptor.AdapterVersion != static.AdapterVersion || runtimeDescriptor.Executable != static.Executable || !sameVersions(runtimeDescriptor.ProtocolVersions, static.ProtocolVersions) {
		return ErrIdentityMismatch
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
