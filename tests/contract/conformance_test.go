package contract_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/selection"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

const helperTimeout = 3 * time.Second

func TestProtocolFixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		validPath   string
		invalidPath string
		decode      func([]byte) error
	}{
		{"adapter descriptor", "../../contracts/adapter/v1/examples/descriptor.valid.json", "../../contracts/adapter/v1/examples/descriptor.invalid.json", func(data []byte) error { _, err := adapterv1.DecodeDescriptor(data); return err }},
		{"adapter request", "../../contracts/adapter/v1/examples/request.valid.json", "../../contracts/adapter/v1/examples/request.invalid.json", func(data []byte) error { _, err := adapterv1.DecodeRequest(data); return err }},
		{"adapter response", "../../contracts/adapter/v1/examples/response.valid.json", "../../contracts/adapter/v1/examples/response.invalid.json", func(data []byte) error { _, err := adapterv1.DecodeResponse(data); return err }},
		{"change plan", "../../contracts/adapter/v1/examples/change-plan.valid.json", "../../contracts/adapter/v1/examples/change-plan.invalid.json", func(data []byte) error { _, err := adapterv1.DecodeChangePlan(data); return err }},
		{"platform descriptor", "../../contracts/platform/v1/examples/descriptor.valid.json", "../../contracts/platform/v1/examples/descriptor.invalid.json", func(data []byte) error { _, err := platformv1.DecodeDescriptor(data); return err }},
		{"platform request", "../../contracts/platform/v1/examples/request.valid.json", "../../contracts/platform/v1/examples/request.invalid.json", func(data []byte) error { _, err := platformv1.DecodeRequest(data); return err }},
		{"platform response", "../../contracts/platform/v1/examples/response.valid.json", "../../contracts/platform/v1/examples/response.invalid.json", func(data []byte) error { _, err := platformv1.DecodeResponse(data); return err }},
		{"transaction journal", "../../contracts/manifest/v1/examples/transaction-journal.valid.json", "../../contracts/manifest/v1/examples/transaction-journal.invalid.json", func(data []byte) error { _, err := manifestv1.DecodeTransactionJournal(data); return err }},
		{"install manifest", "../../contracts/manifest/v1/examples/install-manifest.valid.json", "../../contracts/manifest/v1/examples/install-manifest.invalid.json", func(data []byte) error { _, err := manifestv1.DecodeInstallManifest(data); return err }},
		{"analyzer finding", "../../contracts/analyzer/v1/examples/finding.valid.json", "../../contracts/analyzer/v1/examples/finding.invalid.json", func(data []byte) error { _, err := analyzerv1.DecodeFinding(data); return err }},
		{"analyzer report", "../../contracts/analyzer/v1/examples/report.valid.json", "../../contracts/analyzer/v1/examples/report.invalid.json", func(data []byte) error { _, err := analyzerv1.DecodeReport(data); return err }},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			valid := mustRead(t, test.validPath)
			if err := test.decode(valid); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
			invalid := mustRead(t, test.invalidPath)
			if err := test.decode(invalid); err == nil {
				t.Fatal("invalid fixture accepted")
			}
		})
	}
}

func TestAnalyzerNullableFields(t *testing.T) {
	t.Parallel()
	var finding map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, "../../contracts/analyzer/v1/examples/finding.valid.json"), &finding); err != nil {
		t.Fatal(err)
	}
	finding["suggested_action"] = json.RawMessage("null")
	data, _ := json.Marshal(finding)
	if _, err := analyzerv1.DecodeFinding(data); err != nil {
		t.Fatalf("null suggested action rejected: %v", err)
	}

	var report map[string]json.RawMessage
	if err := json.Unmarshal(mustRead(t, "../../contracts/analyzer/v1/examples/report.valid.json"), &report); err != nil {
		t.Fatal(err)
	}
	report["target"] = json.RawMessage(`{"adapter_id":null,"instance_id":null}`)
	data, _ = json.Marshal(report)
	if _, err := analyzerv1.DecodeReport(data); err != nil {
		t.Fatalf("null report target rejected: %v", err)
	}
}

func TestShippedDescriptorsMatchV1(t *testing.T) {
	t.Parallel()
	if _, err := adapterv1.DecodeDescriptor(mustRead(t, "../../adapters/sddm/adapter.json")); err != nil {
		t.Fatalf("SDDM descriptor: %v", err)
	}
	if _, err := platformv1.DecodeDescriptor(mustRead(t, "../../platforms/arch/platform.json")); err != nil {
		t.Fatalf("Arch provider descriptor: %v", err)
	}
}

func TestAdapterDiscoveryAndFailures(t *testing.T) {
	t.Parallel()
	if descriptortrust.Elevated() {
		t.Skip("development descriptors require an ordinary user")
	}
	t.Run("discovers through runtime handshake", func(t *testing.T) {
		root, descriptorPath := makeAdapterInstallation(t, "org.example.adapter.one", 1)
		client := newAdapterClient(t, root, "normal", helperTimeout)
		discovered, err := client.Discover(context.Background(), []string{descriptorPath}, hostContext())
		if err != nil {
			t.Fatal(err)
		}
		if len(discovered) != 1 || discovered[0].Descriptor.AdapterID != "org.example.adapter.one" {
			t.Fatalf("unexpected discovery result: %#v", discovered)
		}
	})
	t.Run("rejects duplicate IDs", func(t *testing.T) {
		rootOne, pathOne := makeAdapterInstallation(t, "org.example.adapter.duplicate", 1)
		_, pathTwo := makeAdapterInstallation(t, "org.example.adapter.duplicate", 1)
		client := newAdapterClient(t, rootOne, "sleep", 30*time.Millisecond)
		_, err := client.Discover(context.Background(), []string{pathOne, pathTwo}, hostContext())
		if !errors.Is(err, adapterclient.ErrDuplicateID) {
			t.Fatalf("expected duplicate error, got %v", err)
		}
	})
	t.Run("rejects protocol major mismatch before execution", func(t *testing.T) {
		root, descriptorPath := makeAdapterInstallation(t, "org.example.adapter.mismatch", 2)
		client := newAdapterClient(t, root, "normal", helperTimeout)
		_, err := client.LoadDescriptor(descriptorPath)
		if !errors.Is(err, adapterclient.ErrProtocolMismatch) {
			t.Fatalf("expected protocol mismatch, got %v", err)
		}
	})
	t.Run("maps protocol exit status", func(t *testing.T) {
		root, descriptorPath := makeAdapterInstallation(t, "org.example.adapter.exit-mismatch", 1)
		client := newAdapterClient(t, root, "exit-protocol", helperTimeout)
		_, err := client.Discover(context.Background(), []string{descriptorPath}, hostContext())
		if !errors.Is(err, adapterclient.ErrProtocolMismatch) {
			t.Fatalf("expected protocol mismatch, got %v", err)
		}
	})
	t.Run("rejects runtime protocol mismatch", func(t *testing.T) {
		root, descriptorPath := makeAdapterInstallation(t, "org.example.adapter.runtime-mismatch", 1)
		client := newAdapterClient(t, root, "version-mismatch", helperTimeout)
		_, err := client.Discover(context.Background(), []string{descriptorPath}, hostContext())
		if !errors.Is(err, adapterclient.ErrProtocolMismatch) {
			t.Fatalf("expected protocol mismatch, got %v", err)
		}
	})
	t.Run("rejects malformed stdout", func(t *testing.T) {
		root, descriptorPath := makeAdapterInstallation(t, "org.example.adapter.malformed", 1)
		client := newAdapterClient(t, root, "malformed", helperTimeout)
		descriptor, err := client.LoadDescriptor(descriptorPath)
		if err != nil {
			t.Fatal(err)
		}
		request := adapterRequest(t, descriptor.ProtocolVersion)
		_, err = client.Invoke(context.Background(), descriptor, request)
		if !errors.Is(err, adapterclient.ErrMalformedOutput) {
			t.Fatalf("expected malformed output, got %v", err)
		}
	})
	t.Run("rejects untrusted writable descriptor", func(t *testing.T) {
		root, descriptorPath := makeAdapterInstallation(t, "org.example.adapter.untrusted", 1)
		if err := os.Chmod(descriptorPath, 0o666); err != nil {
			t.Fatal(err)
		}
		client := newAdapterClient(t, root, "normal", helperTimeout)
		if _, err := client.LoadDescriptor(descriptorPath); err == nil {
			t.Fatal("writable descriptor accepted")
		}
	})
}

func TestPlatformDiscoveryAndCapabilities(t *testing.T) {
	t.Parallel()
	if descriptortrust.Elevated() {
		t.Skip("development descriptors require an ordinary user")
	}
	t.Run("discovers and filters capabilities", func(t *testing.T) {
		root, descriptorPath := makePlatformInstallation(t, "org.example.platform.one", 1)
		client := newPlatformClient(t, root, "normal", helperTimeout)
		discovered, err := client.Discover(context.Background(), []string{descriptorPath}, hostContext())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := platformclient.SelectByCapabilities(discovered, []string{"host.inspect"}); err != nil {
			t.Fatalf("required capability rejected: %v", err)
		}
		if _, err := platformclient.SelectByCapabilities(discovered, []string{"artifact.stage"}); !errors.Is(err, platformclient.ErrCapabilityInsufficient) {
			t.Fatalf("missing capability accepted: %v", err)
		}
	})
	t.Run("rejects duplicate IDs before execution", func(t *testing.T) {
		root, pathOne := makePlatformInstallation(t, "org.example.platform.duplicate", 1)
		_, pathTwo := makePlatformInstallation(t, "org.example.platform.duplicate", 1)
		client := newPlatformClient(t, root, "sleep", 30*time.Millisecond)
		_, err := client.Discover(context.Background(), []string{pathOne, pathTwo}, hostContext())
		if !errors.Is(err, platformclient.ErrDuplicateID) {
			t.Fatalf("expected duplicate error, got %v", err)
		}
	})
	t.Run("rejects runtime protocol mismatch", func(t *testing.T) {
		root, descriptorPath := makePlatformInstallation(t, "org.example.platform.mismatch", 1)
		client := newPlatformClient(t, root, "version-mismatch", helperTimeout)
		_, err := client.Discover(context.Background(), []string{descriptorPath}, hostContext())
		if !errors.Is(err, platformclient.ErrProtocolMismatch) {
			t.Fatalf("expected protocol mismatch, got %v", err)
		}
	})
	t.Run("rejects malformed stdout", func(t *testing.T) {
		root, descriptorPath := makePlatformInstallation(t, "org.example.platform.malformed", 1)
		client := newPlatformClient(t, root, "malformed", helperTimeout)
		descriptor, err := client.LoadDescriptor(descriptorPath)
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(platformv1.DescribePayload{})
		request := platformRequest(t, "Describe", payload)
		_, err = client.Invoke(context.Background(), descriptor, request)
		if !errors.Is(err, platformclient.ErrMalformedOutput) {
			t.Fatalf("expected malformed output, got %v", err)
		}
	})
}

func TestBoundedRunnerTimeoutAndOutput(t *testing.T) {
	t.Parallel()
	root, _ := makeAdapterInstallation(t, "org.example.adapter.runner", 1)
	executable := filepath.Join(root, "bin", "fake")
	t.Run("timeout", func(t *testing.T) {
		runner := newRunner(t, "sleep", 30*time.Millisecond, 4096)
		_, err := runner.Run(context.Background(), executable, []byte(`{}`))
		if !errors.Is(err, processrunner.ErrTimeout) {
			t.Fatalf("expected timeout, got %v", err)
		}
	})
	t.Run("output bound", func(t *testing.T) {
		runner := newRunner(t, "huge", helperTimeout, 64)
		_, err := runner.Run(context.Background(), executable, []byte(`{}`))
		if !errors.Is(err, processrunner.ErrOutputTooLarge) {
			t.Fatalf("expected output limit, got %v", err)
		}
	})
}

func TestTypedOperationAndArtifactValidation(t *testing.T) {
	t.Parallel()
	base := platformRequest(t, "ApplyOperation", json.RawMessage(`{"operation":{"operation_id":"op-1","kind":"run_command","dependencies":[],"parameters":{},"preconditions":[],"expected_before":{},"expected_after":{},"compensation":{"kind":"noop"}},"plan_digest":"4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"}`))
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platformv1.DecodeRequest(encoded); err == nil {
		t.Fatal("unknown privileged operation accepted")
	}

	payload := platformv1.PrepareArtifactInstallPayload{
		SelectedCapabilities: []string{"artifact.stage"}, PlanDigest: digest(), OperationIDs: []string{"op-1"},
		StagingHandoff:     platformv1.StagingHandoff{Workspace: "/tmp/work", SourceCache: "/tmp/cache"},
		ArtifactReferences: []platformv1.ArtifactReference{{ArtifactID: "artifact-1", MediaType: "application/octet-stream", SHA256: digest(), Size: 1, CanonicalPath: "/tmp/outside/file"}},
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := platformRequest(t, "PrepareArtifactInstall", rawPayload)
	encoded, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platformv1.DecodeRequest(encoded); err == nil {
		t.Fatal("artifact path outside staging workspace accepted")
	}
	payload.ArtifactReferences[0].CanonicalPath = "/tmp/work/file"
	payload.ArtifactReferences[0].SHA256 = "not-a-digest"
	rawPayload, _ = json.Marshal(payload)
	request.Payload = rawPayload
	encoded, _ = json.Marshal(request)
	if _, err := platformv1.DecodeRequest(encoded); err == nil {
		t.Fatal("invalid artifact digest accepted")
	}

	workspace := t.TempDir()
	artifactPath := filepath.Join(workspace, "artifact")
	if err := os.WriteFile(artifactPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	filePayload := platformv1.PrepareArtifactInstallPayload{
		SelectedCapabilities: []string{"artifact.stage"},
		PlanDigest:           digest(),
		OperationIDs:         []string{"op-1"},
		StagingHandoff:       platformv1.StagingHandoff{Workspace: workspace, SourceCache: t.TempDir()},
		ArtifactReferences: []platformv1.ArtifactReference{{
			ArtifactID: "artifact-1", MediaType: "application/octet-stream", SHA256: digest(), Size: 1, CanonicalPath: artifactPath,
		}},
	}
	if err := platformclient.ValidateArtifactFiles(filePayload); err == nil {
		t.Fatal("artifact content digest mismatch accepted")
	}
	filePayload.ArtifactReferences[0].SHA256 = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
	if err := platformclient.ValidateArtifactFiles(filePayload); err != nil {
		t.Fatalf("valid artifact file rejected: %v", err)
	}
}

func TestAnalyzerFactsPreserveEvidenceWithoutClassification(t *testing.T) {
	t.Parallel()
	data := mustRead(t, "../../contracts/platform/v1/examples/analyzer-facts.valid.json")
	var facts platformv1.PlatformAnalyzerFacts
	if err := protocol.DecodeStrict(data, &facts, "scope", "collected_at", "evidence", "probe_errors"); err != nil {
		t.Fatal(err)
	}
	if err := facts.Validate(); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["confidence"] = json.RawMessage(`"confirmed"`)
	classified, _ := json.Marshal(document)
	if err := protocol.DecodeStrict(classified, &facts, "scope", "collected_at", "evidence", "probe_errors"); err == nil {
		t.Fatal("provider fact accepted a preclassified confidence")
	}
}

func TestSelectionFixtures(t *testing.T) {
	t.Parallel()
	paths := []string{
		"../fixtures/selection/one_compatible.json",
		"../fixtures/selection/multiple_compatible.json",
		"../fixtures/selection/multiple_dms_one_compatible.json",
		"../fixtures/selection/requested_no_adapter.json",
		"../fixtures/selection/zero_compatible.json",
	}
	capability := protocol.Capability{ID: "auth.concurrent_methods", Status: "provided", Level: json.RawMessage(`1`), Constraints: protocol.Object{}, EvidenceRequirements: []string{}}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fixture struct {
				RequestedTarget   string `json:"requested_target"`
				AdapterDetections []struct {
					AdapterID string                     `json:"adapter_id"`
					Targets   []adapterv1.DetectedTarget `json:"targets"`
				} `json:"adapter_detections"`
				Expected struct {
					Status               string `json:"status"`
					Reason               string `json:"reason"`
					RequiresConfirmation bool   `json:"requires_confirmation"`
					RequiresUserChoice   bool   `json:"requires_user_choice"`
					SelectableTargets    []struct {
						TargetInstanceID string `json:"target_instance_id"`
						AdapterID        string `json:"adapter_id"`
					} `json:"selectable_targets"`
				} `json:"expected_outcome"`
			}
			if err := json.Unmarshal(mustRead(t, path), &fixture); err != nil {
				t.Fatal(err)
			}
			detections := make([]selection.AdapterDetection, 0, len(fixture.AdapterDetections))
			for _, detection := range fixture.AdapterDetections {
				detections = append(detections, selection.AdapterDetection{
					AdapterID:                  detection.AdapterID,
					AdapterName:                detection.AdapterID,
					Capabilities:               []protocol.Capability{capability},
					Targets:                    detection.Targets,
					HardPrerequisitesSatisfied: true,
				})
			}
			result, err := selection.BuildForRequest(detections, []string{capability.ID}, fixture.RequestedTarget)
			if fixture.Expected.Status == "selection_error" {
				var selectionError selection.NoCompatibleError
				if !errors.As(err, &selectionError) || selectionError.Reason != fixture.Expected.Reason {
					t.Fatalf("expected selection reason %q, got %v", fixture.Expected.Reason, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.RequiresConfirmation != fixture.Expected.RequiresConfirmation || result.RequiresUserChoice != fixture.Expected.RequiresUserChoice || len(result.Targets) != len(fixture.Expected.SelectableTargets) {
				t.Fatalf("unexpected selection result: %#v", result)
			}
			for index, expected := range fixture.Expected.SelectableTargets {
				if result.Targets[index].TargetInstanceID != expected.TargetInstanceID || result.Targets[index].AdapterID != expected.AdapterID {
					t.Fatalf("target %d mismatch: %#v", index, result.Targets[index])
				}
			}
		})
	}
}

func TestProtocolHelperProcess(t *testing.T) {
	if os.Getenv("FPLOGIN_PROTOCOL_HELPER") != "1" {
		return
	}
	behavior := os.Getenv("FPLOGIN_HELPER_BEHAVIOR")
	if behavior == "exit-protocol" {
		os.Exit(65)
	}
	if behavior == "sleep" {
		time.Sleep(2 * time.Second)
		return
	}
	if behavior == "huge" {
		_, _ = fmt.Fprint(os.Stdout, string(make([]byte, 8192)))
		return
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(70)
	}
	var request struct {
		ProtocolVersion protocol.Version `json:"protocol_version"`
		RequestID       string           `json:"request_id"`
	}
	if err := json.Unmarshal(input, &request); err != nil {
		os.Exit(64)
	}
	if behavior == "malformed" {
		_, _ = fmt.Fprint(os.Stdout, `{"ok":true}{"extra":true}`)
		return
	}
	root := filepath.Dir(filepath.Dir(os.Args[0]))
	descriptorPath := filepath.Join(root, "adapter.json")
	if _, err := os.Stat(descriptorPath); err != nil {
		descriptorPath = filepath.Join(root, "platform.json")
	}
	descriptor, err := os.ReadFile(descriptorPath)
	if err != nil {
		os.Exit(70)
	}
	version := request.ProtocolVersion
	if behavior == "version-mismatch" {
		version.Major++
	}
	response := struct {
		ProtocolVersion protocol.Version `json:"protocol_version"`
		RequestID       string           `json:"request_id"`
		OK              bool             `json:"ok"`
		Result          json.RawMessage  `json:"result"`
		Error           any              `json:"error"`
	}{version, request.RequestID, true, descriptor, nil}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		os.Exit(70)
	}
	os.Exit(0)
}

func makeAdapterInstallation(t *testing.T, id string, major int) (string, string) {
	t.Helper()
	root := makeInstallation(t)
	descriptor := adapterv1.Descriptor{DescriptorSchemaVersion: "1.0", AdapterID: id, AdapterVersion: "1.0.0", ProtocolVersions: []protocol.Version{{Major: major, Minor: 0}}, MinimumCoreVersion: "0.1.0", Name: "Fake Adapter", Vendor: "tests", Executable: "bin/fake", SupportedDisplayManagers: []adapterv1.SupportedDisplayManager{{DMID: "opaque", Name: "Fake DM", VersionPolicy: "test", TargetAliases: []string{}}}, IntegrationStrategies: []string{"configuration"}, Capabilities: []protocol.Capability{{ID: "auth.concurrent_methods", Status: "provided", Level: json.RawMessage(`1`), Constraints: protocol.Object{}, EvidenceRequirements: []string{}}}, Prerequisites: []adapterv1.PrerequisiteDeclaration{}, SupportedPlatforms: []string{"any"}, OperationModes: []string{"fresh_install", "uninstall"}, AssetRoot: "assets"}
	path := filepath.Join(root, "adapter.json")
	writeJSON(t, path, descriptor)
	return root, path
}

func makePlatformInstallation(t *testing.T, id string, major int) (string, string) {
	t.Helper()
	root := makeInstallation(t)
	descriptor := platformv1.Descriptor{DescriptorSchemaVersion: "1.0", PlatformID: id, PlatformVersion: "1.0.0", ProtocolVersions: []protocol.Version{{Major: major, Minor: 0}}, MinimumCoreVersion: "0.1.0", Name: "Fake Platform", Vendor: "tests", Executable: "bin/fake", SupportedPlatforms: []platformv1.SupportedPlatform{{Distribution: "opaque", Architecture: runtime.GOARCH}}, Capabilities: []protocol.Capability{{ID: "host.inspect", Status: "provided", Level: json.RawMessage(`1`), Constraints: protocol.Object{}, EvidenceRequirements: []string{}}}, OperationKinds: []protocol.OperationKind{protocol.CreateDirectory}, PackageFormats: []string{}, ServiceManager: platformv1.ServiceManager{Kind: "opaque", Capabilities: []string{}}, AssetRoot: "assets"}
	path := filepath.Join(root, "platform.json")
	writeJSON(t, path, descriptor)
	return root, path
}

func makeInstallation(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "bin", "fake")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o500)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	return root
}

func newAdapterClient(t *testing.T, root, behavior string, timeout time.Duration) adapterclient.Client {
	t.Helper()
	runner := newRunner(t, behavior, timeout, 1<<20)
	client, err := adapterclient.New(adapterclient.Config{Runner: runner, TrustPolicy: descriptortrust.Policy{OwnerUID: uint32(os.Getuid())}, DescriptorMaxBytes: 1 << 20, ProtocolMajor: 1, CoreVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func newPlatformClient(t *testing.T, root, behavior string, timeout time.Duration) platformclient.Client {
	t.Helper()
	runner := newRunner(t, behavior, timeout, 1<<20)
	client, err := platformclient.New(platformclient.Config{Runner: runner, TrustPolicy: descriptortrust.Policy{OwnerUID: uint32(os.Getuid())}, DescriptorMaxBytes: 1 << 20, ProtocolMajor: 1, CoreVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func newRunner(t *testing.T, behavior string, timeout time.Duration, stdoutLimit int) processrunner.Runner {
	t.Helper()
	runner, err := processrunner.New(processrunner.Config{Timeout: timeout, MaxInputBytes: 1 << 20, MaxStdoutBytes: stdoutLimit, MaxStderrBytes: 4096, Environment: []string{"FPLOGIN_PROTOCOL_HELPER=1", "FPLOGIN_HELPER_BEHAVIOR=" + behavior}, Arguments: []string{"-test.run=TestProtocolHelperProcess"}})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func adapterRequest(t *testing.T, version protocol.Version) adapterv1.Request {
	t.Helper()
	payload, _ := json.Marshal(adapterv1.DescribePayload{})
	return adapterv1.Request{ProtocolVersion: version, RequestID: "11111111-2222-4333-8444-555555555555", Operation: "Describe", CoreVersion: "0.1.0", Context: hostContext(), Payload: payload}
}
func platformRequest(t *testing.T, operation string, payload json.RawMessage) platformv1.Request {
	t.Helper()
	return platformv1.Request{ProtocolVersion: protocol.Version{Major: 1}, RequestID: "11111111-2222-4333-8444-555555555555", Operation: operation, CoreVersion: "0.1.0", Context: hostContext(), Payload: payload}
}
func hostContext() protocol.HostContext {
	return protocol.HostContext{Root: "/", Platform: protocol.Object{"os": json.RawMessage(`"linux"`)}, Architecture: runtime.GOARCH, InvokingUID: uint32(os.Getuid()), InvokingGID: uint32(os.Getgid()), Locale: "C", Deadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
}
func digest() string { return "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a" }
func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
