package selection_test

import (
	"encoding/json"
	"errors"
	"testing"

	"fplogin/internal/core/selection"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

func TestBuild_EmptyDetections(t *testing.T) {
	_, err := selection.Build(nil, []string{"auth.concurrent_methods"})
	if !errors.Is(err, selection.ErrNoCompatibleTarget) {
		t.Fatalf("expected ErrNoCompatibleTarget, got: %v", err)
	}
}

func TestBuild_SkipsEmptyAdapterOrUnmetPrereqs(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "",
			AdapterName:                "Empty ID",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{InstanceID: "target-1", Compatibility: "compatible"},
			},
		},
		{
			AdapterID:                  "adapter.unmet",
			AdapterName:                "Unmet Prereqs",
			HardPrerequisitesSatisfied: false,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{InstanceID: "target-2", Compatibility: "compatible"},
			},
		},
	}

	_, err := selection.Build(detections, []string{"auth.concurrent_methods"})
	if !errors.Is(err, selection.ErrNoCompatibleTarget) {
		t.Fatalf("expected ErrNoCompatibleTarget, got: %v", err)
	}
}

func TestBuild_MissingRequiredCapabilities(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "adapter.partial",
			AdapterName:                "Partial",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "other.capability", Status: "provided"},
				{ID: "auth.concurrent_methods", Status: "unsupported"},
			},
			Targets: []adapterv1.DetectedTarget{
				{InstanceID: "target-1", Compatibility: "compatible"},
			},
		},
	}

	_, err := selection.Build(detections, []string{"auth.concurrent_methods"})
	if !errors.Is(err, selection.ErrNoCompatibleTarget) {
		t.Fatalf("expected ErrNoCompatibleTarget, got: %v", err)
	}
}

func TestBuild_FiltersIncompatibleTargets(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "adapter.one",
			AdapterName:                "Adapter One",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{InstanceID: "target-incompat", Compatibility: "incompatible"},
				{InstanceID: "target-unknown", Compatibility: "unknown"},
			},
		},
	}

	_, err := selection.Build(detections, []string{"auth.concurrent_methods"})
	if !errors.Is(err, selection.ErrNoCompatibleTarget) {
		t.Fatalf("expected ErrNoCompatibleTarget, got: %v", err)
	}
}

func TestBuild_SingleTargetSelection(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "adapter.sddm",
			AdapterName:                "SDDM Adapter",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
				{ID: "ui.greeter_feedback", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{
					InstanceID:    "sddm-0.21.0",
					DisplayName:   "SDDM v0.21.0",
					Confidence:    "confirmed",
					Compatibility: "compatible",
				},
			},
		},
	}

	res, err := selection.Build(detections, []string{"auth.concurrent_methods"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(res.Targets))
	}
	if res.RequiresUserChoice {
		t.Fatalf("expected RequiresUserChoice to be false for single target")
	}
	if !res.RequiresConfirmation {
		t.Fatalf("expected RequiresConfirmation to be true")
	}
	target := res.Targets[0]
	if target.TargetInstanceID != "sddm-0.21.0" || target.AdapterID != "adapter.sddm" {
		t.Fatalf("unexpected target properties: %+v", target)
	}
	if len(target.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(target.Capabilities))
	}
}

func TestBuild_MultipleTargetsRequiresChoiceAndSorted(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "adapter.beta",
			AdapterName:                "Beta Adapter",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{InstanceID: "inst-b2", DisplayName: "Target B2", Compatibility: "compatible"},
				{InstanceID: "inst-b1", DisplayName: "Target B1", Compatibility: "compatible"},
			},
		},
		{
			AdapterID:                  "adapter.alpha",
			AdapterName:                "Alpha Adapter",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{InstanceID: "inst-a1", DisplayName: "Target A1", Compatibility: "compatible"},
			},
		},
	}

	res, err := selection.Build(detections, []string{"auth.concurrent_methods"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(res.Targets))
	}
	if !res.RequiresUserChoice {
		t.Fatalf("expected RequiresUserChoice to be true for multiple targets")
	}

	// Order should be sorted by AdapterID then TargetInstanceID
	if res.Targets[0].AdapterID != "adapter.alpha" || res.Targets[0].TargetInstanceID != "inst-a1" {
		t.Fatalf("expected first target to be alpha/inst-a1, got %+v", res.Targets[0])
	}
	if res.Targets[1].AdapterID != "adapter.beta" || res.Targets[1].TargetInstanceID != "inst-b1" {
		t.Fatalf("expected second target to be beta/inst-b1, got %+v", res.Targets[1])
	}
	if res.Targets[2].AdapterID != "adapter.beta" || res.Targets[2].TargetInstanceID != "inst-b2" {
		t.Fatalf("expected third target to be beta/inst-b2, got %+v", res.Targets[2])
	}
}

func TestBuildForRequest_RequestedTargetMatch(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "adapter.sddm",
			AdapterName:                "SDDM",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{DMID: "sddm", InstanceID: "sddm-system", Compatibility: "compatible"},
				{DMID: "other", InstanceID: "other-system", Compatibility: "compatible"},
			},
		},
	}

	// Match by DMID
	res, err := selection.BuildForRequest(detections, []string{"auth.concurrent_methods"}, "sddm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Targets) != 1 || res.Targets[0].TargetInstanceID != "sddm-system" {
		t.Fatalf("expected match by DMID, got %+v", res.Targets)
	}

	// Match by InstanceID
	res, err = selection.BuildForRequest(detections, []string{"auth.concurrent_methods"}, "other-system")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Targets) != 1 || res.Targets[0].TargetInstanceID != "other-system" {
		t.Fatalf("expected match by InstanceID, got %+v", res.Targets)
	}
}

func TestBuildForRequest_RequestedTargetNoMatch(t *testing.T) {
	detections := []selection.AdapterDetection{
		{
			AdapterID:                  "adapter.sddm",
			AdapterName:                "SDDM",
			HardPrerequisitesSatisfied: true,
			Capabilities: []protocol.Capability{
				{ID: "auth.concurrent_methods", Status: "provided"},
			},
			Targets: []adapterv1.DetectedTarget{
				{DMID: "sddm", InstanceID: "sddm-system", Compatibility: "compatible"},
			},
		},
	}

	_, err := selection.BuildForRequest(detections, []string{"auth.concurrent_methods"}, "gdm")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var noCompErr selection.NoCompatibleError
	if !errors.As(err, &noCompErr) {
		t.Fatalf("expected NoCompatibleError, got %T: %v", err, err)
	}
	if noCompErr.Reason != "no_compatible_adapter" || noCompErr.RequestedTarget != "gdm" {
		t.Fatalf("unexpected NoCompatibleError content: %+v", noCompErr)
	}
	if !errors.Is(err, selection.ErrNoCompatibleTarget) {
		t.Fatalf("expected unwrapped ErrNoCompatibleTarget, got: %v", err)
	}
	if noCompErr.Error() == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestBuildForRequest_NoTargetSpecifiedEmptyDetections(t *testing.T) {
	_, err := selection.BuildForRequest(nil, []string{"auth.concurrent_methods"}, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var noCompErr selection.NoCompatibleError
	if !errors.As(err, &noCompErr) {
		t.Fatalf("expected NoCompatibleError, got %T: %v", err, err)
	}
	if noCompErr.Reason != "no_compatible_target" {
		t.Fatalf("unexpected reason: %s", noCompErr.Reason)
	}
	if !errors.Is(err, selection.ErrNoCompatibleTarget) {
		t.Fatalf("expected unwrapped ErrNoCompatibleTarget, got: %v", err)
	}
}

func TestSelectableTarget_JSONMarshaling(t *testing.T) {
	target := selection.SelectableTarget{
		TargetInstanceID: "inst-1",
		AdapterID:        "adapter.test",
		AdapterName:      "Test Adapter",
		DisplayName:      "Display Name",
		Confidence:       "confirmed",
		Capabilities:     []string{"cap1", "cap2"},
	}

	data, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("failed to marshal target: %v", err)
	}

	var decoded selection.SelectableTarget
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal target: %v", err)
	}
	if decoded.TargetInstanceID != target.TargetInstanceID || decoded.AdapterID != target.AdapterID {
		t.Fatalf("mismatch after marshal/unmarshal: %+v vs %+v", decoded, target)
	}
}
