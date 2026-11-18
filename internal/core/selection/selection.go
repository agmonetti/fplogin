// Package selection filters adapter-attributed targets using opaque identities
// and capability predicates. It never assigns a priority or implicit winner.
package selection

import (
	"errors"
	"sort"

	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

var ErrNoCompatibleTarget = errors.New("no compatible target")

const NoSelectableTargetExitCode = 4

type NoCompatibleError struct {
	Reason          string
	RequestedTarget string
	Message         string
}

func (e NoCompatibleError) Error() string { return e.Message }
func (e NoCompatibleError) Unwrap() error { return ErrNoCompatibleTarget }

type AdapterDetection struct {
	AdapterID                  string
	AdapterName                string
	Capabilities               []protocol.Capability
	Targets                    []adapterv1.DetectedTarget
	HardPrerequisitesSatisfied bool
}

type SelectableTarget struct {
	TargetInstanceID string   `json:"target_instance_id"`
	AdapterID        string   `json:"adapter_id"`
	AdapterName      string   `json:"adapter_name"`
	DisplayName      string   `json:"display_name"`
	Confidence       string   `json:"confidence"`
	Capabilities     []string `json:"capabilities"`
}

type Result struct {
	Targets              []SelectableTarget
	RequiresUserChoice   bool
	RequiresConfirmation bool
}

func Build(detections []AdapterDetection, requiredCapabilities []string) (Result, error) {
	return build(detections, requiredCapabilities, false)
}

// PreviewChoices lists targets to inspect, not targets eligible for installation.
func PreviewChoices(detections []AdapterDetection, requiredCapabilities []string) (Result, error) {
	return build(detections, requiredCapabilities, true)
}

func build(detections []AdapterDetection, requiredCapabilities []string, previewOnly bool) (Result, error) {
	selectable := make([]SelectableTarget, 0)
	for _, detection := range detections {
		if detection.AdapterID == "" || (!previewOnly && !detection.HardPrerequisitesSatisfied) {
			continue
		}
		offered := make(map[string]struct{}, len(detection.Capabilities))
		for _, capability := range detection.Capabilities {
			if capability.Status != "unsupported" {
				offered[capability.ID] = struct{}{}
			}
		}
		if !containsAll(offered, requiredCapabilities) {
			continue
		}
		capabilities := make([]string, 0, len(offered))
		for capability := range offered {
			capabilities = append(capabilities, capability)
		}
		sort.Strings(capabilities)
		for _, target := range detection.Targets {
			if target.Compatibility != "compatible" {
				continue
			}
			selectable = append(selectable, SelectableTarget{target.InstanceID, detection.AdapterID, detection.AdapterName, target.DisplayName, target.Confidence, capabilities})
		}
	}
	sort.Slice(selectable, func(i, j int) bool {
		if selectable[i].AdapterID != selectable[j].AdapterID {
			return selectable[i].AdapterID < selectable[j].AdapterID
		}
		return selectable[i].TargetInstanceID < selectable[j].TargetInstanceID
	})
	if len(selectable) == 0 {
		return Result{}, ErrNoCompatibleTarget
	}
	return Result{Targets: selectable, RequiresUserChoice: len(selectable) > 1, RequiresConfirmation: true}, nil
}

func BuildForRequest(detections []AdapterDetection, requiredCapabilities []string, requestedTarget string) (Result, error) {
	if requestedTarget != "" {
		filtered := make([]AdapterDetection, 0, len(detections))
		for _, detection := range detections {
			matching := detection
			matching.Targets = nil
			for _, target := range detection.Targets {
				if target.InstanceID == requestedTarget || target.DMID == requestedTarget {
					matching.Targets = append(matching.Targets, target)
				}
			}
			if len(matching.Targets) > 0 {
				filtered = append(filtered, matching)
			}
		}
		result, err := Build(filtered, requiredCapabilities)
		if err != nil {
			return Result{}, NoCompatibleError{
				Reason:          "no_compatible_adapter",
				RequestedTarget: requestedTarget,
				Message:         "No compatible fplogin adapter is available for the requested target '" + requestedTarget + "'. Installed or detected targets were checked, but none satisfies the required adapter capabilities. No changes were made.",
			}
		}
		return result, nil
	}
	result, err := Build(detections, requiredCapabilities)
	if err != nil {
		return Result{}, NoCompatibleError{
			Reason:  "no_compatible_target",
			Message: "No compatible installation target was detected. No changes were made.",
		}
	}
	return result, nil
}

func containsAll(offered map[string]struct{}, required []string) bool {
	for _, capability := range required {
		if _, exists := offered[capability]; !exists {
			return false
		}
	}
	return true
}
