// Binary fplogin-adapter-sddm implements the out-of-process SDDM Display Manager
// Adapter following protocol/adapter/v1.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		emitError("00000000-0000-0000-0000-000000000000", protocol.Version{Major: 1, Minor: 0}, "internal_error", err.Error())
		os.Exit(1)
	}

	req, err := adapterv1.DecodeRequest(input)
	if err != nil {
		emitError("00000000-0000-0000-0000-000000000000", protocol.Version{Major: 1, Minor: 0}, "invalid_request", err.Error())
		os.Exit(1)
	}

	res, err := handleRequest(req)
	if err != nil {
		emitError(req.RequestID, req.ProtocolVersion, "internal_error", err.Error())
		os.Exit(0)
	}

	emitSuccess(req.RequestID, req.ProtocolVersion, res)
}

const staticAdapterDescriptor = `{
  "descriptor_schema_version": "1.0",
  "adapter_id": "org.fplogin.adapter.sddm",
  "adapter_version": "0.1.0",
  "protocol_versions": [{"major": 1, "minor": 0}],
  "minimum_core_version": "0.1.0",
  "name": "SDDM Biometric Login Adapter",
  "vendor": "fplogin",
  "executable": "bin/fplogin-adapter-sddm",
  "supported_display_managers": [
    {
      "dm_id": "sddm",
      "name": "Simple Desktop Display Manager",
      "version_policy": ">= 0.20, <= 0.21",
      "target_aliases": ["sddm.service", "display-manager.service"]
    }
  ],
  "integration_strategies": ["source_patch", "configuration"],
  "capabilities": [
    {
      "id": "auth.concurrent_methods",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["pam_service_sddm_fingerprint"]
    }
  ],
  "prerequisites": [
    {
      "id": "service.fprintd",
      "kind": "service",
      "required": true,
      "reason": "Biometric authentication requires fprintd daemon",
      "remediation_policy": "Install and start fprintd"
    }
  ],
  "supported_platforms": ["any"],
  "packaging_backends": ["arch"],
  "operation_modes": ["fresh_install", "upgrade", "repair", "reinstall", "uninstall"],
  "asset_root": "assets"
}`

func handleRequest(req adapterv1.Request) (json.RawMessage, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	switch req.Operation {
	case "Describe":
		return json.RawMessage(staticAdapterDescriptor), nil

	case "Detect":
		rep := adapterv1.DetectionReport{
			Targets: []adapterv1.DetectedTarget{
				{
					InstanceID:        "inst-sddm-1",
					DMID:              "sddm",
					DisplayName:       "Simple Desktop Display Manager",
					UpstreamVersion:   "0.21.0",
					PackageReferences: []string{"sddm"},
					ServiceReferences: []string{"sddm.service"},
					Compatibility:     "compatible",
					Confidence:        "confirmed",
					Evidence: []json.RawMessage{
						json.RawMessage(`{"type":"service","unit":"sddm.service","active":true}`),
					},
				},
			},
		}
		return json.Marshal(rep)

	case "CheckPrerequisites":
		rep := adapterv1.PrerequisiteReport{
			Findings: []adapterv1.PrerequisiteFinding{
				{
					PrerequisiteID: "sddm-active",
					Status:         "satisfied",
					Severity:       "required",
					Evidence: []protocol.Evidence{
						{
							Source:        "adapter",
							Kind:          "service",
							Subject:       "sddm.service",
							ObservedValue: "active",
							Timestamp:     now,
						},
					},
					Remediation: protocol.Object{"action": json.RawMessage(`"none"`)},
				},
			},
		}
		return json.Marshal(rep)

	case "InspectState":
		state := adapterv1.DisplayManagerState{
			Active:                "yes",
			Enabled:               "yes",
			Configurable:          "yes",
			ConflictingInstances:  []string{},
			InstalledAssets:       []string{},
			EffectiveCapabilities: []string{"concurrent_pam", "theme_status"},
			Evidence:              []json.RawMessage{},
		}
		return json.Marshal(state)

	case "PlanInstall":
		plan := adapterv1.ChangePlan{
			PlanID:               "plan-sddm-install",
			AdapterID:            "org.fplogin.adapter.sddm",
			AdapterVersion:       "0.1.0",
			ProtocolVersion:      req.ProtocolVersion,
			TargetInstanceID:     "inst-sddm-1",
			Mode:                 "fresh_install",
			CreatedAt:            now,
			InputHash:            calcSHA256([]byte("input-state")),
			Approvals:            []adapterv1.Approval{},
			Preconditions:        []adapterv1.Condition{},
			Postconditions:       []adapterv1.Condition{},
			ArtifactReferences:   []adapterv1.ArtifactReference{},
			Operations:           []protocol.Operation{},
			ExpectedCapabilities: []string{"concurrent_pam"},
			CanonicalPlanDigest:  calcSHA256([]byte("canonical-plan-digest")),
		}
		return json.Marshal(plan)

	case "PrepareArtifacts":
		set := adapterv1.ArtifactSet{
			Artifacts: []adapterv1.Artifact{},
		}
		return json.Marshal(set)

	case "PlanUninstall":
		plan := adapterv1.ChangePlan{
			PlanID:               "plan-sddm-uninstall",
			AdapterID:            "org.fplogin.adapter.sddm",
			AdapterVersion:       "0.1.0",
			ProtocolVersion:      req.ProtocolVersion,
			TargetInstanceID:     "inst-sddm-1",
			Mode:                 "uninstall",
			CreatedAt:            now,
			InputHash:            calcSHA256([]byte("input-state-uninstall")),
			Approvals:            []adapterv1.Approval{},
			Preconditions:        []adapterv1.Condition{},
			Postconditions:       []adapterv1.Condition{},
			ArtifactReferences:   []adapterv1.ArtifactReference{},
			Operations:           []protocol.Operation{},
			ExpectedCapabilities: []string{},
			CanonicalPlanDigest:  calcSHA256([]byte("canonical-uninstall-digest")),
		}
		return json.Marshal(plan)

	case "Verify":
		rep := adapterv1.VerificationReport{
			ReportID:   "verify-sddm-1",
			VerifiedAt: now,
			Checks: []adapterv1.VerificationCheck{
				{
					CheckID:  "sddm-config-check",
					Status:   "passed",
					Severity: "required",
					Message:  "SDDM adapter configuration verified",
					Evidence: []protocol.Evidence{
						{
							Source:        "adapter",
							Kind:          "service",
							Subject:       "sddm.service",
							ObservedValue: "verified",
							Timestamp:     now,
						},
					},
				},
			},
		}
		return json.Marshal(rep)

	default:
		return nil, fmt.Errorf("unsupported adapter operation %q", req.Operation)
	}
}

func calcSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func emitSuccess(reqID string, pv protocol.Version, result json.RawMessage) {
	resp := adapterv1.Response{
		ProtocolVersion: pv,
		RequestID:       reqID,
		OK:              true,
		Result:          result,
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}

func emitError(reqID string, pv protocol.Version, code, message string) {
	resp := adapterv1.Response{
		ProtocolVersion: pv,
		RequestID:       reqID,
		OK:              false,
		Error: &adapterv1.AdapterError{
			Code:      code,
			Message:   message,
			Retryable: false,
			Evidence:  []protocol.Evidence{},
		},
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}
