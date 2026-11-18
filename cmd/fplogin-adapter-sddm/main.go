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
  "protocol_versions": [
    {
      "major": 1,
      "minor": 0
    }
  ],
  "minimum_core_version": "0.1.0",
  "name": "SDDM Biometric Login Adapter",
  "vendor": "fplogin",
  "executable": "bin/fplogin-adapter-sddm",
  "supported_display_managers": [
    {
      "dm_id": "sddm",
      "name": "Simple Desktop Display Manager",
      "version_policy": "0.21.0",
      "target_aliases": [
        "sddm.service",
        "display-manager.service"
      ]
    }
  ],
  "integration_strategies": [
    "source_patch",
    "configuration"
  ],
  "capabilities": [
    {
      "id": "install.preview",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "package_inventory",
        "service_inventory"
      ]
    }
  ],
  "prerequisites": [
    {
      "id": "package.fprintd",
      "kind": "package",
      "required": true,
      "reason": "Biometric authentication requires fprintd",
      "remediation_policy": "Install fprintd if missing"
    },
    {
      "id": "hardware.fingerprint_reader",
      "kind": "hardware",
      "required": true,
      "reason": "Supported fingerprint sensor must be present",
      "remediation_policy": "Connect compatible fingerprint sensor"
    }
  ],
  "supported_platforms": [
    "arch"
  ],
  "packaging_backends": [
    "arch"
  ],
  "operation_modes": [
    "fresh_install"
  ],
  "asset_root": "assets"
}`

func handleRequest(req adapterv1.Request) (json.RawMessage, error) {
	switch req.Operation {
	case "Describe":
		return json.RawMessage(staticAdapterDescriptor), nil
	case "Detect", "CheckPrerequisites", "InspectState", "PlanInstall":
		return preflight(req)
	case "PrepareArtifacts", "PlanUninstall", "Verify":
		// Fail closed: no fabricated detection, prerequisite, plan or
		// verification result may be reported before a verified implementation.
		return nil, fmt.Errorf("adapter operation %q is not implemented (fail-closed; no display-manager state was read or changed)", req.Operation)
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
