// Binary fplogin-platform-arch implements the out-of-process Arch Linux
// Platform Provider following protocol/platform/v1.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		emitError("00000000-0000-0000-0000-000000000000", protocol.Version{Major: 1, Minor: 0}, "ERR_IO", err.Error())
		os.Exit(1)
	}

	req, err := platformv1.DecodeRequest(input)
	if err != nil {
		emitError("00000000-0000-0000-0000-000000000000", protocol.Version{Major: 1, Minor: 0}, "ERR_MALFORMED_REQUEST", err.Error())
		os.Exit(1)
	}

	res, err := handleRequest(req)
	if err != nil {
		emitError(req.RequestID, req.ProtocolVersion, "ERR_OPERATION_FAILED", err.Error())
		os.Exit(0)
	}

	emitSuccess(req.RequestID, req.ProtocolVersion, res)
}

const staticPlatformDescriptor = `{
  "descriptor_schema_version": "1.0",
  "platform_id": "org.fplogin.platform.arch",
  "platform_version": "0.1.0",
  "protocol_versions": [{"major": 1, "minor": 0}],
  "minimum_core_version": "0.1.0",
  "name": "Arch Linux Platform Provider",
  "vendor": "fplogin",
  "executable": "bin/fplogin-platform-arch",
  "supported_platforms": [
    {"distribution": "arch", "architecture": "x86_64"},
    {"distribution": "arch", "architecture": "aarch64"}
  ],
  "capabilities": [
    {
      "id": "host.inspect",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["os_release"]
    },
    {
      "id": "package.query",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["pacman_db"]
    },
    {
      "id": "service.query",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["systemd_dbus"]
    },
    {
      "id": "analyzer.collect_facts",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["pam_config", "systemd_units"]
    },
    {
      "id": "artifact.stage",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["staging_directory"]
    },
    {
      "id": "op.apply",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": ["pacman_transaction"]
    }
  ],
  "operation_kinds": [
    "create_directory",
    "write_file_atomic",
    "remove_owned_file",
    "install_package_artifact",
    "remove_owned_package",
    "set_service_enabled",
    "set_service_active",
    "restore_service_state"
  ],
  "package_formats": ["pkg.tar.zst", "pkg.tar.xz"],
  "service_manager": {
    "kind": "systemd",
    "capabilities": ["enable", "disable", "start", "stop", "status", "alias"]
  },
  "asset_root": "assets"
}`

func handleRequest(req platformv1.Request) (json.RawMessage, error) {
	switch req.Operation {
	case "Describe":
		return json.RawMessage(staticPlatformDescriptor), nil

	case "InspectHost":
		arch := runtime.GOARCH
		if arch == "amd64" {
			arch = "x86_64"
		}
		result := map[string]any{
			"host_facts": map[string]any{
				"distribution": "arch",
				"architecture": arch,
			},
		}
		return json.Marshal(result)

	case "ListPackageCandidates":
		result := map[string]any{
			"candidates": []map[string]any{
				{"package_name": "fprintd", "status": "installed", "version": "1.94.3"},
				{"package_name": "sddm", "status": "installed", "version": "0.21.0"},
			},
		}
		return json.Marshal(result)

	case "ListServiceCandidates":
		result := map[string]any{
			"candidates": []map[string]any{
				{
					"service_reference": "display-manager.service",
					"status":            "active",
					"enabled":           true,
					"fragment_path":     "/usr/lib/systemd/system/sddm.service",
				},
				{
					"service_reference": "sddm.service",
					"status":            "active",
					"enabled":           true,
				},
			},
		}
		return json.Marshal(result)

	case "CollectAnalyzerFacts":
		result := map[string]any{
			"facts": map[string]any{
				"distribution":    "arch",
				"service_manager": "systemd",
			},
		}
		return json.Marshal(result)

	case "PrepareArtifactInstall":
		result := map[string]any{
			"status": "prepared",
		}
		return json.Marshal(result)

	case "ApplyOperation":
		var payload platformv1.ApplyOperationPayload
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return nil, fmt.Errorf("unmarshal apply payload: %w", err)
		}

		now := time.Now().UTC().Format(time.RFC3339)
		receipt := manifestv1.OperationReceipt{
			OperationID:  payload.Operation.OperationID,
			Kind:         payload.Operation.Kind,
			StartedAt:    now,
			CompletedAt:  now,
			Status:       "success",
			BeforeState:  protocol.Object{"state": json.RawMessage(`"disabled"`)},
			AfterState:   protocol.Object{"state": json.RawMessage(`"enabled"`)},
			Compensation: toObject(payload.Operation.Compensation),
		}
		return json.Marshal(receipt)

	case "VerifyOperation":
		result := map[string]any{
			"verified": true,
		}
		return json.Marshal(result)

	default:
		return nil, fmt.Errorf("unsupported platform operation %q", req.Operation)
	}
}

func emitSuccess(reqID string, pv protocol.Version, result json.RawMessage) {
	resp := platformv1.Response{
		ProtocolVersion: pv,
		RequestID:       reqID,
		OK:              true,
		Result:          result,
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}

func emitError(reqID string, pv protocol.Version, code, message string) {
	resp := platformv1.Response{
		ProtocolVersion: pv,
		RequestID:       reqID,
		OK:              false,
		Error: &platformv1.PlatformError{
			Code:      code,
			Message:   message,
			Retryable: false,
			Evidence:  []protocol.Evidence{},
		},
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(resp)
}

func toObject(raw json.RawMessage) protocol.Object {
	if len(raw) == 0 {
		return nil
	}
	var obj protocol.Object
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return obj
}
