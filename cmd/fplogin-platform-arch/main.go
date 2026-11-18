// Binary fplogin-platform-arch implements the out-of-process Arch Linux
// Platform Provider following protocol/platform/v1.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"fplogin/internal/protocol"
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
		code := "internal_error"
		var known *opError
		if errors.As(err, &known) {
			code = known.code
		}
		emitError(req.RequestID, req.ProtocolVersion, code, err.Error())
		os.Exit(0)
	}

	emitSuccess(req.RequestID, req.ProtocolVersion, res)
}

const staticPlatformDescriptor = `{
  "descriptor_schema_version": "1.0",
  "platform_id": "org.fplogin.platform.arch",
  "platform_version": "0.1.0",
  "protocol_versions": [
    {
      "major": 1,
      "minor": 0
    }
  ],
  "minimum_core_version": "0.1.0",
  "name": "Arch Linux Platform Provider",
  "vendor": "fplogin",
  "executable": "bin/fplogin-platform-arch",
  "supported_platforms": [
    {
      "distribution": "arch",
      "architecture": "x86_64"
    },
    {
      "distribution": "arch",
      "architecture": "aarch64"
    }
  ],
  "capabilities": [
    {
      "id": "host.inspect",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "os_release"
      ]
    },
    {
      "id": "package.query",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "pacman_db"
      ]
    },
    {
      "id": "service.query",
      "status": "provided",
      "level": 1,
      "constraints": {},
      "evidence_requirements": [
        "systemd_dbus"
      ]
    }
  ],
  "operation_kinds": [],
  "package_formats": [
    "pkg.tar.zst",
    "pkg.tar.xz"
  ],
  "service_manager": {
    "kind": "systemd",
    "capabilities": [
      "status",
      "alias"
    ]
  },
  "asset_root": "assets"
}`

// opError carries a contract error code (contracts/platform/v1/response.schema.json).
type opError struct {
	code    string
	message string
}

func (e *opError) Error() string { return e.message }

// notImplemented fails closed: an operation without a verified host
// implementation must never report fabricated host state or success.
func notImplemented(operation string) error {
	return &opError{code: "unsupported_operation",
		message: fmt.Sprintf("operation %q is not implemented by this platform provider (fail-closed; no host state was read or changed)", operation)}
}

// osReleaseID reads the distribution ID from os-release without executing anything.
func osReleaseID(paths ...string) (string, error) {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ID="); ok {
				return strings.Trim(value, `"'`), nil
			}
		}
		return "", fmt.Errorf("%s has no ID field", path)
	}
	return "", fmt.Errorf("os-release not readable")
}

func handleRequest(req platformv1.Request) (json.RawMessage, error) {
	switch req.Operation {
	case "Describe":
		return json.RawMessage(staticPlatformDescriptor), nil

	case "InspectHost":
		report, err := inspectHost()
		if err != nil {
			return nil, &opError{code: "host_read_failed", message: err.Error()}
		}
		return json.Marshal(report)

	case "ListPackageCandidates", "ListServiceCandidates":
		result, err := preflightQuery(req)
		if err != nil {
			return nil, &opError{code: "host_read_failed", message: err.Error()}
		}
		return result, nil

	case "CollectAnalyzerFacts",
		"PrepareArtifactInstall", "ApplyOperation", "VerifyOperation":
		return nil, notImplemented(req.Operation)

	default:
		return nil, &opError{code: "unsupported_operation", message: fmt.Sprintf("unknown platform operation %q", req.Operation)}
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
