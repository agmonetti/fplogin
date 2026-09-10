// Package v1 implements the Go representation and validation boundary for the
// platform-provider v1 JSON protocol.
package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"fplogin/internal/protocol"
)

const DescriptorSchemaVersion = "1.0"

type Descriptor struct {
	DescriptorSchemaVersion string                   `json:"descriptor_schema_version"`
	PlatformID              string                   `json:"platform_id"`
	PlatformVersion         string                   `json:"platform_version"`
	ProtocolVersions        []protocol.Version       `json:"protocol_versions"`
	MinimumCoreVersion      string                   `json:"minimum_core_version"`
	Name                    string                   `json:"name"`
	Vendor                  string                   `json:"vendor"`
	Executable              string                   `json:"executable"`
	SupportedPlatforms      []SupportedPlatform      `json:"supported_platforms"`
	Capabilities            []protocol.Capability    `json:"capabilities"`
	OperationKinds          []protocol.OperationKind `json:"operation_kinds"`
	PackageFormats          []string                 `json:"package_formats"`
	ServiceManager          ServiceManager           `json:"service_manager"`
	AssetRoot               string                   `json:"asset_root"`
}

type SupportedPlatform struct {
	Distribution      string `json:"distribution"`
	Architecture      string `json:"architecture"`
	VersionConstraint string `json:"version_constraint,omitempty"`
}

type ServiceManager struct {
	Kind         string   `json:"kind"`
	Capabilities []string `json:"capabilities"`
}

func DecodeDescriptor(data []byte) (Descriptor, error) {
	var descriptor Descriptor
	err := protocol.DecodeStrict(data, &descriptor,
		"descriptor_schema_version", "platform_id", "platform_version", "protocol_versions",
		"minimum_core_version", "name", "vendor", "executable", "supported_platforms",
		"capabilities", "operation_kinds", "package_formats", "service_manager", "asset_root")
	if err == nil {
		err = descriptor.Validate()
	}
	return descriptor, err
}

func (d Descriptor) Validate() error {
	if d.DescriptorSchemaVersion != DescriptorSchemaVersion {
		return fmt.Errorf("unsupported descriptor schema version %q", d.DescriptorSchemaVersion)
	}
	if err := protocol.ValidOpaqueID(d.PlatformID); err != nil {
		return err
	}
	if d.PlatformVersion == "" || d.MinimumCoreVersion == "" || d.Name == "" || d.Vendor == "" {
		return errors.New("platform version, minimum core version, name, and vendor are required")
	}
	if err := protocol.ValidRelativePath(d.Executable); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if err := protocol.ValidRelativePath(d.AssetRoot); err != nil {
		return fmt.Errorf("asset_root: %w", err)
	}
	if len(d.ProtocolVersions) == 0 || len(d.SupportedPlatforms) == 0 || len(d.Capabilities) == 0 || len(d.OperationKinds) == 0 {
		return errors.New("platform descriptor lists must not be empty")
	}
	for _, version := range d.ProtocolVersions {
		if err := version.Validate(); err != nil {
			return err
		}
	}
	for _, candidate := range d.SupportedPlatforms {
		if candidate.Distribution == "" || candidate.Architecture == "" {
			return errors.New("supported platform fields are required")
		}
	}
	for _, capability := range d.Capabilities {
		if err := capability.Validate(); err != nil {
			return err
		}
	}
	seenKinds := make(map[protocol.OperationKind]struct{}, len(d.OperationKinds))
	for _, kind := range d.OperationKinds {
		if err := kind.Validate(); err != nil {
			return err
		}
		if _, exists := seenKinds[kind]; exists {
			return fmt.Errorf("duplicate operation kind %q", kind)
		}
		seenKinds[kind] = struct{}{}
	}
	if d.PackageFormats == nil || d.ServiceManager.Kind == "" || d.ServiceManager.Capabilities == nil {
		return errors.New("package formats and service manager are required")
	}
	return nil
}

type Request struct {
	ProtocolVersion protocol.Version     `json:"protocol_version"`
	RequestID       string               `json:"request_id"`
	Operation       string               `json:"operation"`
	CoreVersion     string               `json:"core_version"`
	Context         protocol.HostContext `json:"context"`
	Payload         json.RawMessage      `json:"payload"`
}

func DecodeRequest(data []byte) (Request, error) {
	var request Request
	err := protocol.DecodeStrict(data, &request, "protocol_version", "request_id", "operation", "core_version", "context", "payload")
	if err == nil {
		err = request.Validate()
	}
	return request, err
}

func (r Request) Validate() error {
	if err := r.ProtocolVersion.Validate(); err != nil {
		return err
	}
	if err := protocol.ValidRequestID(r.RequestID); err != nil {
		return err
	}
	if r.CoreVersion == "" {
		return errors.New("core_version is required")
	}
	if !protocol.OneOf(r.Operation, "Describe", "InspectHost", "ListPackageCandidates", "ListServiceCandidates", "CollectAnalyzerFacts", "PrepareArtifactInstall", "ApplyOperation", "VerifyOperation") {
		return fmt.Errorf("unknown platform operation %q", r.Operation)
	}
	if err := r.Context.Validate(); err != nil {
		return fmt.Errorf("context: %w", err)
	}
	return validatePayload(r.Operation, r.Payload)
}

type ProtocolRange struct {
	MinMajor int `json:"min_major"`
	MaxMajor int `json:"max_major"`
}
type DescribePayload struct {
	SupportedProtocolRange *ProtocolRange `json:"supported_protocol_range,omitempty"`
}
type InspectHostPayload struct {
	RequestedFactClasses []string `json:"requested_fact_classes,omitempty"`
}
type ListPackageCandidatesPayload struct {
	Predicates   []string `json:"predicates,omitempty"`
	PackageHints []string `json:"package_hints,omitempty"`
}
type ListServiceCandidatesPayload struct {
	Aliases           []string `json:"aliases,omitempty"`
	CapabilityQueries []string `json:"capability_queries,omitempty"`
}
type CollectAnalyzerFactsPayload struct {
	Scope         string          `json:"scope"`
	TargetContext protocol.Object `json:"target_context,omitempty"`
	ProbeIDs      []string        `json:"probe_ids"`
	Deadline      string          `json:"deadline,omitempty"`
}

type ArtifactReference struct {
	ArtifactID    string `json:"artifact_id"`
	MediaType     string `json:"media_type"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	CanonicalPath string `json:"canonical_path,omitempty"`
	Role          string `json:"role,omitempty"`
}

func (a *ArtifactReference) UnmarshalJSON(data []byte) error {
	type wire ArtifactReference
	var decoded wire
	if err := protocol.DecodeStrict(data, &decoded, "artifact_id", "media_type", "sha256", "size"); err != nil {
		return err
	}
	*a = ArtifactReference(decoded)
	return nil
}

type StagingHandoff struct {
	Workspace   string `json:"workspace"`
	SourceCache string `json:"source_cache"`
}
type PrepareArtifactInstallPayload struct {
	SelectedCapabilities []string            `json:"selected_capabilities"`
	PlanDigest           string              `json:"plan_digest"`
	ArtifactReferences   []ArtifactReference `json:"artifact_references"`
	OperationIDs         []string            `json:"operation_ids"`
	StagingHandoff       StagingHandoff      `json:"staging_handoff"`
}
type ApplyOperationPayload struct {
	Operation                 protocol.Operation `json:"operation"`
	PlanDigest                string             `json:"plan_digest"`
	PreparedArtifactReference json.RawMessage    `json:"prepared_artifact_reference,omitempty"`
}
type VerifyOperationPayload struct {
	OperationID           string          `json:"operation_id"`
	PlanDigest            string          `json:"plan_digest"`
	ExpectedPostcondition protocol.Object `json:"expected_postcondition"`
	Phase                 string          `json:"phase"`
}

func validatePayload(operation string, raw json.RawMessage) error {
	var err error
	switch operation {
	case "Describe":
		var p DescribePayload
		err = protocol.DecodeStrict(raw, &p)
		if err == nil && p.SupportedProtocolRange != nil && (p.SupportedProtocolRange.MinMajor < 1 || p.SupportedProtocolRange.MaxMajor < p.SupportedProtocolRange.MinMajor) {
			err = errors.New("invalid supported protocol range")
		}
	case "InspectHost":
		var p InspectHostPayload
		err = protocol.DecodeStrict(raw, &p)
	case "ListPackageCandidates":
		var p ListPackageCandidatesPayload
		err = protocol.DecodeStrict(raw, &p)
	case "ListServiceCandidates":
		var p ListServiceCandidatesPayload
		err = protocol.DecodeStrict(raw, &p)
	case "CollectAnalyzerFacts":
		var p CollectAnalyzerFactsPayload
		err = protocol.DecodeStrict(raw, &p, "scope", "probe_ids")
		if err == nil && (p.Scope == "" || p.ProbeIDs == nil) {
			err = errors.New("analyzer scope and probe IDs are required")
		}
		if err == nil && p.Deadline != "" {
			err = protocol.ValidTimestamp(p.Deadline)
		}
	case "PrepareArtifactInstall":
		var p PrepareArtifactInstallPayload
		err = protocol.DecodeStrict(raw, &p, "selected_capabilities", "plan_digest", "artifact_references", "operation_ids", "staging_handoff")
		if err == nil {
			err = validateArtifactPreparation(p)
		}
	case "ApplyOperation":
		var p ApplyOperationPayload
		err = protocol.DecodeStrict(raw, &p, "operation", "plan_digest")
		if err == nil {
			err = protocol.ValidDigest(p.PlanDigest)
		}
		if err == nil {
			err = p.Operation.Validate()
		}
	case "VerifyOperation":
		var p VerifyOperationPayload
		err = protocol.DecodeStrict(raw, &p, "operation_id", "plan_digest", "expected_postcondition", "phase")
		if err == nil && (p.OperationID == "" || p.ExpectedPostcondition == nil || !protocol.OneOf(p.Phase, "pre_apply", "post_install", "post_rollback", "post_uninstall")) {
			err = errors.New("invalid operation verification fields")
		}
		if err == nil {
			err = protocol.ValidDigest(p.PlanDigest)
		}
	}
	if err != nil {
		return fmt.Errorf("%s payload: %w", operation, err)
	}
	return nil
}

func validateArtifactPreparation(p PrepareArtifactInstallPayload) error {
	if p.SelectedCapabilities == nil || p.ArtifactReferences == nil || p.OperationIDs == nil {
		return errors.New("artifact preparation lists are required")
	}
	if err := protocol.ValidDigest(p.PlanDigest); err != nil {
		return err
	}
	if p.StagingHandoff.Workspace == "" || p.StagingHandoff.SourceCache == "" || !filepath.IsAbs(p.StagingHandoff.Workspace) || !filepath.IsAbs(p.StagingHandoff.SourceCache) || filepath.Clean(p.StagingHandoff.Workspace) != p.StagingHandoff.Workspace || filepath.Clean(p.StagingHandoff.SourceCache) != p.StagingHandoff.SourceCache {
		return errors.New("staging paths must be canonical and absolute")
	}
	workspace := p.StagingHandoff.Workspace
	for _, artifact := range p.ArtifactReferences {
		if artifact.ArtifactID == "" || artifact.MediaType == "" || artifact.Size < 0 {
			return errors.New("invalid artifact reference")
		}
		if err := protocol.ValidDigest(artifact.SHA256); err != nil {
			return err
		}
		if artifact.CanonicalPath != "" {
			clean := filepath.Clean(artifact.CanonicalPath)
			rel, err := filepath.Rel(workspace, clean)
			if err != nil || clean != artifact.CanonicalPath || rel == ".." || filepath.IsAbs(rel) || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
				return fmt.Errorf("artifact %q escapes staging workspace", artifact.ArtifactID)
			}
		}
	}
	return nil
}

type Response struct {
	ProtocolVersion protocol.Version `json:"protocol_version"`
	RequestID       string           `json:"request_id"`
	OK              bool             `json:"ok"`
	Result          json.RawMessage  `json:"result,omitempty"`
	Error           *PlatformError   `json:"error,omitempty"`
}
type PlatformError struct {
	Code      string              `json:"code"`
	Message   string              `json:"message"`
	Retryable bool                `json:"retryable"`
	Evidence  []protocol.Evidence `json:"evidence"`
	Details   protocol.Object     `json:"details,omitempty"`
}

func (e *PlatformError) UnmarshalJSON(data []byte) error {
	type wire PlatformError
	var decoded wire
	if err := protocol.DecodeStrict(data, &decoded, "code", "message", "retryable", "evidence"); err != nil {
		return err
	}
	*e = PlatformError(decoded)
	return nil
}

func DecodeResponse(data []byte) (Response, error) {
	var response Response
	err := protocol.DecodeStrict(data, &response, "protocol_version", "request_id", "ok")
	if err == nil {
		err = response.Validate()
	}
	return response, err
}
func (r Response) Validate() error {
	if err := r.ProtocolVersion.Validate(); err != nil {
		return err
	}
	if err := protocol.ValidRequestID(r.RequestID); err != nil {
		return err
	}
	if r.OK {
		if len(r.Result) == 0 || string(r.Result) == "null" || r.Error != nil {
			return errors.New("successful response requires a result and no error")
		}
		var result protocol.Object
		if err := json.Unmarshal(r.Result, &result); err != nil || result == nil {
			return errors.New("result must be an object")
		}
		return nil
	}
	if len(r.Result) != 0 && string(r.Result) != "null" {
		return errors.New("failed response result must be null")
	}
	if r.Error == nil {
		return errors.New("failed response requires an error")
	}
	return r.Error.Validate()
}
func (e PlatformError) Validate() error {
	if !protocol.OneOf(e.Code, "invalid_request", "protocol_mismatch", "unsupported_platform", "unsupported_operation", "timeout", "host_read_failed", "artifact_failed", "mutation_failed", "internal_error") || e.Message == "" || e.Evidence == nil {
		return errors.New("invalid platform error")
	}
	for _, evidence := range e.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Result representations are operation-specific objects carried by Response.Result.
type PlatformHostReport struct {
	Platform         protocol.Object     `json:"platform"`
	Architecture     string              `json:"architecture"`
	PackageManager   json.RawMessage     `json:"package_manager"`
	ServiceManager   json.RawMessage     `json:"service_manager"`
	FilesystemPolicy protocol.Object     `json:"filesystem_policy"`
	Packages         []PackageCandidate  `json:"packages"`
	Services         []ServiceCandidate  `json:"services"`
	Evidence         []protocol.Evidence `json:"evidence"`
}
type PackageCandidate struct {
	PackageReference     string              `json:"package_reference"`
	DisplayName          string              `json:"display_name"`
	Version              json.RawMessage     `json:"version"`
	Installed            string              `json:"installed"`
	ProvidedCapabilities []string            `json:"provided_capabilities"`
	Evidence             []protocol.Evidence `json:"evidence"`
}
type ServiceCandidate struct {
	ServiceReference  string              `json:"service_reference"`
	Active            string              `json:"active"`
	Enabled           string              `json:"enabled"`
	Configurable      string              `json:"configurable"`
	PackageReferences []string            `json:"package_references"`
	Evidence          []protocol.Evidence `json:"evidence"`
}
type PlatformAnalyzerFacts struct {
	Scope       string              `json:"scope"`
	CollectedAt string              `json:"collected_at"`
	Evidence    []protocol.Evidence `json:"evidence"`
	ProbeErrors []ProbeError        `json:"probe_errors"`
}
type ProbeError struct {
	ProbeID  string              `json:"probe_id"`
	Message  string              `json:"message"`
	Evidence []protocol.Evidence `json:"evidence,omitempty"`
}
type PreparedArtifactReference struct {
	ArtifactID          string          `json:"artifact_id"`
	ProviderReference   string          `json:"provider_reference"`
	MediaType           string          `json:"media_type"`
	SHA256              string          `json:"sha256"`
	Size                int64           `json:"size"`
	PackageOwnership    protocol.Object `json:"package_ownership,omitempty"`
	OperationParameters protocol.Object `json:"operation_parameters"`
}
type ArtifactInstallPreparation struct {
	References []PreparedArtifactReference `json:"references"`
}
type OperationReceipt struct {
	OperationID  string                 `json:"operation_id"`
	Kind         protocol.OperationKind `json:"kind"`
	StartedAt    string                 `json:"started_at"`
	CompletedAt  string                 `json:"completed_at"`
	Status       string                 `json:"status"`
	BeforeState  protocol.Object        `json:"before_state"`
	AfterState   protocol.Object        `json:"after_state"`
	Evidence     []protocol.Evidence    `json:"evidence,omitempty"`
	Compensation protocol.Object        `json:"compensation"`
	Error        json.RawMessage        `json:"error,omitempty"`
}
type VerificationCheck struct {
	CheckID  string              `json:"check_id"`
	Status   string              `json:"status"`
	Severity string              `json:"severity"`
	Evidence []protocol.Evidence `json:"evidence"`
	Message  string              `json:"message,omitempty"`
}
type PlatformVerificationReport struct {
	ReportID   string              `json:"report_id"`
	VerifiedAt string              `json:"verified_at"`
	Checks     []VerificationCheck `json:"checks"`
}

func (f PlatformAnalyzerFacts) Validate() error {
	if f.Scope == "" || f.Evidence == nil || f.ProbeErrors == nil {
		return errors.New("analyzer facts scope, evidence, and probe errors are required")
	}
	if err := protocol.ValidTimestamp(f.CollectedAt); err != nil {
		return err
	}
	for _, evidence := range f.Evidence {
		if evidence.Source != "platform" {
			return errors.New("platform analyzer evidence must retain platform source")
		}
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r OperationReceipt) Validate() error {
	if r.OperationID == "" || r.BeforeState == nil || r.AfterState == nil || r.Compensation == nil || !protocol.OneOf(r.Status, "success", "failed", "rolled_back", "rollback_failed") {
		return errors.New("invalid operation receipt")
	}
	if err := r.Kind.Validate(); err != nil {
		return err
	}
	if err := protocol.ValidTimestamp(r.StartedAt); err != nil {
		return err
	}
	return protocol.ValidTimestamp(r.CompletedAt)
}
