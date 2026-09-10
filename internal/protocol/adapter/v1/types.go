// Package v1 implements the Go representation and validation boundary for the
// adapter v1 JSON protocol.
package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"fplogin/internal/protocol"
)

const DescriptorSchemaVersion = "1.0"

type Descriptor struct {
	DescriptorSchemaVersion  string                    `json:"descriptor_schema_version"`
	AdapterID                string                    `json:"adapter_id"`
	AdapterVersion           string                    `json:"adapter_version"`
	ProtocolVersions         []protocol.Version        `json:"protocol_versions"`
	MinimumCoreVersion       string                    `json:"minimum_core_version"`
	Name                     string                    `json:"name"`
	Vendor                   string                    `json:"vendor"`
	Executable               string                    `json:"executable"`
	SupportedDisplayManagers []SupportedDisplayManager `json:"supported_display_managers"`
	IntegrationStrategies    []string                  `json:"integration_strategies"`
	Capabilities             []protocol.Capability     `json:"capabilities"`
	Prerequisites            []PrerequisiteDeclaration `json:"prerequisites"`
	SupportedPlatforms       []string                  `json:"supported_platforms"`
	PackagingBackends        []string                  `json:"packaging_backends,omitempty"`
	OperationModes           []string                  `json:"operation_modes"`
	AssetRoot                string                    `json:"asset_root"`
}

type SupportedDisplayManager struct {
	DMID          string   `json:"dm_id"`
	Name          string   `json:"name"`
	VersionPolicy string   `json:"version_policy"`
	TargetAliases []string `json:"target_aliases"`
}

type PrerequisiteDeclaration struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Required          bool   `json:"required"`
	Reason            string `json:"reason"`
	RemediationPolicy string `json:"remediation_policy"`
}

func (p *PrerequisiteDeclaration) UnmarshalJSON(data []byte) error {
	type wire PrerequisiteDeclaration
	var decoded wire
	if err := protocol.DecodeStrict(data, &decoded, "id", "kind", "required", "reason", "remediation_policy"); err != nil {
		return err
	}
	*p = PrerequisiteDeclaration(decoded)
	return nil
}

func DecodeDescriptor(data []byte) (Descriptor, error) {
	var descriptor Descriptor
	err := protocol.DecodeStrict(data, &descriptor,
		"descriptor_schema_version", "adapter_id", "adapter_version", "protocol_versions",
		"minimum_core_version", "name", "vendor", "executable", "supported_display_managers",
		"integration_strategies", "capabilities", "prerequisites", "supported_platforms",
		"operation_modes", "asset_root")
	if err == nil {
		err = descriptor.Validate()
	}
	return descriptor, err
}

func (d Descriptor) Validate() error {
	if d.DescriptorSchemaVersion != DescriptorSchemaVersion {
		return fmt.Errorf("unsupported descriptor schema version %q", d.DescriptorSchemaVersion)
	}
	if err := protocol.ValidOpaqueID(d.AdapterID); err != nil {
		return err
	}
	if d.AdapterVersion == "" || d.MinimumCoreVersion == "" || d.Name == "" || d.Vendor == "" {
		return errors.New("adapter version, minimum core version, name, and vendor are required")
	}
	if err := protocol.ValidRelativePath(d.Executable); err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	if err := protocol.ValidRelativePath(d.AssetRoot); err != nil {
		return fmt.Errorf("asset_root: %w", err)
	}
	if len(d.ProtocolVersions) == 0 || len(d.SupportedDisplayManagers) == 0 || len(d.IntegrationStrategies) == 0 || len(d.Capabilities) == 0 || len(d.OperationModes) == 0 {
		return errors.New("adapter descriptor lists must not be empty")
	}
	for _, version := range d.ProtocolVersions {
		if err := version.Validate(); err != nil {
			return err
		}
	}
	for _, manager := range d.SupportedDisplayManagers {
		if manager.DMID == "" || manager.Name == "" || manager.VersionPolicy == "" || manager.TargetAliases == nil || !regexp.MustCompile(`^[a-z0-9_-]+$`).MatchString(manager.DMID) {
			return fmt.Errorf("invalid supported display manager %q", manager.DMID)
		}
	}
	for _, strategy := range d.IntegrationStrategies {
		if !protocol.OneOf(strategy, "native", "source_patch", "configuration", "plugin") {
			return fmt.Errorf("invalid integration strategy %q", strategy)
		}
	}
	for _, capability := range d.Capabilities {
		if err := capability.Validate(); err != nil {
			return err
		}
	}
	for _, prerequisite := range d.Prerequisites {
		if prerequisite.ID == "" || prerequisite.Kind == "" || prerequisite.Reason == "" || prerequisite.RemediationPolicy == "" {
			return errors.New("prerequisite fields must not be empty")
		}
	}
	for _, mode := range d.OperationModes {
		if !validMode(mode, true) {
			return fmt.Errorf("invalid operation mode %q", mode)
		}
	}
	return nil
}

type DisplayManagerCandidate struct {
	CandidateID string            `json:"candidate_id"`
	DisplayName string            `json:"display_name"`
	ServiceName string            `json:"service_name"`
	PackageName string            `json:"package_name,omitempty"`
	Evidence    []json.RawMessage `json:"evidence,omitempty"`
}

func (c DisplayManagerCandidate) Validate() error {
	if c.CandidateID == "" || c.DisplayName == "" || c.ServiceName == "" {
		return errors.New("display manager candidate identity is required")
	}
	return nil
}

type DetectedTarget struct {
	InstanceID        string            `json:"instance_id"`
	DMID              string            `json:"dm_id"`
	DisplayName       string            `json:"display_name"`
	UpstreamVersion   string            `json:"upstream_version,omitempty"`
	PackageReferences []string          `json:"package_references,omitempty"`
	ServiceReferences []string          `json:"service_references,omitempty"`
	Compatibility     string            `json:"compatibility"`
	Confidence        string            `json:"confidence"`
	Evidence          []json.RawMessage `json:"evidence"`
}

func (t DetectedTarget) Validate() error {
	if t.InstanceID == "" || t.DMID == "" || t.DisplayName == "" || t.Evidence == nil {
		return errors.New("target identity and evidence are required")
	}
	if !protocol.OneOf(t.Compatibility, "compatible", "incompatible", "unknown") || !protocol.OneOf(t.Confidence, "confirmed", "likely", "unknown") {
		return errors.New("invalid target compatibility or confidence")
	}
	return nil
}

type DisplayManagerState struct {
	Active                string            `json:"active"`
	Enabled               string            `json:"enabled"`
	Configurable          string            `json:"configurable"`
	ConflictingInstances  []string          `json:"conflicting_instances,omitempty"`
	InstalledAssets       []string          `json:"installed_assets,omitempty"`
	EffectiveCapabilities []string          `json:"effective_capabilities,omitempty"`
	Evidence              []json.RawMessage `json:"evidence,omitempty"`
}

func (s DisplayManagerState) Validate() error {
	if !triState(s.Active) || !triState(s.Enabled) || !triState(s.Configurable) {
		return errors.New("display manager state must use yes, no, or unknown")
	}
	return nil
}

type DetectionReport struct {
	Targets []DetectedTarget `json:"targets"`
}

type PrerequisiteFinding struct {
	PrerequisiteID string              `json:"prerequisite_id"`
	Status         string              `json:"status"`
	Severity       string              `json:"severity"`
	Evidence       []protocol.Evidence `json:"evidence"`
	Remediation    protocol.Object     `json:"remediation"`
}

type PrerequisiteReport struct {
	Findings []PrerequisiteFinding `json:"findings"`
}

type Artifact struct {
	ArtifactID            string          `json:"artifact_id"`
	CanonicalPath         string          `json:"canonical_path"`
	MediaType             string          `json:"media_type"`
	Size                  int64           `json:"size"`
	SHA256                string          `json:"sha256"`
	Provenance            protocol.Object `json:"provenance"`
	TargetArchitecture    string          `json:"target_architecture"`
	ConsumingOperationIDs []string        `json:"consuming_operation_ids"`
	Role                  string          `json:"role"`
}

type ArtifactSet struct {
	Artifacts []Artifact `json:"artifacts"`
}

type VerificationCheck struct {
	CheckID  string              `json:"check_id"`
	Status   string              `json:"status"`
	Severity string              `json:"severity"`
	Evidence []protocol.Evidence `json:"evidence"`
	Message  string              `json:"message,omitempty"`
}

type VerificationReport struct {
	ReportID   string              `json:"report_id"`
	VerifiedAt string              `json:"verified_at"`
	Checks     []VerificationCheck `json:"checks"`
}

func (r DetectionReport) Validate() error {
	if r.Targets == nil {
		return errors.New("detection targets are required")
	}
	for _, target := range r.Targets {
		if err := target.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r PrerequisiteReport) Validate() error {
	if r.Findings == nil {
		return errors.New("prerequisite findings are required")
	}
	for _, finding := range r.Findings {
		if finding.PrerequisiteID == "" || !protocol.OneOf(finding.Status, "satisfied", "missing", "incompatible", "unknown") || !protocol.OneOf(finding.Severity, "required", "optional") || finding.Evidence == nil || finding.Remediation == nil {
			return errors.New("invalid prerequisite finding")
		}
		for _, evidence := range finding.Evidence {
			if err := evidence.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s ArtifactSet) Validate() error {
	if s.Artifacts == nil {
		return errors.New("artifact set is required")
	}
	seen := make(map[string]struct{}, len(s.Artifacts))
	for _, artifact := range s.Artifacts {
		if artifact.ArtifactID == "" || !canonicalAbsolute(artifact.CanonicalPath) || artifact.MediaType == "" || artifact.Size < 0 || artifact.Provenance == nil || artifact.TargetArchitecture == "" || artifact.ConsumingOperationIDs == nil || artifact.Role == "" {
			return errors.New("invalid prepared artifact")
		}
		if _, exists := seen[artifact.ArtifactID]; exists {
			return fmt.Errorf("duplicate artifact ID %q", artifact.ArtifactID)
		}
		seen[artifact.ArtifactID] = struct{}{}
		if err := protocol.ValidDigest(artifact.SHA256); err != nil {
			return err
		}
	}
	return nil
}

func (r VerificationReport) Validate() error {
	if r.ReportID == "" || r.Checks == nil {
		return errors.New("verification report identity and checks are required")
	}
	if err := protocol.ValidTimestamp(r.VerifiedAt); err != nil {
		return err
	}
	for _, check := range r.Checks {
		if check.CheckID == "" || !protocol.OneOf(check.Status, "passed", "failed", "unknown") || !protocol.OneOf(check.Severity, "required", "optional") || check.Evidence == nil {
			return errors.New("invalid verification check")
		}
		for _, evidence := range check.Evidence {
			if err := evidence.Validate(); err != nil {
				return err
			}
		}
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
	if !protocol.OneOf(r.Operation, "Describe", "Detect", "CheckPrerequisites", "InspectState", "PlanInstall", "PrepareArtifacts", "PlanUninstall", "Verify") {
		return fmt.Errorf("unknown adapter operation %q", r.Operation)
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

type DetectPayload struct {
	Candidates []DisplayManagerCandidate `json:"candidates,omitempty"`
}

type CheckPrerequisitesPayload struct {
	Target                DetectedTarget  `json:"target"`
	RequestedCapabilities []string        `json:"requested_capabilities"`
	Mode                  string          `json:"mode"`
	HostFacts             protocol.Object `json:"host_facts,omitempty"`
}

type InspectStatePayload struct {
	Target    DetectedTarget  `json:"target"`
	HostFacts protocol.Object `json:"host_facts,omitempty"`
}

type PlanInstallPayload struct {
	Target                DetectedTarget      `json:"target"`
	RequestedCapabilities []string            `json:"requested_capabilities"`
	RemediationPolicy     protocol.Object     `json:"remediation_policy"`
	CurrentState          DisplayManagerState `json:"current_state"`
	PrerequisiteReport    protocol.Object     `json:"prerequisite_report"`
	ExistingInstall       json.RawMessage     `json:"existing_install,omitempty"`
	Mode                  string              `json:"mode"`
}

type PlatformContext struct {
	PlatformID            string           `json:"platform_id"`
	PlatformVersion       string           `json:"platform_version"`
	ProtocolVersion       protocol.Version `json:"protocol_version"`
	DescriptorSHA256      string           `json:"descriptor_sha256"`
	TargetArchitecture    string           `json:"target_architecture"`
	PackageFormats        []string         `json:"package_formats"`
	ProviderCapabilities  []string         `json:"provider_capabilities"`
	PlanID                string           `json:"plan_id"`
	PlanDigest            string           `json:"plan_digest"`
	ConsumingOperationIDs []string         `json:"consuming_operation_ids"`
	Workspace             string           `json:"workspace"`
	SourceCache           string           `json:"source_cache"`
	NetworkPolicy         string           `json:"network_policy"`
	Deadline              string           `json:"deadline"`
}

type PrepareArtifactsPayload struct {
	PlanID          string          `json:"plan_id"`
	PlanDigest      string          `json:"plan_digest"`
	Workspace       string          `json:"workspace"`
	SourceCache     string          `json:"source_cache"`
	NetworkPolicy   string          `json:"network_policy"`
	Deadline        string          `json:"deadline,omitempty"`
	PlatformContext PlatformContext `json:"platform_context"`
}

type PlanUninstallPayload struct {
	InstallRecord       protocol.Object     `json:"install_record"`
	CurrentState        DisplayManagerState `json:"current_state"`
	DriftFindings       []json.RawMessage   `json:"drift_findings"`
	ModifiedFilesPolicy string              `json:"modified_files_policy"`
}

type VerifyPayload struct {
	Target                 DetectedTarget    `json:"target"`
	Phase                  string            `json:"phase"`
	ExpectedCapabilities   []string          `json:"expected_capabilities"`
	ExpectedPostconditions []json.RawMessage `json:"expected_postconditions"`
	InstallRecord          json.RawMessage   `json:"install_record,omitempty"`
}

func validatePayload(operation string, raw json.RawMessage) error {
	var err error
	switch operation {
	case "Describe":
		var payload DescribePayload
		err = protocol.DecodeStrict(raw, &payload)
		if err == nil && payload.SupportedProtocolRange != nil && (payload.SupportedProtocolRange.MinMajor < 1 || payload.SupportedProtocolRange.MaxMajor < payload.SupportedProtocolRange.MinMajor) {
			err = errors.New("invalid supported protocol range")
		}
	case "Detect":
		var payload DetectPayload
		err = protocol.DecodeStrict(raw, &payload)
		if err == nil {
			for _, candidate := range payload.Candidates {
				if err = candidate.Validate(); err != nil {
					break
				}
			}
		}
	case "CheckPrerequisites":
		var payload CheckPrerequisitesPayload
		err = protocol.DecodeStrict(raw, &payload, "target", "requested_capabilities", "mode")
		if err == nil {
			err = payload.Target.Validate()
		}
		if err == nil && !validMode(payload.Mode, true) {
			err = errors.New("invalid operation mode")
		}
	case "InspectState":
		var payload InspectStatePayload
		err = protocol.DecodeStrict(raw, &payload, "target")
		if err == nil {
			err = payload.Target.Validate()
		}
	case "PlanInstall":
		var payload PlanInstallPayload
		err = protocol.DecodeStrict(raw, &payload, "target", "requested_capabilities", "remediation_policy", "current_state", "prerequisite_report", "mode")
		if err == nil {
			err = payload.Target.Validate()
		}
		if err == nil {
			err = payload.CurrentState.Validate()
		}
		if err == nil && (!validMode(payload.Mode, false) || payload.Mode == "uninstall") {
			err = errors.New("invalid install mode")
		}
	case "PrepareArtifacts":
		var payload PrepareArtifactsPayload
		err = protocol.DecodeStrict(raw, &payload, "plan_id", "plan_digest", "workspace", "source_cache", "network_policy", "platform_context")
		if err == nil {
			err = validatePrepareArtifacts(payload)
		}
	case "PlanUninstall":
		var payload PlanUninstallPayload
		err = protocol.DecodeStrict(raw, &payload, "install_record", "current_state", "drift_findings", "modified_files_policy")
		if err == nil {
			err = payload.CurrentState.Validate()
		}
		if err == nil && !protocol.OneOf(payload.ModifiedFilesPolicy, "preserve", "overwrite", "abort", "prompt") {
			err = errors.New("invalid modified files policy")
		}
	case "Verify":
		var payload VerifyPayload
		err = protocol.DecodeStrict(raw, &payload, "target", "phase", "expected_capabilities", "expected_postconditions")
		if err == nil {
			err = payload.Target.Validate()
		}
		if err == nil && !protocol.OneOf(payload.Phase, "pre_apply", "post_install", "post_rollback", "post_uninstall") {
			err = errors.New("invalid verification phase")
		}
	}
	if err != nil {
		return fmt.Errorf("%s payload: %w", operation, err)
	}
	return nil
}

func validatePrepareArtifacts(payload PrepareArtifactsPayload) error {
	if payload.PlanID == "" || !canonicalAbsolute(payload.Workspace) || !canonicalAbsolute(payload.SourceCache) || !protocol.OneOf(payload.NetworkPolicy, "forbidden", "isolated", "allowed") {
		return errors.New("invalid artifact preparation fields")
	}
	if err := protocol.ValidDigest(payload.PlanDigest); err != nil {
		return err
	}
	if payload.Deadline != "" {
		if err := protocol.ValidTimestamp(payload.Deadline); err != nil {
			return err
		}
	}
	context := payload.PlatformContext
	if context.PlatformVersion == "" || context.TargetArchitecture == "" || context.PlanID != payload.PlanID || context.PlanDigest != payload.PlanDigest || context.PackageFormats == nil || context.ProviderCapabilities == nil || context.ConsumingOperationIDs == nil || context.Workspace != payload.Workspace || context.SourceCache != payload.SourceCache || context.NetworkPolicy != payload.NetworkPolicy {
		return errors.New("platform context does not match artifact request")
	}
	if err := protocol.ValidOpaqueID(context.PlatformID); err != nil {
		return err
	}
	if err := context.ProtocolVersion.Validate(); err != nil {
		return err
	}
	if err := protocol.ValidDigest(context.DescriptorSHA256); err != nil {
		return err
	}
	return protocol.ValidTimestamp(context.Deadline)
}

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

type Response struct {
	ProtocolVersion protocol.Version `json:"protocol_version"`
	RequestID       string           `json:"request_id"`
	OK              bool             `json:"ok"`
	Result          json.RawMessage  `json:"result,omitempty"`
	Error           *AdapterError    `json:"error,omitempty"`
}

type AdapterError struct {
	Code      string              `json:"code"`
	Message   string              `json:"message"`
	Retryable bool                `json:"retryable"`
	Evidence  []protocol.Evidence `json:"evidence"`
	Details   protocol.Object     `json:"details,omitempty"`
}

func (e *AdapterError) UnmarshalJSON(data []byte) error {
	type wire AdapterError
	var decoded wire
	if err := protocol.DecodeStrict(data, &decoded, "code", "message", "retryable", "evidence"); err != nil {
		return err
	}
	*e = AdapterError(decoded)
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

func (e AdapterError) Validate() error {
	if !protocol.OneOf(e.Code, "invalid_request", "protocol_mismatch", "unsupported_target", "timeout", "host_read_failed", "artifact_failed", "internal_error") || e.Message == "" || e.Evidence == nil {
		return errors.New("invalid adapter error")
	}
	for _, evidence := range e.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type ChangePlan struct {
	PlanID               string               `json:"plan_id"`
	AdapterID            string               `json:"adapter_id"`
	AdapterVersion       string               `json:"adapter_version"`
	ProtocolVersion      protocol.Version     `json:"protocol_version"`
	TargetInstanceID     string               `json:"target_instance_id"`
	Mode                 string               `json:"mode"`
	CreatedAt            string               `json:"created_at"`
	InputHash            string               `json:"input_hash"`
	Approvals            []Approval           `json:"approvals"`
	Preconditions        []Condition          `json:"preconditions"`
	Postconditions       []Condition          `json:"postconditions"`
	ArtifactReferences   []ArtifactReference  `json:"artifact_references"`
	Operations           []protocol.Operation `json:"operations"`
	ExpectedCapabilities []string             `json:"expected_capabilities"`
	CanonicalPlanDigest  string               `json:"canonical_plan_digest"`
}

type Approval struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	RiskLevel string `json:"risk_level"`
}
type Condition struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Predicate   protocol.Object `json:"predicate,omitempty"`
}
type ArtifactReference struct {
	ArtifactID    string `json:"artifact_id"`
	MediaType     string `json:"media_type"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Role          string `json:"role"`
	CanonicalPath string `json:"canonical_path,omitempty"`
}

func (a *ArtifactReference) UnmarshalJSON(data []byte) error {
	type wire ArtifactReference
	var decoded wire
	if err := protocol.DecodeStrict(data, &decoded, "artifact_id", "media_type", "sha256", "size", "role"); err != nil {
		return err
	}
	*a = ArtifactReference(decoded)
	return nil
}

func DecodeChangePlan(data []byte) (ChangePlan, error) {
	var plan ChangePlan
	err := protocol.DecodeStrict(data, &plan, "plan_id", "adapter_id", "adapter_version", "protocol_version", "target_instance_id", "mode", "created_at", "input_hash", "approvals", "preconditions", "postconditions", "artifact_references", "operations", "expected_capabilities", "canonical_plan_digest")
	if err == nil {
		err = plan.Validate()
	}
	return plan, err
}

func (p ChangePlan) Validate() error {
	if p.PlanID == "" || p.AdapterVersion == "" || p.TargetInstanceID == "" || p.Approvals == nil || p.Preconditions == nil || p.Postconditions == nil || p.ArtifactReferences == nil || p.Operations == nil || p.ExpectedCapabilities == nil {
		return errors.New("change plan required fields are empty")
	}
	if err := protocol.ValidOpaqueID(p.AdapterID); err != nil {
		return err
	}
	if err := p.ProtocolVersion.Validate(); err != nil {
		return err
	}
	if !validMode(p.Mode, true) {
		return errors.New("invalid plan mode")
	}
	if err := protocol.ValidTimestamp(p.CreatedAt); err != nil {
		return err
	}
	if err := protocol.ValidDigest(p.InputHash); err != nil {
		return err
	}
	if err := protocol.ValidDigest(p.CanonicalPlanDigest); err != nil {
		return err
	}
	for _, approval := range p.Approvals {
		if approval.ID == "" || approval.Statement == "" || !protocol.OneOf(approval.RiskLevel, "low", "medium", "high", "critical") {
			return errors.New("invalid approval")
		}
	}
	for _, condition := range append(append([]Condition{}, p.Preconditions...), p.Postconditions...) {
		if condition.ID == "" || condition.Description == "" {
			return errors.New("invalid condition")
		}
	}
	for _, artifact := range p.ArtifactReferences {
		if artifact.ArtifactID == "" || artifact.MediaType == "" || artifact.Role == "" || artifact.Size < 0 {
			return errors.New("invalid artifact reference")
		}
		if err := protocol.ValidDigest(artifact.SHA256); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, len(p.Operations))
	for _, operation := range p.Operations {
		if _, exists := seen[operation.OperationID]; exists {
			return fmt.Errorf("duplicate operation_id %q", operation.OperationID)
		}
		if err := operation.Validate(); err != nil {
			return fmt.Errorf("operation %q: %w", operation.OperationID, err)
		}
		for _, dependency := range operation.Dependencies {
			if _, exists := seen[dependency]; !exists {
				return fmt.Errorf("operation %q depends on non-prior operation %q", operation.OperationID, dependency)
			}
		}
		seen[operation.OperationID] = struct{}{}
	}
	return nil
}

func validMode(mode string, uninstall bool) bool {
	if protocol.OneOf(mode, "fresh_install", "upgrade", "repair", "reinstall") {
		return true
	}
	return uninstall && mode == "uninstall"
}
func triState(value string) bool { return protocol.OneOf(value, "yes", "no", "unknown") }
