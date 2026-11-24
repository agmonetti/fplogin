// Package v1 implements the Go representation and validation boundary for the
// durable transaction journal and installed-state manifest v1 formats.
package v1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"fplogin/internal/protocol"
)

const SchemaVersion = "1.0"

type Target struct {
	InstanceID      string          `json:"instance_id"`
	DMID            string          `json:"dm_id"`
	DisplayName     string          `json:"display_name"`
	VersionEvidence json.RawMessage `json:"version_evidence,omitempty"`
}

type ComponentIdentity struct {
	ID               string           `json:"id"`
	Version          string           `json:"version"`
	ProtocolVersion  protocol.Version `json:"protocol_version"`
	DescriptorSHA256 string           `json:"descriptor_sha256"`
}

type AdapterIdentity struct {
	ComponentIdentity
	InstalledCapabilities []string `json:"installed_capabilities"`
}

func (a AdapterIdentity) MarshalJSON() ([]byte, error) {
	type wire struct {
		ID                    string           `json:"id"`
		Version               string           `json:"version"`
		ProtocolVersion       protocol.Version `json:"protocol_version"`
		DescriptorSHA256      string           `json:"descriptor_sha256"`
		InstalledCapabilities []string         `json:"installed_capabilities"`
	}
	return json.Marshal(wire{a.ID, a.Version, a.ProtocolVersion, a.DescriptorSHA256, a.InstalledCapabilities})
}

func (a *AdapterIdentity) UnmarshalJSON(data []byte) error {
	var value struct {
		ID                    string           `json:"id"`
		Version               string           `json:"version"`
		ProtocolVersion       protocol.Version `json:"protocol_version"`
		DescriptorSHA256      string           `json:"descriptor_sha256"`
		InstalledCapabilities []string         `json:"installed_capabilities"`
	}
	if err := protocol.DecodeStrict(data, &value, "id", "version", "protocol_version", "descriptor_sha256", "installed_capabilities"); err != nil {
		return err
	}
	a.ComponentIdentity = ComponentIdentity{value.ID, value.Version, value.ProtocolVersion, value.DescriptorSHA256}
	a.InstalledCapabilities = value.InstalledCapabilities
	return nil
}

type AcceptedPlan struct {
	PlanID     string `json:"plan_id"`
	PlanDigest string `json:"plan_digest"`
	InputHash  string `json:"input_hash,omitempty"`
	Mode       string `json:"mode"`
}

type OperationReceipt struct {
	OperationID  string                 `json:"operation_id"`
	Kind         protocol.OperationKind `json:"kind"`
	StartedAt    string                 `json:"started_at,omitempty"`
	CompletedAt  string                 `json:"completed_at"`
	Status       string                 `json:"status"`
	BeforeState  protocol.Object        `json:"before_state,omitempty"`
	AfterState   protocol.Object        `json:"after_state,omitempty"`
	Evidence     []json.RawMessage      `json:"evidence,omitempty"`
	Compensation protocol.Object        `json:"compensation"`
	Error        json.RawMessage        `json:"error,omitempty"`
}

func (r OperationReceipt) Validate(journal bool) error {
	if r.OperationID == "" || r.Compensation == nil || !(protocol.OneOf(r.Status, "success", "failed", "rolled_back", "rollback_failed") || journal && r.Status == "pending" && IsRecoverableKind(r.Kind)) {
		return errors.New("invalid operation receipt")
	}
	if err := r.Kind.Validate(); err != nil {
		return err
	}
	if journal {
		if r.BeforeState == nil || r.AfterState == nil || r.StartedAt == "" {
			return errors.New("journal receipt requires timing and before/after state")
		}
		if err := protocol.ValidTimestamp(r.StartedAt); err != nil {
			return err
		}
	}
	return protocol.ValidTimestamp(r.CompletedAt)
}

func IsRecoverableFileKind(kind protocol.OperationKind) bool {
	return kind == protocol.WriteFileAtomic || kind == protocol.RemoveOwnedFile
}

func IsRecoverableKind(kind protocol.OperationKind) bool {
	return IsRecoverableFileKind(kind) ||
		kind == protocol.InstallPackageArtifact ||
		kind == protocol.RemoveOwnedPackage ||
		kind == protocol.SetServiceEnabled ||
		kind == protocol.SetServiceActive ||
		kind == protocol.RestoreServiceState
}

type TransactionJournal struct {
	FileRecovery        bool               `json:"file_recovery,omitempty"`
	SchemaVersion       string             `json:"schema_version"`
	TransactionID       string             `json:"transaction_id"`
	State               string             `json:"state"`
	CreatedAt           string             `json:"created_at"`
	UpdatedAt           string             `json:"updated_at"`
	Target              Target             `json:"target"`
	Adapter             ComponentIdentity  `json:"adapter"`
	PlatformProvider    ComponentIdentity  `json:"platform_provider"`
	AcceptedPlan        AcceptedPlan       `json:"accepted_plan"`
	OperationOrder      []string           `json:"operation_order"`
	PreparedFiles       []OperationReceipt `json:"prepared_files,omitempty"`
	AppliedOperations   []OperationReceipt `json:"applied_operations"`
	VerificationResults []json.RawMessage  `json:"verification_results,omitempty"`
	RollbackRecords     []json.RawMessage  `json:"rollback_records,omitempty"`
}

func DecodeTransactionJournal(data []byte) (TransactionJournal, error) {
	var journal TransactionJournal
	err := protocol.DecodeStrict(data, &journal, "schema_version", "transaction_id", "state", "created_at", "updated_at", "target", "adapter", "platform_provider", "accepted_plan", "operation_order", "applied_operations")
	if err != nil {
		return journal, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return journal, err
	}
	for key := range fields {
		if strings.EqualFold(key, "prepared_files") && (key != "prepared_files" || journal.PreparedFiles == nil) {
			return journal, errors.New("prepared_files must be canonical and non-null")
		}
	}
	return journal, journal.Validate()
}

func (j TransactionJournal) Validate() error {
	if j.SchemaVersion != SchemaVersion || j.TransactionID == "" || !protocol.OneOf(j.State, "planned", "prepared", "applying", "rollback_required", "rolling_back", "rolled_back", "verification_failed", "completed", "aborted") {
		return errors.New("invalid journal identity or state")
	}
	if err := protocol.ValidTimestamp(j.CreatedAt); err != nil {
		return err
	}
	if err := protocol.ValidTimestamp(j.UpdatedAt); err != nil {
		return err
	}
	if err := validateTarget(j.Target); err != nil {
		return err
	}
	if err := validateComponent(j.Adapter); err != nil {
		return fmt.Errorf("adapter: %w", err)
	}
	if err := validateComponent(j.PlatformProvider); err != nil {
		return fmt.Errorf("platform provider: %w", err)
	}
	if err := validatePlan(j.AcceptedPlan, true); err != nil {
		return err
	}
	if j.OperationOrder == nil || j.AppliedOperations == nil {
		return errors.New("operation order and applied operations are required")
	}
	ordered := make(map[string]struct{}, len(j.OperationOrder))
	for _, operationID := range j.OperationOrder {
		if operationID == "" {
			return errors.New("empty operation ID")
		}
		if _, exists := ordered[operationID]; exists {
			return fmt.Errorf("duplicate operation ID %q", operationID)
		}
		ordered[operationID] = struct{}{}
	}
	if err := j.validatePreparedFiles(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(j.AppliedOperations))
	for i, receipt := range j.AppliedOperations {
		if seen[receipt.OperationID] {
			return fmt.Errorf("duplicate operation receipt %q", receipt.OperationID)
		}
		seen[receipt.OperationID] = true
		if receipt.Status == "pending" && (!j.FileRecovery || i != len(j.AppliedOperations)-1 || !protocol.OneOf(j.State, "applying", "rolling_back")) {
			return errors.New("invalid pending file intent")
		}
		if j.FileRecovery && (i >= len(j.OperationOrder) || j.OperationOrder[i] != receipt.OperationID || !IsRecoverableKind(receipt.Kind)) {
			return errors.New("invalid order or operation kind in recoverable journal")
		}
		if j.PreparedFiles != nil && IsRecoverableFileKind(receipt.Kind) && !j.MatchesPreparedFile(i, receipt) {
			return errors.New("file intent differs from prepared plan")
		}
		if (j.State == "completed" && receipt.Status != "success") || (j.State == "rolled_back" && receipt.Status != "rolled_back" && (j.FileRecovery || receipt.Status != "failed")) {
			return errors.New("unresolved receipt in terminal journal")
		}
		if _, exists := ordered[receipt.OperationID]; !exists {
			return fmt.Errorf("receipt references unknown operation %q", receipt.OperationID)
		}
		if err := receipt.Validate(true); err != nil {
			return err
		}
	}
	if j.FileRecovery && j.State == "completed" && len(j.AppliedOperations) != len(j.OperationOrder) {
		return errors.New("completed journal is missing operations")
	}
	return nil
}

func (j TransactionJournal) validatePreparedFiles() error {
	if j.PreparedFiles == nil {
		return nil
	}
	if !j.FileRecovery || len(j.PreparedFiles) == 0 || len(j.PreparedFiles) > len(j.OperationOrder) {
		return errors.New("invalid prepared file plan length or type")
	}
	orderPos := make(map[string]int, len(j.OperationOrder))
	for i, id := range j.OperationOrder {
		orderPos[id] = i
	}
	paths := make(map[string]bool, len(j.PreparedFiles))
	prevPos := -1
	for _, r := range j.PreparedFiles {
		pos, ok := orderPos[r.OperationID]
		if !ok || pos <= prevPos || r.Status != "pending" || !IsRecoverableFileKind(r.Kind) {
			return errors.New("invalid prepared file operation")
		}
		prevPos = pos
		if err := r.Validate(true); err != nil {
			return err
		}
		before, bErr := DecodeFileState(r.BeforeState)
		after, aErr := DecodeFileState(r.AfterState)
		if bErr != nil || aErr != nil || before.Path != after.Path || paths[before.Path] ||
			(r.Kind == protocol.WriteFileAtomic && !after.Exists) ||
			(r.Kind == protocol.RemoveOwnedFile && (!before.Exists || after.Exists)) {
			return errors.New("invalid prepared before/after file state")
		}
		paths[before.Path] = true
	}
	return nil
}

// FileState describes an ordinary single-link file in a trusted tree.
type FileState struct {
	Path   string `json:"destination_path"`
	Exists bool   `json:"existed"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

func DecodeFileState(obj protocol.Object) (FileState, error) {
	var s FileState
	b, err := json.Marshal(obj)
	if err != nil {
		return s, err
	}
	if err := protocol.DecodeStrict(b, &s, "destination_path", "existed"); err != nil {
		return s, err
	}
	if !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path || s.Path == "/" {
		return s, errors.New("invalid file path")
	}
	if s.Exists {
		mode, err := strconv.ParseUint(s.Mode, 8, 9)
		digest, digestErr := hex.DecodeString(s.SHA256)
		if err != nil || s.Mode != fmt.Sprintf("%04o", mode) || digestErr != nil || len(digest) != 32 || hex.EncodeToString(digest) != s.SHA256 {
			return s, errors.New("invalid file mode or digest")
		}
	} else if _, hasMode := obj["mode"]; hasMode || obj["sha256"] != nil {
		return s, errors.New("absent file has a mode or digest")
	}
	return s, nil
}

// MatchesPreparedFile compares only the immutable execution and recovery data.
func (j TransactionJournal) MatchesPreparedFile(i int, r OperationReceipt) bool {
	if i < 0 || i >= len(j.OperationOrder) || j.OperationOrder[i] != r.OperationID {
		return false
	}
	for _, p := range j.PreparedFiles {
		if p.OperationID != r.OperationID {
			continue
		}
		equal := func(a, b json.RawMessage) bool { return bytes.Equal(a, b) }
		return p.Kind == r.Kind &&
			maps.EqualFunc(p.BeforeState, r.BeforeState, equal) &&
			maps.EqualFunc(p.AfterState, r.AfterState, equal)
	}
	return false
}

type InstalledFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Size   int64  `json:"size"`
}
type InstalledPackage struct {
	PackageReference string `json:"package_reference"`
	Version          string `json:"version"`
	SHA256           string `json:"sha256,omitempty"`
}
type ServiceState struct {
	ServiceReference string `json:"service_reference"`
	Enabled          string `json:"enabled"`
	Active           string `json:"active"`
}
type Services struct {
	Enabled     []string       `json:"enabled"`
	Disabled    []string       `json:"disabled"`
	PriorStates []ServiceState `json:"prior_states"`
}
type PreviousDMState struct {
	ServiceName string `json:"service_name"`
	Enabled     string `json:"enabled"`
	Active      string `json:"active"`
}
type VerificationCheck struct {
	CheckID  string            `json:"check_id"`
	Status   string            `json:"status"`
	Evidence []json.RawMessage `json:"evidence"`
	Message  string            `json:"message,omitempty"`
}
type Verification struct {
	ReportID   string              `json:"report_id"`
	VerifiedAt string              `json:"verified_at"`
	Checks     []VerificationCheck `json:"checks"`
}

type InstallManifest struct {
	SchemaVersion     string             `json:"schema_version"`
	FPLoginVersion    string             `json:"fplogin_version"`
	InstalledAt       string             `json:"installed_at"`
	Target            Target             `json:"target"`
	Adapter           AdapterIdentity    `json:"adapter"`
	PlatformProvider  ComponentIdentity  `json:"platform_provider"`
	AcceptedPlan      AcceptedPlan       `json:"accepted_plan"`
	InstalledFiles    []InstalledFile    `json:"installed_files"`
	InstalledPackages []InstalledPackage `json:"installed_packages"`
	Services          Services           `json:"services"`
	PreviousDMState   PreviousDMState    `json:"previous_dm_state"`
	OperationReceipts []OperationReceipt `json:"operation_receipts"`
	Verification      Verification       `json:"verification"`
}

func DecodeInstallManifest(data []byte) (InstallManifest, error) {
	var manifest InstallManifest
	err := protocol.DecodeStrict(data, &manifest, "schema_version", "fplogin_version", "installed_at", "target", "adapter", "platform_provider", "accepted_plan", "installed_files", "installed_packages", "services", "previous_dm_state", "operation_receipts", "verification")
	if err == nil {
		err = manifest.Validate()
	}
	return manifest, err
}

func (m InstallManifest) Validate() error {
	if m.SchemaVersion != SchemaVersion || m.FPLoginVersion == "" {
		return errors.New("invalid manifest version")
	}
	if err := protocol.ValidTimestamp(m.InstalledAt); err != nil {
		return err
	}
	if err := validateTarget(m.Target); err != nil {
		return err
	}
	if err := validateComponent(m.Adapter.ComponentIdentity); err != nil {
		return fmt.Errorf("adapter: %w", err)
	}
	if m.Adapter.InstalledCapabilities == nil {
		return errors.New("installed capabilities are required")
	}
	if err := validateComponent(m.PlatformProvider); err != nil {
		return fmt.Errorf("platform provider: %w", err)
	}
	if err := validatePlan(m.AcceptedPlan, false); err != nil {
		return err
	}
	if m.InstalledFiles == nil || m.InstalledPackages == nil || m.Services.Enabled == nil || m.Services.Disabled == nil || m.Services.PriorStates == nil || m.OperationReceipts == nil {
		return errors.New("manifest collection fields are required")
	}
	for _, file := range m.InstalledFiles {
		if file.Path == "" || file.Mode == "" || file.Owner == "" || file.Group == "" || file.Size < 0 {
			return errors.New("invalid installed file")
		}
		if err := protocol.ValidDigest(file.SHA256); err != nil {
			return err
		}
	}
	for _, pkg := range m.InstalledPackages {
		if pkg.PackageReference == "" || pkg.Version == "" {
			return errors.New("invalid installed package")
		}
		if pkg.SHA256 != "" {
			if err := protocol.ValidDigest(pkg.SHA256); err != nil {
				return err
			}
		}
	}
	for _, state := range append(append([]ServiceState{}, m.Services.PriorStates...), ServiceState{ServiceReference: m.PreviousDMState.ServiceName, Enabled: m.PreviousDMState.Enabled, Active: m.PreviousDMState.Active}) {
		if state.ServiceReference == "" || !triState(state.Enabled) || !triState(state.Active) {
			return errors.New("invalid prior service state")
		}
	}
	for _, receipt := range m.OperationReceipts {
		if err := receipt.Validate(false); err != nil {
			return err
		}
	}
	if m.Verification.ReportID == "" || m.Verification.Checks == nil {
		return errors.New("verification report is required")
	}
	if err := protocol.ValidTimestamp(m.Verification.VerifiedAt); err != nil {
		return err
	}
	for _, check := range m.Verification.Checks {
		if check.CheckID == "" || check.Evidence == nil || !protocol.OneOf(check.Status, "passed", "failed", "unknown") {
			return errors.New("invalid verification check")
		}
	}
	return nil
}

func validateTarget(target Target) error {
	if target.InstanceID == "" || target.DMID == "" || target.DisplayName == "" {
		return errors.New("target identity is required")
	}
	return nil
}
func validateComponent(component ComponentIdentity) error {
	if component.ID == "" || component.Version == "" {
		return errors.New("component identity is required")
	}
	if err := component.ProtocolVersion.Validate(); err != nil {
		return err
	}
	return protocol.ValidDigest(component.DescriptorSHA256)
}
func validatePlan(plan AcceptedPlan, requireInputHash bool) error {
	if plan.PlanID == "" || !protocol.OneOf(plan.Mode, "fresh_install", "upgrade", "repair", "reinstall", "uninstall") {
		return errors.New("invalid accepted plan")
	}
	if err := protocol.ValidDigest(plan.PlanDigest); err != nil {
		return err
	}
	if requireInputHash {
		return protocol.ValidDigest(plan.InputHash)
	}
	if plan.InputHash != "" {
		return protocol.ValidDigest(plan.InputHash)
	}
	return nil
}
func triState(value string) bool { return protocol.OneOf(value, "yes", "no", "unknown") }
