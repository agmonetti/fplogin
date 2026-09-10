// Package protocol contains wire primitives shared by the versioned adapter,
// platform, and manifest protocols.
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	idPattern        = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_-]+)+$`)
	requestIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

type Object map[string]json.RawMessage

type Version struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

func (v *Version) UnmarshalJSON(data []byte) error {
	type wire Version
	var decoded wire
	if err := DecodeStrict(data, &decoded, "major", "minor"); err != nil {
		return err
	}
	*v = Version(decoded)
	return nil
}

func (v Version) Validate() error {
	if v.Major < 1 || v.Minor < 0 {
		return fmt.Errorf("invalid protocol version %d.%d", v.Major, v.Minor)
	}
	return nil
}

type Evidence struct {
	Source        string `json:"source"`
	Kind          string `json:"kind"`
	Subject       string `json:"subject"`
	ObservedValue string `json:"observed_value"`
	Timestamp     string `json:"timestamp"`
	Error         string `json:"error,omitempty"`
}

func (e *Evidence) UnmarshalJSON(data []byte) error {
	type wire Evidence
	var decoded wire
	if err := DecodeStrict(data, &decoded, "source", "kind", "subject", "observed_value", "timestamp"); err != nil {
		return err
	}
	*e = Evidence(decoded)
	return nil
}

func (e Evidence) Validate() error {
	if !oneOf(e.Source, "core", "adapter", "platform") {
		return fmt.Errorf("invalid evidence source %q", e.Source)
	}
	if !oneOf(e.Kind, "path", "command", "package", "service", "adapter_report", "derived") {
		return fmt.Errorf("invalid evidence kind %q", e.Kind)
	}
	if e.Subject == "" {
		return errors.New("evidence subject is required")
	}
	if err := ValidTimestamp(e.Timestamp); err != nil {
		return fmt.Errorf("evidence timestamp: %w", err)
	}
	return nil
}

type HostContext struct {
	Root                     string            `json:"root"`
	Platform                 Object            `json:"platform"`
	Architecture             string            `json:"architecture"`
	PackageManager           json.RawMessage   `json:"package_manager,omitempty"`
	ServiceManager           json.RawMessage   `json:"service_manager,omitempty"`
	DisplayManagerCandidates []json.RawMessage `json:"display_manager_candidates,omitempty"`
	InvokingUID              uint32            `json:"invoking_uid"`
	InvokingGID              uint32            `json:"invoking_gid"`
	Elevated                 bool              `json:"elevated"`
	Locale                   string            `json:"locale"`
	DryRun                   bool              `json:"dry_run"`
	Deadline                 string            `json:"deadline"`
}

func (c *HostContext) UnmarshalJSON(data []byte) error {
	type wire HostContext
	var decoded wire
	if err := DecodeStrict(data, &decoded, "root", "platform", "architecture", "invoking_uid", "invoking_gid", "elevated", "locale", "dry_run", "deadline"); err != nil {
		return err
	}
	*c = HostContext(decoded)
	return nil
}

func (c HostContext) Validate() error {
	if c.Root == "" || !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root {
		return fmt.Errorf("root must be a canonical absolute path: %q", c.Root)
	}
	if c.Platform == nil {
		return errors.New("platform facts are required")
	}
	if c.Architecture == "" {
		return errors.New("architecture is required")
	}
	if c.Locale != "C" {
		return fmt.Errorf("locale must be C, got %q", c.Locale)
	}
	if err := ValidTimestamp(c.Deadline); err != nil {
		return fmt.Errorf("deadline: %w", err)
	}
	return nil
}

type Capability struct {
	ID                   string          `json:"id"`
	Status               string          `json:"status"`
	Level                json.RawMessage `json:"level"`
	Constraints          Object          `json:"constraints"`
	EvidenceRequirements []string        `json:"evidence_requirements"`
}

func (c *Capability) UnmarshalJSON(data []byte) error {
	type wire Capability
	var decoded wire
	if err := DecodeStrict(data, &decoded, "id", "status", "level", "constraints", "evidence_requirements"); err != nil {
		return err
	}
	*c = Capability(decoded)
	return nil
}

func (c Capability) Validate() error {
	if c.ID == "" || !regexp.MustCompile(`^[a-z0-9_.]+$`).MatchString(c.ID) {
		return fmt.Errorf("invalid capability id %q", c.ID)
	}
	if !oneOf(c.Status, "native", "provided", "unsupported") {
		return fmt.Errorf("invalid capability status %q", c.Status)
	}
	if len(c.Level) == 0 || (c.Level[0] != '"' && c.Level[0] != '-' && (c.Level[0] < '0' || c.Level[0] > '9')) {
		return errors.New("capability level must be a string or integer")
	}
	if c.Constraints == nil {
		return errors.New("capability constraints are required")
	}
	return nil
}

type OperationKind string

const (
	CreateDirectory        OperationKind = "create_directory"
	WriteFileAtomic        OperationKind = "write_file_atomic"
	RemoveOwnedFile        OperationKind = "remove_owned_file"
	InstallPackageArtifact OperationKind = "install_package_artifact"
	RemoveOwnedPackage     OperationKind = "remove_owned_package"
	SetServiceEnabled      OperationKind = "set_service_enabled"
	SetServiceActive       OperationKind = "set_service_active"
	RestoreServiceState    OperationKind = "restore_service_state"
)

func (k OperationKind) Validate() error {
	switch k {
	case CreateDirectory, WriteFileAtomic, RemoveOwnedFile, InstallPackageArtifact,
		RemoveOwnedPackage, SetServiceEnabled, SetServiceActive, RestoreServiceState:
		return nil
	default:
		return fmt.Errorf("unknown operation kind %q", k)
	}
}

type Operation struct {
	OperationID    string            `json:"operation_id"`
	Kind           OperationKind     `json:"kind"`
	Dependencies   []string          `json:"dependencies"`
	Parameters     json.RawMessage   `json:"parameters"`
	Preconditions  []json.RawMessage `json:"preconditions"`
	ExpectedBefore Object            `json:"expected_before"`
	ExpectedAfter  Object            `json:"expected_after"`
	Compensation   json.RawMessage   `json:"compensation"`
}

func (o *Operation) UnmarshalJSON(data []byte) error {
	type wire Operation
	var decoded wire
	if err := DecodeStrict(data, &decoded, "operation_id", "kind", "dependencies", "parameters", "preconditions", "expected_before", "expected_after", "compensation"); err != nil {
		return err
	}
	*o = Operation(decoded)
	return nil
}

func (o Operation) Validate() error {
	if o.OperationID == "" {
		return errors.New("operation_id is required")
	}
	if err := o.Kind.Validate(); err != nil {
		return err
	}
	if o.Dependencies == nil || o.Preconditions == nil || o.ExpectedBefore == nil || o.ExpectedAfter == nil {
		return errors.New("operation dependencies, preconditions, and expected states are required")
	}
	if len(o.Parameters) == 0 || len(o.Compensation) == 0 {
		return errors.New("operation parameters and compensation are required")
	}
	return validateOperationPayload(o)
}

func validateOperationPayload(o Operation) error {
	type createDirectoryParameters struct {
		Path  string `json:"path"`
		Mode  string `json:"mode"`
		Owner string `json:"owner"`
		Group string `json:"group"`
	}
	type writeFileParameters struct {
		DestinationPath string `json:"destination_path"`
		SourceArtifact  string `json:"source_artifact_id,omitempty"`
		ContentBase64   string `json:"content_base64,omitempty"`
		SHA256          string `json:"sha256"`
		Mode            string `json:"mode"`
		Owner           string `json:"owner"`
		Group           string `json:"group"`
	}
	type pathHashParameters struct {
		Path           string `json:"path"`
		ExpectedSHA256 string `json:"expected_sha256"`
	}
	type packageArtifactParameters struct {
		ArtifactID       string `json:"artifact_id"`
		PackageReference string `json:"package_reference"`
		SHA256           string `json:"sha256"`
	}
	type packageParameters struct {
		PackageReference string `json:"package_reference"`
	}
	type serviceBoolParameters struct {
		ServiceReference string `json:"service_reference"`
		Enabled          *bool  `json:"enabled,omitempty"`
		Active           *bool  `json:"active,omitempty"`
	}
	type serviceStateParameters struct {
		ServiceReference string `json:"service_reference"`
		Enabled          string `json:"enabled"`
		Active           string `json:"active"`
	}

	var err error
	switch o.Kind {
	case CreateDirectory:
		var p createDirectoryParameters
		err = DecodeStrict(o.Parameters, &p, "path", "mode", "owner", "group")
		if err == nil {
			err = validateFileMetadata(p.Path, "", p.Mode, p.Owner, p.Group)
		}
	case WriteFileAtomic:
		var p writeFileParameters
		err = DecodeStrict(o.Parameters, &p, "destination_path", "sha256", "mode", "owner", "group")
		if err == nil {
			err = validateFileMetadata(p.DestinationPath, p.SHA256, p.Mode, p.Owner, p.Group)
		}
		if err == nil && (p.SourceArtifact == "") == (p.ContentBase64 == "") {
			err = errors.New("write_file_atomic requires exactly one content source")
		}
	case RemoveOwnedFile:
		var p pathHashParameters
		err = DecodeStrict(o.Parameters, &p, "path", "expected_sha256")
		if err == nil {
			err = validateAbsolutePath(p.Path)
		}
		if err == nil {
			err = ValidDigest(p.ExpectedSHA256)
		}
	case InstallPackageArtifact:
		var p packageArtifactParameters
		err = DecodeStrict(o.Parameters, &p, "artifact_id", "package_reference", "sha256")
		if err == nil && (p.ArtifactID == "" || p.PackageReference == "") {
			err = errors.New("artifact and package references are required")
		}
		if err == nil {
			err = ValidDigest(p.SHA256)
		}
	case RemoveOwnedPackage:
		var p packageParameters
		err = DecodeStrict(o.Parameters, &p, "package_reference")
		if err == nil && p.PackageReference == "" {
			err = errors.New("package_reference is required")
		}
	case SetServiceEnabled, SetServiceActive:
		var p serviceBoolParameters
		required := "enabled"
		if o.Kind == SetServiceActive {
			required = "active"
		}
		err = DecodeStrict(o.Parameters, &p, "service_reference", required)
		if err == nil && p.ServiceReference == "" {
			err = errors.New("service_reference is required")
		}
		if err == nil && ((o.Kind == SetServiceEnabled && p.Enabled == nil) || (o.Kind == SetServiceActive && p.Active == nil)) {
			err = fmt.Errorf("%s is required", required)
		}
	case RestoreServiceState:
		var p serviceStateParameters
		err = DecodeStrict(o.Parameters, &p, "service_reference", "enabled", "active")
		if err == nil && (p.ServiceReference == "" || !oneOf(p.Enabled, "yes", "no", "unknown") || !oneOf(p.Active, "yes", "no", "unknown")) {
			err = errors.New("invalid restore_service_state parameters")
		}
	}
	if err != nil {
		return fmt.Errorf("%s parameters: %w", o.Kind, err)
	}
	if err := validateCompensation(o.Kind, o.Compensation); err != nil {
		return fmt.Errorf("%s compensation: %w", o.Kind, err)
	}
	return nil
}

func validateCompensation(operationKind OperationKind, data json.RawMessage) error {
	type pathCompensation struct {
		Kind         string `json:"kind"`
		Path         string `json:"path"`
		BackupSHA256 string `json:"backup_sha256,omitempty"`
		BackupPath   string `json:"backup_path,omitempty"`
	}
	type restoreFileCompensation struct {
		Kind             string `json:"kind"`
		Path             string `json:"path"`
		SourceArtifactID string `json:"source_artifact_id,omitempty"`
		ContentBase64    string `json:"content_base64,omitempty"`
		SHA256           string `json:"sha256,omitempty"`
		Mode             string `json:"mode,omitempty"`
		Owner            string `json:"owner,omitempty"`
		Group            string `json:"group,omitempty"`
	}
	type packageCompensation struct {
		Kind             string `json:"kind"`
		PackageReference string `json:"package_reference"`
	}
	type serviceBoolCompensation struct {
		Kind             string `json:"kind"`
		ServiceReference string `json:"service_reference"`
		Enabled          *bool  `json:"enabled,omitempty"`
		Active           *bool  `json:"active,omitempty"`
	}
	type serviceStateCompensation struct {
		Kind             string `json:"kind"`
		ServiceReference string `json:"service_reference"`
		Enabled          string `json:"enabled"`
		Active           string `json:"active"`
	}

	switch operationKind {
	case CreateDirectory:
		var value pathCompensation
		if err := DecodeStrict(data, &value, "kind", "path"); err != nil {
			return err
		}
		if value.Kind != "remove_directory" {
			return fmt.Errorf("invalid kind %q", value.Kind)
		}
		return validateAbsolutePath(value.Path)
	case WriteFileAtomic:
		var value pathCompensation
		if err := DecodeStrict(data, &value, "kind", "path"); err != nil {
			return err
		}
		if !oneOf(value.Kind, "remove_file", "restore_file") {
			return fmt.Errorf("invalid kind %q", value.Kind)
		}
		if err := validateAbsolutePath(value.Path); err != nil {
			return err
		}
		if value.BackupSHA256 != "" {
			return ValidDigest(value.BackupSHA256)
		}
		return nil
	case RemoveOwnedFile:
		var value restoreFileCompensation
		if err := DecodeStrict(data, &value, "kind", "path"); err != nil {
			return err
		}
		if value.Kind != "restore_file" {
			return fmt.Errorf("invalid kind %q", value.Kind)
		}
		if err := validateAbsolutePath(value.Path); err != nil {
			return err
		}
		if value.SHA256 != "" {
			if err := ValidDigest(value.SHA256); err != nil {
				return err
			}
		}
		if value.Mode != "" && !regexp.MustCompile(`^0[0-7]{3}$`).MatchString(value.Mode) {
			return fmt.Errorf("invalid file mode %q", value.Mode)
		}
		return nil
	case InstallPackageArtifact, RemoveOwnedPackage:
		var value packageCompensation
		if err := DecodeStrict(data, &value, "kind", "package_reference"); err != nil {
			return err
		}
		expected := "remove_package"
		if operationKind == RemoveOwnedPackage {
			expected = "install_package"
		}
		if value.Kind != expected || value.PackageReference == "" {
			return fmt.Errorf("invalid package compensation %q", value.Kind)
		}
		return nil
	case SetServiceEnabled, SetServiceActive:
		var value serviceBoolCompensation
		required := "enabled"
		if operationKind == SetServiceActive {
			required = "active"
		}
		if err := DecodeStrict(data, &value, "kind", "service_reference", required); err != nil {
			return err
		}
		if value.Kind != string(operationKind) || value.ServiceReference == "" {
			return errors.New("invalid service compensation")
		}
		if operationKind == SetServiceEnabled && value.Enabled == nil || operationKind == SetServiceActive && value.Active == nil {
			return fmt.Errorf("%s is required", required)
		}
		return nil
	case RestoreServiceState:
		var value serviceStateCompensation
		if err := DecodeStrict(data, &value, "kind", "service_reference", "enabled", "active"); err != nil {
			return err
		}
		if value.Kind != string(RestoreServiceState) || value.ServiceReference == "" || !oneOf(value.Enabled, "yes", "no", "unknown") || !oneOf(value.Active, "yes", "no", "unknown") {
			return errors.New("invalid restore service compensation")
		}
		return nil
	default:
		return fmt.Errorf("unknown operation kind %q", operationKind)
	}
}

func DecodeStrict(data []byte, dst any, required ...string) error {
	if len(required) > 0 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		for _, name := range required {
			value, ok := fields[name]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("required field %q is missing", name)
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func RequireFieldsAllowNull(data []byte, required ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("required field %q is missing", name)
		}
	}
	return nil
}

func ValidDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("invalid SHA-256 digest %q", value)
	}
	return nil
}

func ValidOpaqueID(value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("invalid opaque ID %q", value)
	}
	return nil
}

func ValidRequestID(value string) error {
	if !requestIDPattern.MatchString(value) {
		return fmt.Errorf("invalid request UUID %q", value)
	}
	return nil
}

func ValidTimestamp(value string) error {
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("invalid RFC3339 timestamp %q", value)
	}
	return nil
}

func ValidRelativePath(value string) error {
	if value == "" || !filepath.IsLocal(value) || filepath.Clean(value) != value || strings.Contains(value, "\\") {
		return fmt.Errorf("path must be canonical and relative: %q", value)
	}
	return nil
}

func validateAbsolutePath(value string) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("path must be canonical and absolute: %q", value)
	}
	return nil
}

func validateFileMetadata(path, digest, mode, owner, group string) error {
	if err := validateAbsolutePath(path); err != nil {
		return err
	}
	if digest != "" {
		if err := ValidDigest(digest); err != nil {
			return err
		}
	}
	if !regexp.MustCompile(`^0[0-7]{3}$`).MatchString(mode) {
		return fmt.Errorf("invalid file mode %q", mode)
	}
	if owner == "" || group == "" {
		return errors.New("owner and group are required")
	}
	return nil
}

func OneOf(value string, allowed ...string) bool { return oneOf(value, allowed...) }

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func NewRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	var encoded [36]byte
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded[:]), nil
}
