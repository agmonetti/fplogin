// Package v1 implements the Go representation and validation boundary for
// analyzer v1 findings and machine-readable reports.
package v1

import (
	"errors"
	"fmt"
	"regexp"

	"fplogin/internal/protocol"
)

const SchemaVersion = "1.0"

var findingIDPattern = regexp.MustCompile(`^[a-z0-9_.-]+$`)

type Component struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Impact struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type SuggestedAction struct {
	ActionID    string `json:"action_id"`
	Description string `json:"description"`
	NextStep    string `json:"next_step,omitempty"`
}

type Finding struct {
	FindingID               string              `json:"finding_id"`
	Component               Component           `json:"component"`
	Evidence                []protocol.Evidence `json:"evidence"`
	FingerprintLoginImpact  string              `json:"fingerprint_login_impact"`
	PasswordLoginComparison string              `json:"password_login_comparison"`
	Impact                  Impact              `json:"impact"`
	Confidence              string              `json:"confidence"`
	SuggestedAction         *SuggestedAction    `json:"suggested_action"`
}

func (f *Finding) UnmarshalJSON(data []byte) error {
	type wire Finding
	var decoded wire
	if err := protocol.RequireFieldsAllowNull(data, "finding_id", "component", "evidence", "fingerprint_login_impact", "password_login_comparison", "impact", "confidence", "suggested_action"); err != nil {
		return err
	}
	if err := protocol.DecodeStrict(data, &decoded); err != nil {
		return err
	}
	*f = Finding(decoded)
	return nil
}

func DecodeFinding(data []byte) (Finding, error) {
	var finding Finding
	err := protocol.DecodeStrict(data, &finding)
	if err == nil {
		err = finding.Validate()
	}
	return finding, err
}

func (f Finding) Validate() error {
	if !findingIDPattern.MatchString(f.FindingID) || f.Component.ID == "" || f.Component.Label == "" || len(f.Evidence) == 0 || f.FingerprintLoginImpact == "" || f.PasswordLoginComparison == "" || !protocol.OneOf(f.Impact.Severity, "none", "informational", "degraded", "blocked") || f.Impact.Description == "" || !protocol.OneOf(f.Confidence, "confirmed", "likely", "unknown") {
		return errors.New("invalid analyzer finding")
	}
	for _, evidence := range f.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
	}
	if f.SuggestedAction != nil && (f.SuggestedAction.ActionID == "" || f.SuggestedAction.Description == "") {
		return errors.New("invalid suggested action")
	}
	return nil
}

type ProviderIdentity struct {
	ID               string `json:"id"`
	Version          string `json:"version"`
	DescriptorSHA256 string `json:"descriptor_sha256"`
}
type Target struct {
	AdapterID  *string `json:"adapter_id"`
	InstanceID *string `json:"instance_id"`
}
type Limitation struct {
	Code     string              `json:"code"`
	Message  string              `json:"message"`
	Evidence []protocol.Evidence `json:"evidence"`
}
type Report struct {
	SchemaVersion    string           `json:"schema_version"`
	AnalyzerVersion  string           `json:"analyzer_version"`
	GeneratedAt      string           `json:"generated_at"`
	PlatformProvider ProviderIdentity `json:"platform_provider"`
	Target           Target           `json:"target"`
	Findings         []Finding        `json:"findings"`
	Limitations      []Limitation     `json:"limitations"`
}

func (t *Target) UnmarshalJSON(data []byte) error {
	type wire Target
	var decoded wire
	if err := protocol.RequireFieldsAllowNull(data, "adapter_id", "instance_id"); err != nil {
		return err
	}
	if err := protocol.DecodeStrict(data, &decoded); err != nil {
		return err
	}
	*t = Target(decoded)
	return nil
}

func DecodeReport(data []byte) (Report, error) {
	var report Report
	err := protocol.DecodeStrict(data, &report, "schema_version", "analyzer_version", "generated_at", "platform_provider", "target", "findings", "limitations")
	if err == nil {
		err = report.Validate()
	}
	return report, err
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion || r.AnalyzerVersion == "" || r.PlatformProvider.ID == "" || r.PlatformProvider.Version == "" || r.Findings == nil || r.Limitations == nil {
		return errors.New("invalid analyzer report identity")
	}
	if err := protocol.ValidTimestamp(r.GeneratedAt); err != nil {
		return err
	}
	if err := protocol.ValidDigest(r.PlatformProvider.DescriptorSHA256); err != nil {
		return err
	}
	if (r.Target.AdapterID == nil) != (r.Target.InstanceID == nil) {
		return errors.New("analyzer target identity must be entirely set or null")
	}
	for _, finding := range r.Findings {
		if err := finding.Validate(); err != nil {
			return err
		}
	}
	for _, limitation := range r.Limitations {
		if limitation.Code == "" || limitation.Message == "" || limitation.Evidence == nil {
			return errors.New("invalid analyzer limitation")
		}
		for _, evidence := range limitation.Evidence {
			if err := evidence.Validate(); err != nil {
				return fmt.Errorf("limitation evidence: %w", err)
			}
		}
	}
	return nil
}
