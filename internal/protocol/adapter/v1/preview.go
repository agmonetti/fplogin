package v1

import platformv1 "fplogin/internal/protocol/platform/v1"

// PreflightFacts is the read-only snapshot used by installer previews. It carries
// no transaction state, approvals or staged artifacts.
type PreflightFacts struct {
	Packages []platformv1.PackageCandidate `json:"packages"`
	Services []platformv1.ServiceCandidate `json:"services"`
}

// InstallPreview is deliberately not a ChangePlan: its package artifacts have
// not been resolved, verified or staged, so the transaction engine cannot use it.
type InstallPreview struct {
	TargetInstanceID string          `json:"target_instance_id"`
	Changes          []PreviewChange `json:"changes"`
	Replacement      []string        `json:"display_manager_replacement"`
	Limitations      []string        `json:"limitations"`
}

type PreviewChange struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Detail   string `json:"detail,omitempty"`
}
