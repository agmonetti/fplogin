package report

import (
	"strings"
	"testing"
	"time"

	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
)

func sampleReport() analyzerv1.Report {
	now := time.Now().UTC().Format(time.RFC3339)
	targetAdapter := "org.fplogin.adapter.sddm"
	targetInstance := "sddm-inst"

	return analyzerv1.Report{
		SchemaVersion:   analyzerv1.SchemaVersion,
		AnalyzerVersion: "0.2.0",
		GeneratedAt:     now,
		PlatformProvider: analyzerv1.ProviderIdentity{
			ID:               "org.fplogin.platform.arch",
			Version:          "1.0.0",
			DescriptorSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Target: analyzerv1.Target{
			AdapterID:  &targetAdapter,
			InstanceID: &targetInstance,
		},
		Findings: []analyzerv1.Finding{
			{
				FindingID: "kwallet5_pam_autounlock",
				Component: analyzerv1.Component{
					ID:    "kwallet5",
					Label: "KWallet Secret Storage",
				},
				Evidence: []protocol.Evidence{
					{
						Source:        "core",
						Kind:          "path",
						Subject:       "/etc/pam.d/sddm",
						ObservedValue: "session optional pam_kwallet5.so",
						Timestamp:     now,
					},
				},
				FingerprintLoginImpact:  "KWallet remains locked",
				PasswordLoginComparison: "KWallet auto-unlocks on password",
				Impact: analyzerv1.Impact{
					Severity:    "degraded",
					Description: "Unlock does not occur",
				},
				Confidence: "confirmed",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "suggest_kwallet_prompt",
					Description: "Unlock manually",
				},
			},
		},
		Limitations: []analyzerv1.Limitation{
			{
				Code:     "known_blind_spots",
				Message:  "Does not inspect wallet contents or process memory.",
				Evidence: []protocol.Evidence{},
			},
			{
				Code:     "unscanned_user_sessions",
				Message:  "User home not scanned",
				Evidence: []protocol.Evidence{},
			},
		},
	}
}

func TestFormatJSON(t *testing.T) {
	r := sampleReport()
	data, err := FormatJSON(r)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	decoded, err := analyzerv1.DecodeReport(data)
	if err != nil {
		t.Fatalf("DecodeReport on formatted JSON failed: %v", err)
	}
	if len(decoded.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(decoded.Findings))
	}
}

func TestFormatTerminal(t *testing.T) {
	r := sampleReport()
	out := FormatTerminal(r)

	if !strings.Contains(out, "[DEGRADED / confirmed] KWallet Secret Storage") {
		t.Errorf("expected header with DEGRADED / confirmed, got:\n%s", out)
	}
	if !strings.Contains(out, "KWallet remains locked") {
		t.Errorf("expected impact description in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Limitations / Unscanned Scope") {
		t.Errorf("expected limitations section, got:\n%s", out)
	}
	if !strings.Contains(out, "sudo, su, polkit, ssh, screen lockers") {
		t.Errorf("expected login vs independent auth scope distinction, got:\n%s", out)
	}
}

func TestFormatTerminal_CleanSystemNoFalseSafetyOverclaim(t *testing.T) {
	r := sampleReport()
	r.Findings = []analyzerv1.Finding{}

	out := FormatTerminal(r)
	lower := strings.ToLower(out)

	banned := []string{
		"fingerprint login is safe",
		"without expected secret unlock issues",
		"guaranteed safe",
	}
	for _, phrase := range banned {
		if strings.Contains(lower, phrase) {
			t.Errorf("clean terminal output must not contain overclaim phrase %q:\n%s", phrase, out)
		}
	}

	required := []string{
		"No known PAM-coupled password-derived facilities were observed within the inspected scope",
		"Absence of findings does not guarantee identical behavior",
		"sudo, su, polkit, ssh, screen lockers",
		"Limitations / Unscanned Scope",
	}
	for _, phrase := range required {
		if !strings.Contains(out, phrase) {
			t.Errorf("clean terminal output missing required phrase %q:\n%s", phrase, out)
		}
	}

	data, err := FormatJSON(r)
	if err != nil {
		t.Fatalf("FormatJSON clean report failed: %v", err)
	}
	if _, err := analyzerv1.DecodeReport(data); err != nil {
		t.Fatalf("DecodeReport clean report failed: %v", err)
	}
}
