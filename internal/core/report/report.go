// Package report formats analyzer reports for terminal display and machine-readable JSON export.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
)

// FormatJSON serializes the analyzer report to indented JSON bytes.
func FormatJSON(r analyzerv1.Report) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("validate report: %w", err)
	}
	return json.MarshalIndent(r, "", "  ")
}

// FormatTerminal produces a clear, evidence-scoped terminal summary that avoids
// overstating certainty and separates login-session effects from later auth flows.
func FormatTerminal(r analyzerv1.Report) string {
	var b strings.Builder

	b.WriteString("─────────────────────────────────────────────────────────────\n")
	b.WriteString("System Analysis: Password-Derived Facilities\n")
	b.WriteString("─────────────────────────────────────────────────────────────\n")
	b.WriteString("Scope: Display-manager login session only; independent auth flows (sudo, su, polkit, ssh, screen lockers) are unchanged.\n\n")

	if len(r.Findings) == 0 {
		b.WriteString("No known PAM-coupled password-derived facilities were observed within the inspected scope.\n")
		b.WriteString("Absence of findings does not guarantee identical behavior for every application; review Limitations below.\n")
	} else {
		for i, f := range r.Findings {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(fmt.Sprintf("[%s / %s] %s\n",
				strings.ToUpper(f.Impact.Severity), f.Confidence, f.Component.Label))
			b.WriteString(fmt.Sprintf("  Component:   %s (%s)\n", f.Component.Label, f.Component.ID))
			b.WriteString(fmt.Sprintf("  Impact:      %s\n", f.FingerprintLoginImpact))
			b.WriteString(fmt.Sprintf("  Vs Password: %s\n", f.PasswordLoginComparison))

			if len(f.Evidence) > 0 {
				b.WriteString("  Evidence:\n")
				for _, ev := range f.Evidence {
					obs := ev.ObservedValue
					if strings.Contains(obs, "\n") {
						obs = strings.ReplaceAll(obs, "\n", " | ")
					}
					if ev.Error != "" {
						b.WriteString(fmt.Sprintf("    - [%s] %s (%s): %s (error: %s)\n", ev.Source, ev.Subject, ev.Kind, obs, ev.Error))
					} else {
						b.WriteString(fmt.Sprintf("    - [%s] %s (%s): %s\n", ev.Source, ev.Subject, ev.Kind, obs))
					}
				}
			}

			if f.SuggestedAction != nil {
				b.WriteString(fmt.Sprintf("  Action:      %s\n", f.SuggestedAction.Description))
				if f.SuggestedAction.NextStep != "" {
					b.WriteString(fmt.Sprintf("  Next Step:   %s\n", f.SuggestedAction.NextStep))
				}
			}
		}
	}

	if len(r.Limitations) > 0 {
		b.WriteString("\nLimitations / Unscanned Scope:\n")
		for _, lim := range r.Limitations {
			b.WriteString(fmt.Sprintf("  - [%s] %s\n", lim.Code, lim.Message))
		}
	}

	b.WriteString("─────────────────────────────────────────────────────────────\n")
	return b.String()
}
