package analyze

import (
	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
)

// Classifier evaluates collected evidence from PAM, wallets, storage, and session probes
// to produce canonical, schema-compliant analyzer findings.
type Classifier struct{}

// NewClassifier creates a new findings classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// Classify evaluates all facts and returns the set of findings.
func (c *Classifier) Classify(pam *PAMStack, wallets *WalletFacts, storage *StorageFacts, session *SessionFacts) []analyzerv1.Finding {
	var findings []analyzerv1.Finding

	// -----------------------------------------------------------------------
	// 1. KWallet
	// -----------------------------------------------------------------------
	hasKWalletPAM := pam != nil && pam.HasModule("pam_kwallet5.so", "auth", "session")
	if hasKWalletPAM {
		evidence := append([]protocol.Evidence{}, pam.Evidence...)
		confidence := "likely"
		if wallets != nil && wallets.KWalletEnabled {
			confidence = "confirmed"
			evidence = append(evidence, wallets.Evidence...)
		}

		findings = append(findings, analyzerv1.Finding{
			FindingID: "kwallet5_pam_autounlock",
			Component: analyzerv1.Component{
				ID:    "kwallet5",
				Label: "KWallet Secret Storage",
			},
			Evidence:                evidence,
			FingerprintLoginImpact:  "KWallet remains locked after login; applications requesting secrets prompt for password",
			PasswordLoginComparison: "KWallet is automatically unlocked by password during PAM authentication",
			Impact: analyzerv1.Impact{
				Severity:    "degraded",
				Description: "Wallet unlock does not occur over biometric authentication path",
			},
			Confidence: confidence,
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "suggest_kwallet_prompt",
				Description: "Unlock wallet on first prompt or configure pam_kwallet auto-prompting",
				NextStep:    "None required unless user expects silent wallet unlock",
			},
		})
	} else if session != nil && session.AutostartKWallet {
		// Launched by session autostart, not by PAM
		findings = append(findings, analyzerv1.Finding{
			FindingID: "kwallet_session_startup",
			Component: analyzerv1.Component{
				ID:    "kwallet5",
				Label: "KWallet Secret Storage",
			},
			Evidence:                session.Evidence,
			FingerprintLoginImpact:  "No change: KWallet is launched by session startup rather than unlocked by PAM",
			PasswordLoginComparison: "Behaves identically to password login",
			Impact: analyzerv1.Impact{
				Severity:    "none",
				Description: "KWallet unlock is not tied to PAM password authentication",
			},
			Confidence: "confirmed",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "action_none",
				Description: "No action needed; session startup handles agent initialization",
			},
		})
	}

	// -----------------------------------------------------------------------
	// 2. GNOME Keyring
	// -----------------------------------------------------------------------
	hasGnomeKeyringPAM := pam != nil && pam.HasModule("pam_gnome_keyring.so", "auth", "session")
	if hasGnomeKeyringPAM {
		evidence := append([]protocol.Evidence{}, pam.Evidence...)
		confidence := "likely"
		if wallets != nil && wallets.GnomeKeyringPresent {
			confidence = "confirmed"
			evidence = append(evidence, wallets.Evidence...)
		}

		findings = append(findings, analyzerv1.Finding{
			FindingID: "gnome_keyring_pam_autounlock",
			Component: analyzerv1.Component{
				ID:    "gnome_keyring",
				Label: "GNOME Keyring Secret Service",
			},
			Evidence:                evidence,
			FingerprintLoginImpact:  "Login keyring remains locked after biometric authentication; unlock prompt shown on secret access",
			PasswordLoginComparison: "Keyring unlocks automatically on password login",
			Impact: analyzerv1.Impact{
				Severity:    "degraded",
				Description: "Keyring autounlock disabled when logging in via fingerprint",
			},
			Confidence: confidence,
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "suggest_keyring_manual_unlock",
				Description: "Provide keyring password on first application request or set blank keyring password if security model permits",
				NextStep:    "Unlock prompt will appear when Chrome, VS Code, or Git requests secrets",
			},
		})
	} else if session != nil && session.AutostartGnomeKeyring {
		findings = append(findings, analyzerv1.Finding{
			FindingID: "gnome_keyring_session_startup",
			Component: analyzerv1.Component{
				ID:    "gnome_keyring",
				Label: "GNOME Keyring Secret Service",
			},
			Evidence:                session.Evidence,
			FingerprintLoginImpact:  "No change: Keyring daemon is started via desktop session autostart rather than unlocked by PAM",
			PasswordLoginComparison: "Behaves identically to password login",
			Impact: analyzerv1.Impact{
				Severity:    "none",
				Description: "Keyring daemon launch does not depend on PAM password",
			},
			Confidence: "confirmed",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "action_none",
				Description: "No action needed",
			},
		})
	}

	// -----------------------------------------------------------------------
	// 3. Encrypted storage / systemd-homed
	// -----------------------------------------------------------------------
	if storage != nil && storage.SystemdHomedDetected {
		findings = append(findings, analyzerv1.Finding{
			FindingID: "systemd_homed_encryption",
			Component: analyzerv1.Component{
				ID:    "systemd_homed",
				Label: "systemd-homed User Storage",
			},
			Evidence:                storage.Evidence,
			FingerprintLoginImpact:  "Encrypted home directory cannot be unlocked with fingerprint alone; requires password on login",
			PasswordLoginComparison: "Unlocks home directory automatically with password",
			Impact: analyzerv1.Impact{
				Severity:    "blocked",
				Description: "Biometric login without password cannot activate encrypted systemd-homed record",
			},
			Confidence: "confirmed",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "homed_password_required",
				Description: "Use password login or configure systemd-homed FIDO2/PIN token instead of PAM fingerprint",
				NextStep:    "Authenticate with password at display manager prompt",
			},
		})
	}

	if storage != nil && storage.CrypttabHasUserHome {
		findings = append(findings, analyzerv1.Finding{
			FindingID: "luks_crypttab_user_home",
			Component: analyzerv1.Component{
				ID:    "crypttab",
				Label: "LUKS Encrypted Home Mount",
			},
			Evidence:                storage.Evidence,
			FingerprintLoginImpact:  "Encrypted user volume configured in crypttab may fail to unlock without PAM password pass-through",
			PasswordLoginComparison: "Password is piped to keyscript/cryptsetup during login",
			Impact: analyzerv1.Impact{
				Severity:    "blocked",
				Description: "Volume requires password token not available during biometric login",
			},
			Confidence: "likely",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "crypttab_manual_passphrase",
				Description: "Ensure home volume is mounted at boot before display manager starts",
			},
		})
	}

	return findings
}
