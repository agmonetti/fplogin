package analyze

import (
	"fmt"
	"path/filepath"
	"strings"

	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

// Classifier evaluates collected evidence from PAM, wallets, storage, session,
// and optional platform-provider probes to produce canonical, schema-compliant findings.
type Classifier struct{}

// NewClassifier creates a new findings classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// Classify evaluates core filesystem facts without platform-provider facts.
func (c *Classifier) Classify(pam *PAMStack, wallets *WalletFacts, storage *StorageFacts, session *SessionFacts) []analyzerv1.Finding {
	return c.ClassifyWithContext(pam, nil, wallets, storage, session, nil)
}

type platformSignals struct {
	pkgStatus          map[string]string
	pkgEvidence        map[string]protocol.Evidence
	pamFprintdStatus   string
	pamFprintdEvidence *protocol.Evidence
	fprintdServiceObs  string
	fprintdServiceEv   *protocol.Evidence
	fprintdEnrollObs   string
	fprintdEnrollEv    *protocol.Evidence
	kwalletDBusEv      []protocol.Evidence
	gnomeDBusEv        []protocol.Evidence
	otherDBusEv        []protocol.Evidence
	fprintdProbeErrors []platformv1.ProbeError
}

func extractPlatformSignals(pf *platformv1.PlatformAnalyzerFacts) platformSignals {
	sig := platformSignals{
		pkgStatus:   make(map[string]string),
		pkgEvidence: make(map[string]protocol.Evidence),
	}
	if pf == nil {
		return sig
	}

	for _, ev := range pf.Evidence {
		switch ev.Kind {
		case "package":
			status := parseKV(ev.ObservedValue, "status")
			if status == "" {
				if strings.Contains(strings.ToLower(ev.ObservedValue), "absent") {
					status = "absent"
				} else {
					status = "installed"
				}
			}
			sig.pkgStatus[ev.Subject] = status
			sig.pkgEvidence[ev.Subject] = ev
		case "service":
			if ev.Subject == "fprintd.service" {
				evCopy := ev
				sig.fprintdServiceObs = ev.ObservedValue
				sig.fprintdServiceEv = &evCopy
			}
		case "command":
			if ev.Subject == "fprintd-list" {
				evCopy := ev
				sig.fprintdEnrollObs = ev.ObservedValue
				sig.fprintdEnrollEv = &evCopy
			}
		case "path":
			if filepath.Base(ev.Subject) == "pam_fprintd.so" {
				evCopy := ev
				sig.pamFprintdStatus = parseKV(ev.ObservedValue, "status")
				sig.pamFprintdEvidence = &evCopy
			}
			if strings.Contains(ev.ObservedValue, "org.freedesktop.secrets") {
				lower := strings.ToLower(ev.Subject + " " + ev.ObservedValue)
				switch {
				case strings.Contains(lower, "kwallet"):
					sig.kwalletDBusEv = append(sig.kwalletDBusEv, ev)
				case strings.Contains(lower, "gnome") || strings.Contains(lower, "keyring"):
					sig.gnomeDBusEv = append(sig.gnomeDBusEv, ev)
				default:
					sig.otherDBusEv = append(sig.otherDBusEv, ev)
				}
			}
		}
	}

	for _, pe := range pf.ProbeErrors {
		if strings.HasPrefix(pe.ProbeID, "fprintd") {
			sig.fprintdProbeErrors = append(sig.fprintdProbeErrors, pe)
		}
	}

	return sig
}

func parseKV(observed, key string) string {
	for _, part := range strings.Split(observed, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func hasModuleEither(primary, secondary *PAMStack, module string, types ...string) bool {
	return (primary != nil && primary.HasModule(module, types...)) ||
		(secondary != nil && secondary.HasModule(module, types...))
}

func moduleEvidenceEither(primary, secondary *PAMStack, module string) []protocol.Evidence {
	var out []protocol.Evidence
	if primary != nil {
		out = append(out, primary.ModuleEvidence(module)...)
	}
	if secondary != nil {
		out = append(out, secondary.ModuleEvidence(module)...)
	}
	return out
}

func filterEvidenceBySubstring(evs []protocol.Evidence, substr string) []protocol.Evidence {
	var out []protocol.Evidence
	lower := strings.ToLower(substr)
	for _, ev := range evs {
		if strings.Contains(strings.ToLower(ev.Subject+" "+ev.ObservedValue), lower) {
			out = append(out, ev)
		}
	}
	return out
}

// ClassifyWithContext evaluates all core and platform facts and returns schema-compliant findings.
func (c *Classifier) ClassifyWithContext(
	pam, fpPAM *PAMStack,
	wallets *WalletFacts,
	storage *StorageFacts,
	session *SessionFacts,
	platformFacts *platformv1.PlatformAnalyzerFacts,
) []analyzerv1.Finding {
	var findings []analyzerv1.Finding
	psig := extractPlatformSignals(platformFacts)

	// -----------------------------------------------------------------------
	// 1. KWallet
	// -----------------------------------------------------------------------
	hasKWalletPAM := hasModuleEither(pam, fpPAM, "pam_kwallet5.so", "auth", "session") ||
		hasModuleEither(pam, fpPAM, "pam_kwallet.so", "auth", "session")
	if hasKWalletPAM {
		evidence := append(moduleEvidenceEither(pam, fpPAM, "pam_kwallet5.so"), moduleEvidenceEither(pam, fpPAM, "pam_kwallet.so")...)
		kwEvidence := []protocol.Evidence{}
		if wallets != nil {
			kwEvidence = filterEvidenceBySubstring(wallets.Evidence, "kwallet")
		}
		kwalletOptOnly := (pam == nil || (pam.AllOptionalIfMissing("pam_kwallet5.so") && pam.AllOptionalIfMissing("pam_kwallet.so"))) &&
			(fpPAM == nil || (fpPAM.AllOptionalIfMissing("pam_kwallet5.so") && fpPAM.AllOptionalIfMissing("pam_kwallet.so")))
		kwalletPkgAbsent := psig.pkgStatus["kwallet-pam"] == "absent" &&
			(wallets == nil || (!wallets.KWalletEnabled && !wallets.KWalletDataPresent))

		if kwalletOptOnly && kwalletPkgAbsent {
			evidence = append(evidence, psig.pkgEvidence["kwallet-pam"])
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "kwallet5_pam_optional_absent",
				Component:               analyzerv1.Component{ID: "kwallet5", Label: "KWallet Secret Storage"},
				Evidence:                evidence,
				FingerprintLoginImpact:  "No change: optional PAM KWallet hook ('-auth'/'-session') is skipped because kwallet-pam is not installed",
				PasswordLoginComparison: "PAM skips the missing module identically on both password and fingerprint login",
				Impact: analyzerv1.Impact{
					Severity:    "none",
					Description: "Optional PAM KWallet hook is inactive without kwallet-pam installed",
				},
				Confidence: "confirmed",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "action_none",
					Description: "No action needed",
				},
			})
		} else if wallets != nil && wallets.KWalletExplicitlyDisabled {
			evidence = append(evidence, kwEvidence...)
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "kwallet5_pam_disabled",
				Component:               analyzerv1.Component{ID: "kwallet5", Label: "KWallet Secret Storage"},
				Evidence:                evidence,
				FingerprintLoginImpact:  "No change: KWallet PAM hook is configured, but KWallet is explicitly disabled in user configuration",
				PasswordLoginComparison: "KWallet does not unlock on password login while disabled in kwalletrc",
				Impact: analyzerv1.Impact{
					Severity:    "none",
					Description: "KWallet is disabled for the inspected user",
				},
				Confidence: "confirmed",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "action_none",
					Description: "No action needed while KWallet remains disabled",
				},
			})
		} else {
			confidence := "likely"
			if wallets != nil && (wallets.KWalletEnabled || wallets.KWalletDataPresent) {
				confidence = "confirmed"
				evidence = append(evidence, kwEvidence...)
			}
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "kwallet5_pam_autounlock",
				Component:               analyzerv1.Component{ID: "kwallet5", Label: "KWallet Secret Storage"},
				Evidence:                evidence,
				FingerprintLoginImpact:  "KWallet remains locked after fingerprint login; applications requesting secrets will prompt for the wallet password",
				PasswordLoginComparison: "KWallet is unlocked automatically using the login password during PAM authentication",
				Impact: analyzerv1.Impact{
					Severity:    "degraded",
					Description: "Automatic PAM wallet unlock does not occur over biometric login",
				},
				Confidence: confidence,
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "suggest_kwallet_prompt",
					Description: "Unlock KWallet when prompted on first secret request, or use password login when automatic unlock is required",
					NextStep:    "No configuration change required unless unattended secret unlock is expected",
				},
			})
		}
	} else if session != nil && session.AutostartKWallet {
		ev := filterEvidenceBySubstring(session.Evidence, "kwallet")
		if len(ev) == 0 {
			ev = session.Evidence
		}
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "kwallet_session_startup",
			Component:               analyzerv1.Component{ID: "kwallet5", Label: "KWallet Secret Storage"},
			Evidence:                ev,
			FingerprintLoginImpact:  "No change: KWallet is launched by session startup without an observed PAM auto-unlock hook",
			PasswordLoginComparison: "Behaves identically to password login",
			Impact: analyzerv1.Impact{
				Severity:    "none",
				Description: "KWallet launch does not depend on PAM password pass-through",
			},
			Confidence: "confirmed",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "action_none",
				Description: "No action needed; session startup initializes KWallet",
			},
		})
	} else {
		var pkgEv []protocol.Evidence
		for _, name := range []string{"kwallet", "kwallet5", "kwallet-pam"} {
			if psig.pkgStatus[name] == "installed" {
				pkgEv = append(pkgEv, psig.pkgEvidence[name])
			}
		}
		pkgEv = append(pkgEv, psig.kwalletDBusEv...)
		if len(pkgEv) > 0 {
			// Package or D-Bus registration alone must NEVER be classified as confirmed degradation.
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "kwallet_installed_no_pam",
				Component:               analyzerv1.Component{ID: "kwallet5", Label: "KWallet Secret Storage"},
				Evidence:                pkgEv,
				FingerprintLoginImpact:  "KWallet package or Secret Service registration is present, but no PAM auto-unlock hook was observed in the inspected login stack",
				PasswordLoginComparison: "Without a PAM auto-unlock hook, password login and fingerprint login behave similarly unless unlocked elsewhere",
				Impact: analyzerv1.Impact{
					Severity:    "informational",
					Description: "Package presence alone does not confirm PAM password coupling",
				},
				Confidence: "likely",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "verify_kwallet_usage",
					Description: "Verify whether your desktop session expects automatic KWallet unlock on login",
				},
			})
		}
	}

	// -----------------------------------------------------------------------
	// 2. GNOME Keyring
	// -----------------------------------------------------------------------
	hasGnomeKeyringPAM := hasModuleEither(pam, fpPAM, "pam_gnome_keyring.so", "auth", "session")
	if hasGnomeKeyringPAM {
		evidence := moduleEvidenceEither(pam, fpPAM, "pam_gnome_keyring.so")
		gkOptOnly := (pam == nil || pam.AllOptionalIfMissing("pam_gnome_keyring.so")) &&
			(fpPAM == nil || fpPAM.AllOptionalIfMissing("pam_gnome_keyring.so"))
		gkPkgAbsent := psig.pkgStatus["gnome-keyring"] == "absent" &&
			(wallets == nil || !wallets.GnomeKeyringPresent)

		if gkOptOnly && gkPkgAbsent {
			evidence = append(evidence, psig.pkgEvidence["gnome-keyring"])
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "gnome_keyring_pam_optional_absent",
				Component:               analyzerv1.Component{ID: "gnome_keyring", Label: "GNOME Keyring Secret Service"},
				Evidence:                evidence,
				FingerprintLoginImpact:  "No change: optional PAM GNOME Keyring hook ('-auth'/'-session') is skipped because gnome-keyring is not installed",
				PasswordLoginComparison: "PAM skips the missing module identically on both password and fingerprint login",
				Impact: analyzerv1.Impact{
					Severity:    "none",
					Description: "Optional PAM GNOME Keyring hook is inactive without gnome-keyring installed",
				},
				Confidence: "confirmed",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "action_none",
					Description: "No action needed",
				},
			})
		} else {
			confidence := "likely"
			if wallets != nil && wallets.GnomeKeyringPresent {
				confidence = "confirmed"
				evidence = append(evidence, filterEvidenceBySubstring(wallets.Evidence, "keyring")...)
			}
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "gnome_keyring_pam_autounlock",
				Component:               analyzerv1.Component{ID: "gnome_keyring", Label: "GNOME Keyring Secret Service"},
				Evidence:                evidence,
				FingerprintLoginImpact:  "Login keyring remains locked after fingerprint login; applications requesting secrets will prompt for the keyring password",
				PasswordLoginComparison: "Login keyring unlocks automatically on password login via pam_gnome_keyring.so",
				Impact: analyzerv1.Impact{
					Severity:    "degraded",
					Description: "Automatic PAM keyring unlock does not occur when logging in via fingerprint",
				},
				Confidence: confidence,
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "suggest_keyring_manual_unlock",
					Description: "Enter the keyring password on the first application secret request, or use password login when silent unlock is needed",
					NextStep:    "Applications using Secret Service (browsers, Git credential helpers, editors) will prompt once per session",
				},
			})
		}
	} else if session != nil && session.AutostartGnomeKeyring {
		ev := filterEvidenceBySubstring(session.Evidence, "keyring")
		if len(ev) == 0 {
			ev = session.Evidence
		}
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "gnome_keyring_session_startup",
			Component:               analyzerv1.Component{ID: "gnome_keyring", Label: "GNOME Keyring Secret Service"},
			Evidence:                ev,
			FingerprintLoginImpact:  "No change: GNOME Keyring is started via desktop session startup without an observed PAM auto-unlock hook",
			PasswordLoginComparison: "Behaves identically to password login",
			Impact: analyzerv1.Impact{
				Severity:    "none",
				Description: "Keyring startup does not depend on PAM password pass-through",
			},
			Confidence: "confirmed",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "action_none",
				Description: "No action needed",
			},
		})
	} else {
		var pkgEv []protocol.Evidence
		if psig.pkgStatus["gnome-keyring"] == "installed" {
			pkgEv = append(pkgEv, psig.pkgEvidence["gnome-keyring"])
		}
		pkgEv = append(pkgEv, psig.gnomeDBusEv...)
		if len(pkgEv) > 0 {
			// Package or D-Bus registration alone must NEVER be classified as confirmed degradation.
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "gnome_keyring_installed_no_pam",
				Component:               analyzerv1.Component{ID: "gnome_keyring", Label: "GNOME Keyring Secret Service"},
				Evidence:                pkgEv,
				FingerprintLoginImpact:  "GNOME Keyring package or Secret Service registration is present, but no PAM auto-unlock hook was observed in the inspected login stack",
				PasswordLoginComparison: "Without pam_gnome_keyring.so in the login PAM stack, password and fingerprint login behave similarly",
				Impact: analyzerv1.Impact{
					Severity:    "informational",
					Description: "Package presence alone does not confirm PAM password coupling",
				},
				Confidence: "likely",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "verify_keyring_usage",
					Description: "Check whether your session starts GNOME Keyring manually or relies on PAM unlock",
				},
			})
		}
	}

	// Other D-Bus Secret Service providers (e.g. KeePassXC, custom providers)
	if len(psig.otherDBusEv) > 0 {
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "secret_service_provider_other",
			Component:               analyzerv1.Component{ID: "secret_service", Label: "Other Secret Service Provider"},
			Evidence:                psig.otherDBusEv,
			FingerprintLoginImpact:  "An additional org.freedesktop.secrets provider is registered; its coupling to login password cannot be determined statically",
			PasswordLoginComparison: "Behavior relative to password login depends on how the provider unlocks its database",
			Impact: analyzerv1.Impact{
				Severity:    "informational",
				Description: "Unclassified D-Bus Secret Service provider detected",
			},
			Confidence: "unknown",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "verify_secret_service_provider",
				Description: "Verify how this Secret Service provider unlocks after biometric login",
			},
		})
	}

	// -----------------------------------------------------------------------
	// 3. Encrypted storage: systemd-homed, pam_mount, crypttab
	// -----------------------------------------------------------------------
	hasSystemdHomePAM := hasModuleEither(pam, fpPAM, "pam_systemd_home.so", "auth", "session")
	if storage != nil && storage.SystemdHomedDetected {
		ev := filterEvidenceBySubstring(storage.Evidence, "systemd-homed")
		if len(ev) == 0 {
			ev = storage.Evidence
		}
		ev = append(ev, moduleEvidenceEither(pam, fpPAM, "pam_systemd_home.so")...)
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "systemd_homed_encryption",
			Component:               analyzerv1.Component{ID: "systemd_homed", Label: "systemd-homed User Storage"},
			Evidence:                ev,
			FingerprintLoginImpact:  "Encrypted home directory managed by systemd-homed cannot be unlocked with PAM fingerprint alone; password login is required",
			PasswordLoginComparison: "Password login provides the credential needed to unlock the systemd-homed area",
			Impact: analyzerv1.Impact{
				Severity:    "blocked",
				Description: "Biometric PAM authentication cannot unlock an encrypted systemd-homed identity",
			},
			Confidence: "confirmed",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "homed_password_required",
				Description: "Use password login or configure a systemd-homed FIDO2/PIN token instead of PAM fingerprint",
				NextStep:    "Authenticate with password at the display manager prompt",
			},
		})
	} else if hasSystemdHomePAM {
		ev := moduleEvidenceEither(pam, fpPAM, "pam_systemd_home.so")
		confidence := "likely"
		impactDesc := "pam_systemd_home.so is configured in PAM; no managed systemd-homed identity was observed for the inspected user"
		if storage != nil && storage.HomedDirUnreadable {
			confidence = "unknown"
			impactDesc = "pam_systemd_home.so is configured in PAM, but /var/lib/systemd/home could not be inspected"
		}
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "systemd_homed_pam_module",
			Component:               analyzerv1.Component{ID: "systemd_homed", Label: "systemd-homed PAM Module"},
			Evidence:                ev,
			FingerprintLoginImpact:  "pam_systemd_home.so is active in PAM; it blocks biometric-only unlock only for accounts managed by systemd-homed",
			PasswordLoginComparison: "Regular local accounts are unaffected; systemd-homed accounts require a password or hardware token",
			Impact: analyzerv1.Impact{
				Severity:    "informational",
				Description: impactDesc,
			},
			Confidence: confidence,
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "verify_homed_account",
				Description: "Confirm with 'homectl list' whether your user account is managed by systemd-homed",
			},
		})
	}

	// pam_mount
	hasPamMountPAM := hasModuleEither(pam, fpPAM, "pam_mount.so", "auth", "session")
	if hasPamMountPAM {
		ev := moduleEvidenceEither(pam, fpPAM, "pam_mount.so")
		confidence := "likely"
		severity := "degraded"
		if storage != nil && storage.PamMountConfigPresent && storage.PamMountVolumeCount > 0 {
			confidence = "confirmed"
			ev = append(ev, filterEvidenceBySubstring(storage.Evidence, "pam_mount")...)
			if storage.PamMountHomeVolume {
				severity = "blocked"
			}
		}
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "pam_mount_login_volume",
			Component:               analyzerv1.Component{ID: "pam_mount", Label: "pam_mount Login-Time Encrypted Volumes"},
			Evidence:                ev,
			FingerprintLoginImpact:  "Volumes mounted via pam_mount.so using the login password will not mount automatically during fingerprint login",
			PasswordLoginComparison: "pam_mount.so reuses the PAM password token during password login to unlock and mount volumes",
			Impact: analyzerv1.Impact{
				Severity:    severity,
				Description: "Login-time password pass-through for pam_mount volumes is unavailable under biometric login",
			},
			Confidence: confidence,
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "pam_mount_password_or_boot",
				Description: "Use password login when pam_mount volumes are required, or unlock volumes at boot instead of login",
			},
		})
	} else if psig.pkgStatus["pam_mount"] == "installed" {
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "pam_mount_installed_no_pam",
			Component:               analyzerv1.Component{ID: "pam_mount", Label: "pam_mount Package"},
			Evidence:                []protocol.Evidence{psig.pkgEvidence["pam_mount"]},
			FingerprintLoginImpact:  "pam_mount is installed, but pam_mount.so was not observed in the inspected login PAM stack",
			PasswordLoginComparison: "Without pam_mount.so in the login PAM stack, login behavior is unchanged",
			Impact: analyzerv1.Impact{
				Severity:    "informational",
				Description: "Package presence alone does not confirm login-time encrypted mount coupling",
			},
			Confidence: "likely",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "verify_pam_mount_config",
				Description: "Verify whether /etc/security/pam_mount.conf.xml defines login-time volumes",
			},
		})
	}

	// /etc/crypttab: distinguish boot-time LUKS unlock from keyscript/login-coupled unlock
	if storage != nil && storage.CrypttabLoginCoupled {
		ev := filterEvidenceBySubstring(storage.Evidence, "crypttab")
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "luks_crypttab_login_coupled",
			Component:               analyzerv1.Component{ID: "crypttab", Label: "LUKS crypttab Keyscript Volume"},
			Evidence:                ev,
			FingerprintLoginImpact:  "A crypttab entry uses a custom keyscript; if it relies on login-time password pass-through, biometric login will not supply a password",
			PasswordLoginComparison: "Custom keyscripts may depend on password availability depending on boot vs login invocation",
			Impact: analyzerv1.Impact{
				Severity:    "blocked",
				Description: "Keyscript-backed crypttab entry has unknown login-time password dependency",
			},
			Confidence: "unknown",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "crypttab_verify_keyscript",
				Description: "Verify that the keyscript unlocks the volume at boot before the display manager starts",
			},
		})
	}
	if storage != nil && storage.CrypttabBootHome {
		ev := filterEvidenceBySubstring(storage.Evidence, "crypttab")
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "luks_crypttab_boot_unlock",
			Component:               analyzerv1.Component{ID: "crypttab", Label: "LUKS Boot-Time Home Volume"},
			Evidence:                ev,
			FingerprintLoginImpact:  "No change expected: /etc/crypttab home volume without a keyscript is typically unlocked at boot before the display manager starts",
			PasswordLoginComparison: "Both password and fingerprint login run after boot-time cryptsetup unlock completes",
			Impact: analyzerv1.Impact{
				Severity:    "none",
				Description: "Boot-time LUKS unlock occurs prior to display-manager login",
			},
			Confidence: "likely",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "action_none",
				Description: "No action needed unless this volume is configured for login-time PAM mounting",
			},
		})
	}

	// -----------------------------------------------------------------------
	// 4. Custom or incomplete PAM configuration
	// -----------------------------------------------------------------------
	customMods := []PAMModule{}
	if pam != nil {
		customMods = append(customMods, pam.CustomModules...)
	}
	if fpPAM != nil {
		customMods = append(customMods, fpPAM.CustomModules...)
	}
	if len(customMods) > 0 {
		var ev []protocol.Evidence
		var names []string
		seenName := map[string]bool{}
		for _, m := range customMods {
			ev = append(ev, coreEvidence("path", m.SourceFile, fmt.Sprintf("line=%d %s %s %s", m.LineNumber, m.Type, m.Control, m.Module)))
			if !seenName[m.Module] {
				seenName[m.Module] = true
				names = append(names, m.Module)
			}
		}
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "pam_custom_modules",
			Component:               analyzerv1.Component{ID: "pam_custom", Label: "Unrecognized PAM Modules"},
			Evidence:                ev,
			FingerprintLoginImpact:  fmt.Sprintf("Unrecognized auth/session PAM module(s) (%s) may depend on a password token that fingerprint login does not provide", strings.Join(names, ", ")),
			PasswordLoginComparison: "During password login these modules receive the user password via PAM_AUTHTOK if configured",
			Impact: analyzerv1.Impact{
				Severity:    "informational",
				Description: "Custom or third-party PAM modules cannot be classified automatically",
			},
			Confidence: "unknown",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "review_custom_pam",
				Description: "Review whether these custom PAM modules require PAM_AUTHTOK or password pass-through",
			},
		})
	}

	var pamIssueEv []protocol.Evidence
	for _, st := range []*PAMStack{pam, fpPAM} {
		if st == nil {
			continue
		}
		for _, iss := range st.Issues {
			if iss.Code == "pam_missing_include" || iss.Code == "pam_depth_truncated" || iss.Code == "pam_include_cycle" || iss.Code == "pam_read_error" || iss.Code == "pam_parse_error" {
				pamIssueEv = append(pamIssueEv, iss.Evidence...)
			}
		}
	}
	if len(pamIssueEv) > 0 {
		findings = append(findings, analyzerv1.Finding{
			FindingID:               "pam_incomplete_analysis",
			Component:               analyzerv1.Component{ID: "pam_stack", Label: "PAM Configuration Visibility"},
			Evidence:                pamIssueEv,
			FingerprintLoginImpact:  "Part of the PAM include stack could not be read or resolved; password-derived modules in unresolved files may be missed",
			PasswordLoginComparison: "Full PAM behavior could not be verified statically from the accessible files",
			Impact: analyzerv1.Impact{
				Severity:    "informational",
				Description: "PAM stack traversal encountered missing, unreadable, cyclic, or truncated directives",
			},
			Confidence: "unknown",
			SuggestedAction: &analyzerv1.SuggestedAction{
				ActionID:    "inspect_pam_includes",
				Description: "Inspect the referenced PAM files and includes listed in Limitations",
			},
		})
	}

	// -----------------------------------------------------------------------
	// 5. Biometric readiness (fprintd / pam_fprintd) from PlatformAnalyzerFacts
	// -----------------------------------------------------------------------
	if platformFacts != nil {
		biometricBlocker := false

		if psig.pkgStatus["fprintd"] == "absent" {
			biometricBlocker = true
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "fprintd_package_missing",
				Component:               analyzerv1.Component{ID: "fprintd", Label: "fprintd Biometric Stack"},
				Evidence:                []protocol.Evidence{psig.pkgEvidence["fprintd"]},
				FingerprintLoginImpact:  "Fingerprint login cannot run because the fprintd package is not installed",
				PasswordLoginComparison: "Password login continues to work normally",
				Impact: analyzerv1.Impact{
					Severity:    "blocked",
					Description: "Required biometric daemon package is absent",
				},
				Confidence: "confirmed",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "install_fprintd",
					Description: "Install fprintd and enroll at least one fingerprint before using biometric login",
				},
			})
		}

		if psig.pamFprintdStatus == "absent" && psig.pamFprintdEvidence != nil {
			biometricBlocker = true
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "pam_fprintd_missing",
				Component:               analyzerv1.Component{ID: "pam_fprintd", Label: "pam_fprintd PAM Module"},
				Evidence:                []protocol.Evidence{*psig.pamFprintdEvidence},
				FingerprintLoginImpact:  "Fingerprint PAM authentication cannot run because pam_fprintd.so is absent",
				PasswordLoginComparison: "Password login continues to work normally",
				Impact: analyzerv1.Impact{
					Severity:    "blocked",
					Description: "pam_fprintd.so shared object was not found",
				},
				Confidence: "confirmed",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "install_fprintd",
					Description: "Install the package providing /usr/lib/security/pam_fprintd.so",
				},
			})
		}

		if psig.fprintdServiceEv != nil {
			load := parseKV(psig.fprintdServiceObs, "load")
			enabled := parseKV(psig.fprintdServiceObs, "enabled")
			if load == "not-found" || load == "masked" || enabled == "masked" || enabled == "masked-runtime" {
				biometricBlocker = true
				findings = append(findings, analyzerv1.Finding{
					FindingID:               "fprintd_service_unavailable",
					Component:               analyzerv1.Component{ID: "fprintd", Label: "fprintd systemd Service"},
					Evidence:                []protocol.Evidence{*psig.fprintdServiceEv},
					FingerprintLoginImpact:  "Fingerprint login cannot activate fprintd.service because the unit is missing or masked",
					PasswordLoginComparison: "Password login does not depend on fprintd.service",
					Impact: analyzerv1.Impact{
						Severity:    "blocked",
						Description: "fprintd.service cannot be D-Bus activated",
					},
					Confidence: "confirmed",
					SuggestedAction: &analyzerv1.SuggestedAction{
						ActionID:    "unmask_fprintd",
						Description: "Ensure fprintd is installed and fprintd.service is not masked",
					},
				})
			}
		}

		if psig.fprintdEnrollEv != nil {
			status := parseKV(psig.fprintdEnrollObs, "status")
			switch status {
			case "no_reader":
				biometricBlocker = true
				findings = append(findings, analyzerv1.Finding{
					FindingID:               "fprintd_no_reader",
					Component:               analyzerv1.Component{ID: "fprintd", Label: "Fingerprint Reader Hardware"},
					Evidence:                []protocol.Evidence{*psig.fprintdEnrollEv},
					FingerprintLoginImpact:  "No supported fingerprint reader was detected by fprintd; login falls back to password",
					PasswordLoginComparison: "Password login works identically",
					Impact: analyzerv1.Impact{
						Severity:    "blocked",
						Description: "No libfprint/fprintd-supported reader is currently available",
					},
					Confidence: "confirmed",
					SuggestedAction: &analyzerv1.SuggestedAction{
						ActionID:    "check_reader_hardware",
						Description: "Verify reader connection and libfprint device support with 'fprintd-list'",
					},
				})
			case "no_enrolled_fingers":
				biometricBlocker = true
				findings = append(findings, analyzerv1.Finding{
					FindingID:               "fprintd_no_enrolled_fingers",
					Component:               analyzerv1.Component{ID: "fprintd", Label: "Enrolled Fingerprints"},
					Evidence:                []protocol.Evidence{*psig.fprintdEnrollEv},
					FingerprintLoginImpact:  "A fingerprint reader is present, but the inspected user has no enrolled fingerprints; login will use password",
					PasswordLoginComparison: "Password login works identically",
					Impact: analyzerv1.Impact{
						Severity:    "blocked",
						Description: "No fingerprints enrolled for the inspected user",
					},
					Confidence: "confirmed",
					SuggestedAction: &analyzerv1.SuggestedAction{
						ActionID:    "enroll_fingerprint",
						Description: "Enroll at least one finger for your user account",
						NextStep:    "Run 'fprintd-enroll' as your regular desktop user",
					},
				})
			case "enrolled":
				findings = append(findings, analyzerv1.Finding{
					FindingID:               "fprintd_ready",
					Component:               analyzerv1.Component{ID: "fprintd", Label: "fprintd Biometric Stack"},
					Evidence:                []protocol.Evidence{*psig.fprintdEnrollEv},
					FingerprintLoginImpact:  "Fingerprint reader and enrolled prints are available for the inspected user",
					PasswordLoginComparison: "Both fingerprint and password login are available",
					Impact: analyzerv1.Impact{
						Severity:    "none",
						Description: "Biometric prerequisites observed ready for the inspected user",
					},
					Confidence: "confirmed",
					SuggestedAction: &analyzerv1.SuggestedAction{
						ActionID:    "action_none",
						Description: "No biometric setup action required",
					},
				})
			}
		}

		if !biometricBlocker && psig.fprintdEnrollEv == nil && len(psig.fprintdProbeErrors) > 0 {
			var ev []protocol.Evidence
			for _, pe := range psig.fprintdProbeErrors {
				if len(pe.Evidence) > 0 {
					ev = append(ev, pe.Evidence...)
				} else {
					ev = append(ev, coreErrorEvidence("derived", pe.ProbeID, "probe error", pe.Message))
				}
			}
			findings = append(findings, analyzerv1.Finding{
				FindingID:               "fprintd_readiness_unknown",
				Component:               analyzerv1.Component{ID: "fprintd", Label: "fprintd Biometric Readiness"},
				Evidence:                ev,
				FingerprintLoginImpact:  "Could not verify fprintd service, reader, or fingerprint enrollment status in this environment",
				PasswordLoginComparison: "Password login does not depend on fprintd availability",
				Impact: analyzerv1.Impact{
					Severity:    "informational",
					Description: "Biometric readiness could not be confirmed due to probe error or unavailable D-Bus",
				},
				Confidence: "unknown",
				SuggestedAction: &analyzerv1.SuggestedAction{
					ActionID:    "verify_fprintd_manually",
					Description: "Verify reader and enrolled fingerprints manually with 'fprintd-list <user>'",
				},
			})
		}
	}

	return findings
}
