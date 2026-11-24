package analyze

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

// EngineConfig holds configuration for a complete system difference analysis run.
type EngineConfig struct {
	Root                  string
	Username              string
	UserHome              string
	ServiceName           string // defaults to "display-manager"
	PlatformProvider      analyzerv1.ProviderIdentity
	Target                analyzerv1.Target
	PlatformFacts         *platformv1.PlatformAnalyzerFacts
	OfflineMode           bool
	AdditionalLimitations []analyzerv1.Limitation
	AnalyzerVersion       string
}

// Engine coordinates the execution of read-only probes and findings classification.
type Engine struct {
	classifier *Classifier
}

// NewEngine creates a new Analyzer Engine.
func NewEngine() *Engine {
	return &Engine{
		classifier: NewClassifier(),
	}
}

// OfflineProviderIdentity returns deterministic, non-zero metadata identifying
// an offline or core-only analysis run when no live platform provider is attached.
func OfflineProviderIdentity(analyzerVersion string) analyzerv1.ProviderIdentity {
	if analyzerVersion == "" {
		analyzerVersion = "0.2.0"
	}
	const id = "org.fplogin.platform.offline"
	sum := sha256.Sum256([]byte(id + ":" + analyzerVersion))
	return analyzerv1.ProviderIdentity{
		ID:               id,
		Version:          analyzerVersion,
		DescriptorSHA256: fmt.Sprintf("%x", sum),
	}
}

// Analyze runs the read-only probes, evaluates evidence, and builds an analyzer report.
func (e *Engine) Analyze(_ context.Context, cfg EngineConfig) (analyzerv1.Report, error) {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "display-manager"
	}
	if cfg.AnalyzerVersion == "" {
		cfg.AnalyzerVersion = "0.2.0"
	}
	if cfg.PlatformProvider.ID == "" {
		cfg.PlatformProvider = OfflineProviderIdentity(cfg.AnalyzerVersion)
	}

	if cfg.PlatformFacts != nil {
		if err := cfg.PlatformFacts.Validate(); err != nil {
			return analyzerv1.Report{}, fmt.Errorf("validate platform analyzer facts: %w", err)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)

	limitations := make([]analyzerv1.Limitation, 0, 4+len(cfg.AdditionalLimitations))

	// Mandatory baseline blind-spot and scope-boundary limitations (Audit A8).
	limitations = append(limitations,
		analyzerv1.Limitation{
			Code: "known_blind_spots",
			Message: "Inspects only known PAM, wallet/Secret Service, encrypted-home, and session-startup configurations within readable scope; " +
				"does not inspect wallet contents, process memory, or arbitrary applications with custom secret stores, " +
				"and absence of findings does not guarantee identical behavior for every application.",
			Evidence: []protocol.Evidence{},
		},
		analyzerv1.Limitation{
			Code: "login_scope_only",
			Message: "Findings describe display-manager login session initialization only; " +
				"later independent authentications (sudo, su, polkit, ssh, screen lockers) are unchanged and outside login PAM scope.",
			Evidence: []protocol.Evidence{},
		},
	)

	if cfg.OfflineMode {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "offline_root_mode",
			Message:  fmt.Sprintf("Offline filesystem root %q was analyzed without invoking live platform provider, package database, systemd, or D-Bus probes.", cfg.Root),
			Evidence: []protocol.Evidence{},
		})
	}

	for _, lim := range cfg.AdditionalLimitations {
		if lim.Evidence == nil {
			lim.Evidence = []protocol.Evidence{}
		}
		limitations = append(limitations, lim)
	}

	// Probe 1: Primary PAM configuration
	pamStack, pamErr := ParsePAM(cfg.Root, cfg.ServiceName, 10)
	if pamStack != nil {
		limitations = appendIssues(limitations, pamStack.Issues)
	} else if pamErr != nil {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "pam_read_error",
			Message:  fmt.Sprintf("Failed to read PAM service %q: %v", cfg.ServiceName, pamErr),
			Evidence: []protocol.Evidence{},
		})
	}

	// Probe 1b: Companion dedicated fingerprint PAM service (<service>-fingerprint), if present
	var fpPAMStack *PAMStack
	fpServiceName := cfg.ServiceName + "-fingerprint"
	fpServicePath := filepath.Join(cfg.Root, "etc", "pam.d", filepath.Base(fpServiceName))
	if _, statErr := os.Stat(fpServicePath); statErr == nil {
		fpStack, fpErr := ParsePAM(cfg.Root, fpServiceName, 10)
		fpPAMStack = fpStack
		if fpStack != nil {
			limitations = appendIssues(limitations, fpStack.Issues)
		} else if fpErr != nil {
			limitations = append(limitations, analyzerv1.Limitation{
				Code:     "pam_read_error",
				Message:  fmt.Sprintf("Failed to read fingerprint PAM service %q: %v", fpServiceName, fpErr),
				Evidence: []protocol.Evidence{},
			})
		}
	}

	// Probe 2: Wallets and Keyrings
	var walletFacts *WalletFacts
	if cfg.UserHome != "" {
		facts, err := ProbeWallets(cfg.UserHome)
		if err != nil {
			limitations = append(limitations, analyzerv1.Limitation{
				Code:     "wallet_read_error",
				Message:  fmt.Sprintf("Failed to probe user wallets in %q: %v", cfg.UserHome, err),
				Evidence: []protocol.Evidence{},
			})
		} else if facts != nil {
			walletFacts = facts
			limitations = appendIssues(limitations, facts.Issues)
		}
	} else {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "unscanned_user_sessions",
			Message:  "User home directory was not resolved or specified; per-user wallet and session startup configuration was not probed.",
			Evidence: []protocol.Evidence{},
		})
	}

	// Probe 3: Storage (systemd-homed, pam_mount & crypttab)
	storageFacts, storageErr := ProbeStorage(cfg.Root, cfg.Username)
	if storageErr != nil {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "storage_read_error",
			Message:  fmt.Sprintf("Failed to probe encrypted storage configuration: %v", storageErr),
			Evidence: []protocol.Evidence{},
		})
	} else if storageFacts != nil {
		limitations = appendIssues(limitations, storageFacts.Issues)
	}

	// Probe 4: Session Startup
	sessionFacts, sessionErr := ProbeSession(cfg.Root, cfg.UserHome)
	if sessionErr != nil {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "session_read_error",
			Message:  fmt.Sprintf("Failed to probe desktop session startup configuration: %v", sessionErr),
			Evidence: []protocol.Evidence{},
		})
	} else if sessionFacts != nil {
		limitations = appendIssues(limitations, sessionFacts.Issues)
	}

	// Propagate platform-provider probe errors into Limitations
	if cfg.PlatformFacts != nil {
		for _, pe := range cfg.PlatformFacts.ProbeErrors {
			ev := pe.Evidence
			if ev == nil {
				ev = []protocol.Evidence{}
			}
			limitations = append(limitations, analyzerv1.Limitation{
				Code:     "platform_probe_error",
				Message:  fmt.Sprintf("Platform probe %q did not complete: %s", pe.ProbeID, pe.Message),
				Evidence: ev,
			})
		}
	}

	// Classify findings
	findings := e.classifier.ClassifyWithContext(pamStack, fpPAMStack, walletFacts, storageFacts, sessionFacts, cfg.PlatformFacts)
	if findings == nil {
		findings = []analyzerv1.Finding{}
	}

	report := analyzerv1.Report{
		SchemaVersion:    analyzerv1.SchemaVersion,
		AnalyzerVersion:  cfg.AnalyzerVersion,
		GeneratedAt:      now,
		PlatformProvider: cfg.PlatformProvider,
		Target:           cfg.Target,
		Findings:         findings,
		Limitations:      limitations,
	}

	if err := report.Validate(); err != nil {
		return report, fmt.Errorf("validate generated analyzer report: %w", err)
	}

	return report, nil
}

func appendIssues(dst []analyzerv1.Limitation, issues []ProbeIssue) []analyzerv1.Limitation {
	for _, iss := range issues {
		ev := iss.Evidence
		if ev == nil {
			ev = []protocol.Evidence{}
		}
		dst = append(dst, analyzerv1.Limitation{
			Code:     iss.Code,
			Message:  iss.Message,
			Evidence: ev,
		})
	}
	return dst
}
