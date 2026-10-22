package analyze

import (
	"context"
	"fmt"
	"time"

	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
)

// EngineConfig holds configuration for a complete system difference analysis run.
type EngineConfig struct {
	Root             string
	Username         string
	UserHome         string
	ServiceName      string // defaults to "display-manager"
	PlatformProvider analyzerv1.ProviderIdentity
	Target           analyzerv1.Target
	AnalyzerVersion  string
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

// Analyze runs the read-only probes, evaluates evidence, and builds an analyzer report.
func (e *Engine) Analyze(ctx context.Context, cfg EngineConfig) (analyzerv1.Report, error) {
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
		cfg.PlatformProvider.ID = "org.fplogin.platform.generic"
		cfg.PlatformProvider.Version = "0.2.0"
		cfg.PlatformProvider.DescriptorSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC().Format(time.RFC3339)

	limitations := make([]analyzerv1.Limitation, 0)

	// Probe 1: PAM Configuration
	pamStack, pamErr := ParsePAM(cfg.Root, cfg.ServiceName, 10)
	if pamErr != nil {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "pam_read_error",
			Message:  fmt.Sprintf("Failed to read PAM service %q: %v", cfg.ServiceName, pamErr),
			Evidence: []protocol.Evidence{},
		})
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
		} else {
			walletFacts = facts
		}
	} else {
		limitations = append(limitations, analyzerv1.Limitation{
			Code:     "unscanned_user_sessions",
			Message:  "User home directory was not specified; active user configuration was not probed",
			Evidence: []protocol.Evidence{},
		})
	}

	// Probe 3: Storage (systemd-homed & crypttab)
	storageFacts, _ := ProbeStorage(cfg.Root, cfg.Username)

	// Probe 4: Session Startup
	sessionFacts, _ := ProbeSession(cfg.Root, cfg.UserHome)

	// Classify findings
	findings := e.classifier.Classify(pamStack, walletFacts, storageFacts, sessionFacts)
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
