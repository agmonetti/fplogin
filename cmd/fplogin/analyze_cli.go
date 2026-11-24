package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fplogin/internal/core/analyze"
	"fplogin/internal/core/install"
	"fplogin/internal/core/manifest"
	"fplogin/internal/core/report"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	analyzerv1 "fplogin/internal/protocol/analyzer/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	outputJSON := fs.Bool("json", false, "Output report as JSON")
	root := fs.String("root", "/", "Root filesystem directory (non-'/' runs in offline fixture mode)")
	service := fs.String("service", "", "Display manager PAM service name to inspect (auto-detected if omitted)")
	user := fs.String("user", "", "Target user to inspect for wallets and encrypted storage")
	manifestPath := fs.String("manifest", filepath.Join(systemStateRoot, "manifest.json"), "Path to installed fplogin manifest")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	userExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "user" {
			userExplicit = true
		}
	})

	rep, err := executeAnalyze(context.Background(), analyzeCLIOptions{
		Root:         *root,
		Service:      *service,
		User:         *user,
		UserExplicit: userExplicit,
		ManifestPath: *manifestPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analysis failed: %v\n", err)
		os.Exit(1)
	}

	if *outputJSON {
		data, err := report.FormatJSON(rep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Format JSON failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	fmt.Print(report.FormatTerminal(rep))
}

type analyzeCLIOptions struct {
	Root         string
	Service      string
	User         string
	UserExplicit bool
	ManifestPath string
}

func executeAnalyze(ctx context.Context, opts analyzeCLIOptions) (analyzerv1.Report, error) {
	cleanRoot := filepath.Clean(opts.Root)
	if cleanRoot == "" {
		cleanRoot = "/"
	}
	offline := cleanRoot != "/"

	targetUser := opts.User
	if targetUser == "" && !opts.UserExplicit {
		if os.Geteuid() == 0 {
			targetUser = os.Getenv("SUDO_USER")
		} else {
			targetUser = os.Getenv("USER")
		}
	}

	var extraLimits []analyzerv1.Limitation
	var userHome string
	if targetUser != "" {
		if !opts.UserExplicit && os.Geteuid() == 0 && targetUser == "root" {
			extraLimits = append(extraLimits, analyzerv1.Limitation{
				Code:     "root_user_no_desktop_home",
				Message:  "Running as root without SUDO_USER or --user; per-user desktop wallet/session files were not scanned.",
				Evidence: []protocol.Evidence{},
			})
			targetUser = ""
		} else {
			home, found, err := analyze.ResolveUserHome(cleanRoot, targetUser)
			switch {
			case found:
				userHome = home
			case err != nil:
				if !offline && targetUser == os.Getenv("USER") && os.Getenv("HOME") != "" {
					userHome = os.Getenv("HOME")
					extraLimits = append(extraLimits, analyzerv1.Limitation{
						Code:     "passwd_read_fallback",
						Message:  fmt.Sprintf("Could not read /etc/passwd (%v); fell back to HOME environment variable.", err),
						Evidence: []protocol.Evidence{},
					})
				} else {
					extraLimits = append(extraLimits, analyzerv1.Limitation{
						Code:     "user_home_unresolved",
						Message:  fmt.Sprintf("Could not resolve home directory for user %q from %s/etc/passwd: %v", targetUser, cleanRoot, err),
						Evidence: []protocol.Evidence{},
					})
				}
			default:
				extraLimits = append(extraLimits, analyzerv1.Limitation{
					Code:     "user_home_unresolved",
					Message:  fmt.Sprintf("User %q was not found in %s/etc/passwd; per-user wallet/session probes skipped.", targetUser, cleanRoot),
					Evidence: []protocol.Evidence{},
				})
			}
		}
	}

	cfg := analyze.EngineConfig{
		Root:            cleanRoot,
		Username:        targetUser,
		UserHome:        userHome,
		ServiceName:     opts.Service,
		OfflineMode:     offline,
		AnalyzerVersion: version,
	}

	if !offline {
		// 1. Read installed manifest (if present and readable) for target attribution and PAM service hint.
		if opts.ManifestPath != "" {
			if m, err := manifest.Load(opts.ManifestPath); err == nil {
				adapterID := m.Adapter.ID
				instanceID := m.Target.InstanceID
				cfg.Target = analyzerv1.Target{
					AdapterID:  &adapterID,
					InstanceID: &instanceID,
				}
				if cfg.ServiceName == "" {
					cfg.ServiceName = inferPAMServiceFromTarget(m.Target.DMID, m.Target.DisplayName)
				}
			}
		}

		// 2. Discover packaged platform provider and collect read-only facts.
		provider, facts, provLimits := collectLivePlatformFacts(ctx, targetUser)
		extraLimits = append(extraLimits, provLimits...)
		if provider != nil {
			cfg.PlatformProvider = *provider
		}
		if facts != nil {
			cfg.PlatformFacts = facts
			if cfg.ServiceName == "" {
				cfg.ServiceName = inferPAMServiceFromFacts(facts)
			}
		}
	}

	if cfg.ServiceName == "" {
		cfg.ServiceName = defaultPAMService(cleanRoot, &extraLimits)
	}

	cfg.AdditionalLimitations = extraLimits
	return analyze.NewEngine().Analyze(ctx, cfg)
}

func collectLivePlatformFacts(ctx context.Context, username string) (*analyzerv1.ProviderIdentity, *platformv1.PlatformAnalyzerFacts, []analyzerv1.Limitation) {
	const maxBytes = 2 << 20
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        15 * time.Second,
		MaxInputBytes:  maxBytes,
		MaxStdoutBytes: maxBytes,
		MaxStderrBytes: 16384,
	})
	if err != nil {
		return nil, nil, []analyzerv1.Limitation{{
			Code:     "platform_provider_unavailable",
			Message:  fmt.Sprintf("Could not initialize platform runner: %v", err),
			Evidence: []protocol.Evidence{},
		}}
	}
	pc, err := platformclient.New(platformclient.Config{
		Runner:             runner,
		DescriptorMaxBytes: maxBytes,
		ProtocolMajor:      1,
		CoreVersion:        version,
	})
	if err != nil {
		return nil, nil, []analyzerv1.Limitation{{
			Code:     "platform_provider_unavailable",
			Message:  fmt.Sprintf("Could not initialize platform client: %v", err),
			Evidence: []protocol.Evidence{},
		}}
	}

	host := componentHost()
	if os.Geteuid() == 0 {
		host.Elevated = true
	}
	host.Deadline = time.Now().Add(15 * time.Second).UTC().Format(time.RFC3339)

	provider, err := discoverPackagedProvider(ctx, pc, host)
	if err != nil {
		return nil, nil, []analyzerv1.Limitation{{
			Code:     "platform_provider_unavailable",
			Message:  fmt.Sprintf("Packaged platform provider not available (%v); package, systemd, D-Bus Secret Service, and fprintd probes did not run.", err),
			Evidence: []protocol.Evidence{},
		}}
	}

	id := &analyzerv1.ProviderIdentity{
		ID:               provider.Descriptor.PlatformID,
		Version:          provider.Descriptor.PlatformVersion,
		DescriptorSHA256: provider.DescriptorSHA256,
	}

	if !provides(provider.Descriptor.Capabilities, "analyzer.facts") {
		return id, nil, []analyzerv1.Limitation{{
			Code:     "platform_capability_missing",
			Message:  fmt.Sprintf("Platform provider %q does not advertise analyzer.facts capability.", provider.Descriptor.PlatformID),
			Evidence: []protocol.Evidence{},
		}}
	}

	facts, callErr := invokeCollectAnalyzerFacts(ctx, pc, provider, host, username)
	if callErr != nil {
		return id, nil, []analyzerv1.Limitation{{
			Code:     "platform_facts_error",
			Message:  fmt.Sprintf("Platform analyzer facts collection failed: %v", callErr),
			Evidence: []protocol.Evidence{},
		}}
	}
	return id, &facts, nil
}

func invokeCollectAnalyzerFacts(ctx context.Context, pc platformclient.Client, provider platformclient.Discovered, host protocol.HostContext, username string) (platformv1.PlatformAnalyzerFacts, error) {
	targetCtx := protocol.Object{}
	if username != "" {
		encoded, err := json.Marshal(username)
		if err == nil {
			targetCtx["username"] = encoded
		}
	}
	payload := platformv1.CollectAnalyzerFactsPayload{
		Scope:         "biometric_login_difference",
		TargetContext: targetCtx,
		ProbeIDs:      []string{"fprintd", "packages", "secret_service", "display_managers"},
		Deadline:      time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339),
	}
	return platformCall[platformv1.PlatformAnalyzerFacts](ctx, pc, provider, host, "CollectAnalyzerFacts", payload)
}

func inferPAMServiceFromTarget(dmID, displayName string) string {
	combined := strings.ToLower(dmID + " " + displayName)
	for _, known := range []string{"sddm", "gdm", "lightdm", "greetd", "lxdm", "xdm", "ly"} {
		if strings.Contains(combined, known) {
			return known
		}
	}
	return ""
}

func inferPAMServiceFromFacts(facts *platformv1.PlatformAnalyzerFacts) string {
	if facts == nil {
		return ""
	}
	fallback := ""
	for _, ev := range facts.Evidence {
		if ev.Kind != "service" || !strings.Contains(ev.ObservedValue, "role=display-manager") {
			continue
		}
		svc := strings.TrimSuffix(ev.Subject, ".service")
		if svc == "" || svc == "display-manager" {
			continue
		}
		if strings.Contains(ev.ObservedValue, "active=active") || strings.Contains(ev.ObservedValue, "enabled=enabled") {
			return svc
		}
		if fallback == "" {
			fallback = svc
		}
	}
	return fallback
}

func defaultPAMService(root string, limits *[]analyzerv1.Limitation) string {
	for _, candidate := range []string{"display-manager", "sddm", "gdm", "lightdm", "login"} {
		if _, err := os.Stat(filepath.Join(root, "etc", "pam.d", candidate)); err == nil {
			return candidate
		}
	}
	*limits = append(*limits, analyzerv1.Limitation{
		Code:     "pam_service_defaulted",
		Message:  "No display manager PAM service was specified or detected; defaulted to \"display-manager\".",
		Evidence: []protocol.Evidence{},
	})
	return "display-manager"
}

// runInstallPostflight executes Installer Phase 13: a strictly read-only, non-fatal
// system difference analysis printed after atomic manifest publication.
func runInstallPostflight(ctx context.Context, bridge *cliLiveBridge, _ *install.Result, stdout, stderr io.Writer) {
	var extraLimits []analyzerv1.Limitation
	targetUser := os.Getenv("SUDO_USER")
	userHome := ""
	if targetUser == "" || targetUser == "root" {
		targetUser = ""
		extraLimits = append(extraLimits, analyzerv1.Limitation{
			Code:     "postflight_no_desktop_user",
			Message:  "Installer ran as root without SUDO_USER; per-user wallet and session startup configuration was not scanned. Run 'fplogin analyze' as your desktop user.",
			Evidence: []protocol.Evidence{},
		})
	} else {
		home, found, err := analyze.ResolveUserHome("/", targetUser)
		switch {
		case found:
			userHome = home
		case err != nil:
			extraLimits = append(extraLimits, analyzerv1.Limitation{
				Code:     "user_home_unresolved",
				Message:  fmt.Sprintf("Could not resolve home directory for SUDO_USER %q from /etc/passwd: %v", targetUser, err),
				Evidence: []protocol.Evidence{},
			})
		default:
			extraLimits = append(extraLimits, analyzerv1.Limitation{
				Code:     "user_home_unresolved",
				Message:  fmt.Sprintf("SUDO_USER %q was not found in /etc/passwd; per-user wallet/session probes skipped.", targetUser),
				Evidence: []protocol.Evidence{},
			})
		}
	}

	serviceName := inferPAMServiceFromTarget(bridge.selectedTgt.DMID, bridge.selectedTgt.DisplayName)
	if serviceName == "" {
		serviceName = defaultPAMService("/", &extraLimits)
	}

	cfg := analyze.EngineConfig{
		Root:            "/",
		Username:        targetUser,
		UserHome:        userHome,
		ServiceName:     serviceName,
		AnalyzerVersion: version,
	}

	if bridge.provider.Descriptor.PlatformID != "" {
		cfg.PlatformProvider = analyzerv1.ProviderIdentity{
			ID:               bridge.provider.Descriptor.PlatformID,
			Version:          bridge.provider.Descriptor.PlatformVersion,
			DescriptorSHA256: bridge.provider.DescriptorSHA256,
		}
		if provides(bridge.provider.Descriptor.Capabilities, "analyzer.facts") {
			host := liveHostContext()
			host.Deadline = time.Now().Add(15 * time.Second).UTC().Format(time.RFC3339)
			facts, err := invokeCollectAnalyzerFacts(ctx, bridge.pc, bridge.provider, host, targetUser)
			if err != nil {
				extraLimits = append(extraLimits, analyzerv1.Limitation{
					Code:     "platform_facts_error",
					Message:  fmt.Sprintf("Postflight platform facts collection did not complete: %v", err),
					Evidence: []protocol.Evidence{},
				})
			} else {
				cfg.PlatformFacts = &facts
			}
		}
	}

	if bridge.lastPlan.AdapterID != "" && bridge.selectedTgt.InstanceID != "" {
		adapterID := bridge.lastPlan.AdapterID
		instanceID := bridge.selectedTgt.InstanceID
		cfg.Target = analyzerv1.Target{
			AdapterID:  &adapterID,
			InstanceID: &instanceID,
		}
	}

	cfg.AdditionalLimitations = extraLimits

	rep, err := analyze.NewEngine().Analyze(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Warning: postflight system analysis did not complete (installation remains committed): %v\n", err)
		return
	}
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, report.FormatTerminal(rep))
}
