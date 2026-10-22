// Command fplogin is the root CLI orchestrator for fingerprint-enabled display manager integration.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/analyze"
	"fplogin/internal/core/install"
	"fplogin/internal/core/manifest"
	"fplogin/internal/core/report"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "version", "--version", "-v":
		fmt.Printf("fplogin v%s (Core Transaction Engine)\n", version)
	case "status":
		runStatus(args)
	case "analyze":
		runAnalyze(args)
	case "install":
		runInstall(args)
	case "uninstall":
		runUninstall(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `fplogin — Fingerprint display manager integration orchestrator

Usage:
  fplogin <subcommand> [flags]

Subcommands:
  install     Discover compatible display managers, plan, and install integration
  uninstall   Safely remove fplogin-managed integration and restore previous DM
  status      Display current installation state from manifest
  analyze     Analyze password-derived facilities impacted by biometric login
  version     Show version information
  help        Show this help message

Run 'fplogin <subcommand> --help' for flags on a specific subcommand.
`)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	manifestPath := fs.String("manifest", "/var/lib/fplogin/manifest.json", "Path to install manifest")
	_ = fs.Parse(args)

	m, err := manifest.Load(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No active fplogin installation found at %s: %v\n", *manifestPath, err)
		os.Exit(1)
	}

	fmt.Printf("fplogin Installation Status\n")
	fmt.Printf("  Version:          %s\n", m.FPLoginVersion)
	fmt.Printf("  Installed At:     %s\n", m.InstalledAt)
	fmt.Printf("  Target DM:        %s (%s)\n", m.Target.DisplayName, m.Target.DMID)
	fmt.Printf("  Adapter:          %s v%s\n", m.Adapter.ID, m.Adapter.Version)
	fmt.Printf("  Platform:         %s v%s\n", m.PlatformProvider.ID, m.PlatformProvider.Version)
	fmt.Printf("  Mode:             %s\n", m.AcceptedPlan.Mode)
	fmt.Printf("  Installed Files:  %d\n", len(m.InstalledFiles))
	fmt.Printf("  Verification:     %s (verified at %s)\n", m.Verification.ReportID, m.Verification.VerifiedAt)

	mismatches, err := manifest.VerifyFiles(m)
	if err != nil {
		fmt.Printf("  Integrity:        Warning: could not verify files: %v\n", err)
	} else if len(mismatches) == 0 {
		fmt.Printf("  Integrity:        Intact (all file checksums match)\n")
	} else {
		fmt.Printf("  Integrity:        Mismatches detected (%d modified/missing files)\n", len(mismatches))
		for _, mm := range mismatches {
			fmt.Printf("    - %s: %s\n", mm.Kind, mm.Path)
		}
	}
}

func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	manifestPath := fs.String("manifest", "/var/lib/fplogin/manifest.json", "Path to install manifest")
	force := fs.Bool("force", false, "Force uninstall even if installed files have been modified")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Error: root privileges required to uninstall fplogin. Please run with sudo.\n")
		os.Exit(1)
	}

	cfg := manifest.UninstallConfig{
		ManifestPath: *manifestPath,
		Force:        *force,
	}

	ctx := context.Background()
	if err := manifest.Uninstall(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("fplogin successfully uninstalled.")
}

func runInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "Simulate planning and validation without modifying system")
	target := fs.String("target", "", "Explicit target display manager ID (e.g. org.freedesktop.DisplayManager.sddm)")
	yes := fs.Bool("yes", false, "Automatically approve package installations and DM replacement")
	manifestPath := fs.String("manifest", "/var/lib/fplogin/manifest.json", "Path to install manifest")
	journalDir := fs.String("journal-dir", "/var/lib/fplogin/transactions", "Directory for transaction journals")
	adapterDir := fs.String("adapter-dir", "/usr/lib/fplogin/adapters", "Directory containing adapter descriptors")
	providerDir := fs.String("provider-dir", "/usr/lib/fplogin/platforms", "Directory containing platform provider descriptors")
	_ = fs.Parse(args)

	// Set up runners and client adapters
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        30 * time.Second,
		MaxInputBytes:  1024 * 1024,
		MaxStdoutBytes: 10 * 1024 * 1024,
		MaxStderrBytes: 1024 * 1024,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialize runner: %v\n", err)
		os.Exit(1)
	}

	adClient, err := adapterclient.New(adapterclient.Config{
		Runner:             runner,
		DescriptorMaxBytes: 64 * 1024,
		ProtocolMajor:      1,
		CoreVersion:        version,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialize adapter client: %v\n", err)
		os.Exit(1)
	}

	prClient, err := platformclient.New(platformclient.Config{
		Runner:             runner,
		DescriptorMaxBytes: 64 * 1024,
		ProtocolMajor:      1,
		CoreVersion:        version,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Initialize platform client: %v\n", err)
		os.Exit(1)
	}

	host := protocol.HostContext{
		Root:        "/",
		InvokingUID: uint32(os.Getuid()),
		InvokingGID: uint32(os.Getgid()),
		Elevated:    os.Geteuid() == 0,
		DryRun:      *dryRun,
		Deadline:    time.Now().Add(60 * time.Second).UTC().Format(time.RFC3339),
	}

	cfg := install.Config{
		AdapterDiscoverer:  adClient,
		ProviderDiscoverer: prClient,
		AdapterDirs:        []string{*adapterDir},
		ProviderDirs:       []string{*providerDir},
		TargetDMID:         *target,
		DryRun:             *dryRun,
		AutoApprove:        *yes,
		JournalDir:         *journalDir,
		ManifestPath:       *manifestPath,
		BackupDir:          filepath.Join(filepath.Dir(*journalDir), "backups"),
		Host:               host,
		CoreVersion:        version,
	}

	ctx := context.Background()
	res, err := install.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Installation failed: %v\n", err)
		os.Exit(1)
	}

	if res.DryRun {
		fmt.Printf("fplogin Dry-Run Simulation Successful\n")
		fmt.Printf("  Target DM:        %s (%s)\n", res.SelectedTarget.DisplayName, res.SelectedTarget.DMID)
		fmt.Printf("  Adapter:          %s v%s\n", res.SelectedAdapter.Descriptor.AdapterID, res.SelectedAdapter.Descriptor.AdapterVersion)
		fmt.Printf("  Platform:         %s v%s\n", res.SelectedProvider.Descriptor.PlatformID, res.SelectedProvider.Descriptor.PlatformVersion)
		fmt.Printf("  Planned Actions:  %d operations\n", len(res.Plan.Operations))
		for i, op := range res.Plan.Operations {
			fmt.Printf("    [%d] %s (id: %s)\n", i+1, op.Kind, op.OperationID)
		}
		fmt.Printf("\nNo modifications were made to the system.\n")
		return
	}

	fmt.Printf("fplogin Installation Completed Successfully\n")
	fmt.Printf("  Target:           %s\n", res.SelectedTarget.DisplayName)
	fmt.Printf("  Transaction ID:   %s\n", res.TransactionID)
	fmt.Printf("  Manifest:         %s\n", res.ManifestPath)
	fmt.Printf("  Operations:       %d applied and verified\n", len(res.AppliedReceipts))
}

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	outputJSON := fs.Bool("json", false, "Output report as JSON")
	root := fs.String("root", "/", "Root filesystem directory")
	service := fs.String("service", "sddm", "Display manager PAM service name to inspect")
	user := fs.String("user", os.Getenv("USER"), "Target user to inspect for wallets and encrypted storage")
	_ = fs.Parse(args)

	userHome := os.Getenv("HOME")
	if *user != "" && *user != os.Getenv("USER") {
		userHome = filepath.Join(*root, "home", *user)
	}

	engine := analyze.NewEngine()
	ctx := context.Background()

	cfg := analyze.EngineConfig{
		Root:        *root,
		Username:    *user,
		UserHome:    userHome,
		ServiceName: *service,
	}

	rep, err := engine.Analyze(ctx, cfg)
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

