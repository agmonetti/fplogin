// Command fplogin is the root CLI orchestrator for fingerprint-enabled display manager integration.
package main

import (
	"flag"
	"fmt"
	"os"

	"fplogin/internal/core/manifest"
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
	case "config":
		runConfig(args)
	case "components":
		fs := flag.NewFlagSet("components", flag.ExitOnError)
		_ = fs.Parse(args)
		if fs.NArg() != 0 {
			fs.Usage()
			os.Exit(2)
		}
		if err := listComponents(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: components: %v\n", err)
			os.Exit(1)
		}
	case "install":
		runInstall(args)
	case "uninstall":
		runUninstall(args)
	case "recover":
		runRecover(args)
	case "update":
		runUpdate(args)
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
  install     Install fplogin (--dry-run unprivileged preview; live requires root + --artifacts-dir)
  uninstall   Transactionally restore the pre-fplogin baseline from manifest (root required)
  recover     Reconcile any interrupted install or uninstall transaction from disk (root required)
  update      Check or apply GitHub Release updates verified by SHA-256 (--check unprivileged; apply requires root)
  status      Display current installation state from manifest (read-only)
  analyze     Inspect password-derived facilities impacted by biometric login (read-only)
  config      Show or persistently update SDDM fingerprint drop-in settings
  components  List packaged providers and adapters (read-only, unprivileged)
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
