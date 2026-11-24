package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/discovery"
	"fplogin/internal/core/install"
	"fplogin/internal/core/manifest"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

const systemStateRoot = "/var/lib/fplogin"

type cliArtifactMeta struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	MediaType string `json:"media_type"`
}

func requireRoot(cmd string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return fmt.Errorf("%s requires root privileges (run with sudo)", cmd)
	}
	return nil
}

func isTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

func newLiveClients() (platformclient.Client, adapterclient.Client, error) {
	const maxBytes = 2 << 20
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        2 * time.Minute,
		MaxInputBytes:  maxBytes,
		MaxStdoutBytes: maxBytes,
		MaxStderrBytes: 65536,
	})
	if err != nil {
		return platformclient.Client{}, adapterclient.Client{}, err
	}
	pc, err := platformclient.New(platformclient.Config{
		Runner: runner, DescriptorMaxBytes: maxBytes, ProtocolMajor: 1, CoreVersion: version,
	})
	if err != nil {
		return platformclient.Client{}, adapterclient.Client{}, err
	}
	ac, err := adapterclient.New(adapterclient.Config{
		Runner: runner, DescriptorMaxBytes: maxBytes, ProtocolMajor: 1, CoreVersion: version,
	})
	if err != nil {
		return platformclient.Client{}, adapterclient.Client{}, err
	}
	return pc, ac, nil
}

func liveHostContext() protocol.HostContext {
	h := componentHost()
	h.DryRun = false
	h.Elevated = true
	h.Deadline = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	return h
}

func scanOfflineArtifacts(dir string) ([]cliArtifactMeta, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("artifacts directory %q is not an accessible directory", abs)
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	var results []cliArtifactMeta
	seenPkg := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".sig") || strings.HasSuffix(name, ".name") {
			continue
		}
		isPkg := strings.HasSuffix(name, ".pkg.tar.zst") || strings.HasSuffix(name, ".pkg.tar.xz")
		isDigest := protocol.ValidDigest(name) == nil
		if !isPkg && !isDigest {
			continue
		}
		full := filepath.Join(abs, name)
		f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, fmt.Errorf("open artifact %q: %w", full, err)
		}
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			f.Close()
			return nil, fmt.Errorf("artifact %q must be a non-empty regular file", full)
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, f)
		f.Close()
		if copyErr != nil {
			return nil, fmt.Errorf("hash artifact %q: %w", full, copyErr)
		}
		digest := fmt.Sprintf("%x", h.Sum(nil))
		if isDigest && digest != name {
			return nil, fmt.Errorf("content-addressed artifact %q digest mismatch", full)
		}
		sigInfo, err := os.Lstat(full + ".sig")
		if err != nil || !sigInfo.Mode().IsRegular() || sigInfo.Size() <= 0 || sigInfo.Size() > 65536 {
			return nil, fmt.Errorf("missing or invalid detached signature %q", full+".sig")
		}
		c := exec.Command("/usr/bin/pacman", "--config", "/dev/null", "-Qp", full)
		c.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
		out, err := c.Output()
		if err != nil {
			return nil, fmt.Errorf("inspect package archive %q via pacman -Qp: %w", full, err)
		}
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) != 2 {
			return nil, fmt.Errorf("unexpected pacman -Qp output for %q: %q", full, string(out))
		}
		if seenPkg[fields[0]] {
			return nil, fmt.Errorf("duplicate archive for package %q in %s", fields[0], abs)
		}
		seenPkg[fields[0]] = true
		mediaType := "application/octet-stream"
		if strings.HasSuffix(name, ".zst") {
			mediaType = "application/zstd"
		} else if strings.HasSuffix(name, ".xz") {
			mediaType = "application/x-xz"
		}
		results = append(results, cliArtifactMeta{
			Package:   fields[0],
			Version:   fields[1],
			SHA256:    digest,
			Size:      info.Size(),
			MediaType: mediaType,
		})
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no signed package archives found in %s", abs)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Package < results[j].Package })
	return results, nil
}

func queryLocalInstalledPackages() (map[string]string, error) {
	c := exec.Command("/usr/bin/pacman", "--config", "/dev/null", "-Q")
	c.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("query installed packages via pacman -Q: %w", err)
	}
	res := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if n, v, ok := strings.Cut(line, " "); ok && n != "" {
			res[n] = v
		}
	}
	return res, nil
}

// cliLiveBridge connects install.Run to real packaged platform and adapter subprocesses.
type cliLiveBridge struct {
	pc            platformclient.Client
	ac            adapterclient.Client
	provider      discovery.Provider
	artifacts     []cliArtifactMeta
	activate      bool
	adapterHost   protocol.HostContext
	factsReady    bool
	candidates    []adapterv1.DisplayManagerCandidate
	selectedTgt   adapterv1.DetectedTarget
	dmState       adapterv1.DisplayManagerState
	lastPlan      adapterv1.ChangePlan
	lastMode      string
}

func (b *cliLiveBridge) Discover(ctx context.Context, paths []string, host protocol.HostContext) ([]platformclient.Discovered, error) {
	providers, err := b.pc.Discover(ctx, paths, host)
	if err != nil {
		return nil, err
	}
	if len(providers) == 1 {
		b.provider = providers[0]
	}
	return providers, nil
}

func (b *cliLiveBridge) InspectHost(ctx context.Context, provider discovery.Provider, host protocol.HostContext) (platformv1.PlatformHostReport, error) {
	b.provider = provider
	return platformCall[platformv1.PlatformHostReport](ctx, b.pc, provider, host, "InspectHost", platformv1.InspectHostPayload{})
}

func (b *cliLiveBridge) ensureAdapterContext(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (protocol.HostContext, error) {
	if b.factsReady {
		return b.adapterHost, nil
	}
	if b.provider.ExecutablePath == "" {
		return protocol.HostContext{}, fmt.Errorf("platform provider not discovered")
	}
	hostReport, err := b.InspectHost(ctx, b.provider, host)
	if err != nil {
		return protocol.HostContext{}, err
	}
	pHost := host
	pHost.Platform = protocol.Object{}
	for k, v := range hostReport.Platform {
		pHost.Platform[k] = v
	}
	pHost.Architecture = hostReport.Architecture
	pHost.PackageManager = hostReport.PackageManager
	pHost.ServiceManager = hostReport.ServiceManager

	services, err := platformCall[platformv1.ServiceCandidateReport](ctx, b.pc, b.provider, pHost, "ListServiceCandidates", platformv1.ListServiceCandidatesPayload{})
	if err != nil {
		return protocol.HostContext{}, err
	}
	var hints []string
	for _, d := range adapter.Descriptor.Prerequisites {
		if name, ok := strings.CutPrefix(d.ID, "package."); d.Kind == "package" && ok && name != "" {
			hints = append(hints, name)
		}
	}
	packages, err := platformCall[platformv1.PackageCandidateReport](ctx, b.pc, b.provider, pHost, "ListPackageCandidates", platformv1.ListPackageCandidatesPayload{PackageHints: hints})
	if err != nil {
		return protocol.HostContext{}, err
	}
	facts := adapterv1.PreflightFacts{Services: services.Services, Packages: packages.Packages}
	for _, s := range facts.Services {
		pkg := ""
		if len(s.PackageReferences) > 0 {
			pkg = s.PackageReferences[0]
		}
		b.candidates = append(b.candidates, adapterv1.DisplayManagerCandidate{
			CandidateID: s.ServiceReference,
			DisplayName: s.ServiceReference,
			ServiceName: s.ServiceReference,
			PackageName: pkg,
		})
	}
	installedPkgs, err := queryLocalInstalledPackages()
	if err != nil {
		return protocol.HostContext{}, err
	}

	aHost := pHost
	aHost.Elevated = false
	aHost.DryRun = false
	aHost.Platform = protocol.Object{}
	for k, v := range hostReport.Platform {
		aHost.Platform[k] = v
	}
	aHost.Platform["inventory"], _ = json.Marshal(facts)
	aHost.Platform["artifacts"], _ = json.Marshal(b.artifacts)
	aHost.Platform["installed_packages"], _ = json.Marshal(installedPkgs)
	aHost.Platform["activate"], _ = json.Marshal(b.activate)
	b.adapterHost = aHost
	b.factsReady = true
	return aHost, nil
}

func (b *cliLiveBridge) Detect(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.DetectionReport, error) {
	aHost, err := b.ensureAdapterContext(ctx, adapter, host)
	if err != nil {
		return adapterv1.DetectionReport{}, err
	}
	rep, err := adapterCall[adapterv1.DetectionReport](ctx, b.ac, adapter, aHost, "Detect", adapterv1.DetectPayload{Candidates: b.candidates})
	if err != nil {
		return rep, err
	}
	for _, t := range rep.Targets {
		if t.Compatibility == "compatible" {
			b.selectedTgt = t
			break
		}
	}
	return rep, nil
}

func (b *cliLiveBridge) CheckPrerequisites(ctx context.Context, adapter discovery.Adapter, payload adapterv1.CheckPrerequisitesPayload, host protocol.HostContext) (adapterv1.PrerequisiteReport, error) {
	b.selectedTgt = payload.Target
	b.lastMode = payload.Mode
	aHost, err := b.ensureAdapterContext(ctx, adapter, host)
	if err != nil {
		return adapterv1.PrerequisiteReport{}, err
	}
	return adapterCall[adapterv1.PrerequisiteReport](ctx, b.ac, adapter, aHost, "CheckPrerequisites", payload)
}

func (b *cliLiveBridge) InspectState(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.DisplayManagerState, error) {
	aHost, err := b.ensureAdapterContext(ctx, adapter, host)
	if err != nil {
		return adapterv1.DisplayManagerState{}, err
	}
	st, err := adapterCall[adapterv1.DisplayManagerState](ctx, b.ac, adapter, aHost, "InspectState", struct {
		Target adapterv1.DetectedTarget `json:"target"`
	}{Target: b.selectedTgt})
	if err == nil {
		b.dmState = st
	}
	return st, err
}

func (b *cliLiveBridge) PlanInstall(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.ChangePlan, error) {
	aHost, err := b.ensureAdapterContext(ctx, adapter, host)
	if err != nil {
		return adapterv1.ChangePlan{}, err
	}
	mode := b.lastMode
	if mode == "" {
		mode = "fresh_install"
	}
	plan, err := adapterCall[adapterv1.ChangePlan](ctx, b.ac, adapter, aHost, "PlanInstall", adapterv1.PlanInstallPayload{
		Target:                b.selectedTgt,
		CurrentState:          b.dmState,
		Mode:                  mode,
		RequestedCapabilities: []string{"biometric_auth"},
		RemediationPolicy:     protocol.Object{},
		PrerequisiteReport:    protocol.Object{},
	})
	if err == nil {
		b.lastPlan = plan
	}
	return plan, err
}

func (b *cliLiveBridge) PrepareArtifacts(_ context.Context, _ discovery.Adapter, _ protocol.HostContext) (adapterv1.ArtifactSet, error) {
	return adapterv1.ArtifactSet{}, errors.New("PrepareArtifacts is handled by core staging")
}

func (b *cliLiveBridge) Verify(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.VerificationReport, error) {
	aHost, err := b.ensureAdapterContext(ctx, adapter, host)
	if err != nil {
		return adapterv1.VerificationReport{}, err
	}
	return adapterCall[adapterv1.VerificationReport](ctx, b.ac, adapter, aHost, "Verify", adapterv1.VerifyPayload{
		Target:                 b.selectedTgt,
		Phase:                  "post_install",
		ExpectedCapabilities:   []string{"biometric_auth"},
		ExpectedPostconditions: []json.RawMessage{},
	})
}

func (b *cliLiveBridge) PrepareArtifactInstall(ctx context.Context, provider discovery.Provider, payload platformv1.PrepareArtifactInstallPayload, host protocol.HostContext) error {
	b.provider = provider
	_, err := platformCall[platformv1.ArtifactInstallPreparation](ctx, b.pc, provider, host, "PrepareArtifactInstall", payload)
	return err
}

func (b *cliLiveBridge) ApplyOperation(_ context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error) {
	return manifestv1.OperationReceipt{}, fmt.Errorf("operation %q requires prepared platform invocation", op.OperationID)
}

func (b *cliLiveBridge) ApplyPreparedOperation(ctx context.Context, req install.PlatformOperationRequest) (manifestv1.OperationReceipt, error) {
	payload := platformv1.ApplyOperationPayload{
		Operation:  req.Operation,
		PlanDigest: req.PlanDigest,
	}
	if req.Operation.Kind == protocol.InstallPackageArtifact {
		var params protocol.PackageArtifactParameters
		if err := json.Unmarshal(req.Operation.Parameters, &params); err != nil {
			return manifestv1.OperationReceipt{}, err
		}
		refBytes, err := json.Marshal(map[string]string{
			"canonical_path": filepath.Join(req.StageDir, params.SHA256),
			"sha256":         params.SHA256,
		})
		if err != nil {
			return manifestv1.OperationReceipt{}, err
		}
		payload.PreparedArtifactReference = refBytes
	}
	pr, err := platformCall[platformv1.OperationReceipt](ctx, b.pc, b.provider, liveHostContext(), "ApplyOperation", payload)
	if err != nil {
		return manifestv1.OperationReceipt{}, err
	}
	return manifestv1.OperationReceipt{
		OperationID:  pr.OperationID,
		Kind:         pr.Kind,
		StartedAt:    pr.StartedAt,
		CompletedAt:  pr.CompletedAt,
		Status:       pr.Status,
		BeforeState:  pr.BeforeState,
		AfterState:   pr.AfterState,
		Compensation: pr.Compensation,
		Error:        pr.Error,
	}, nil
}

func discoverPackagedProvider(ctx context.Context, pc platformclient.Client, host protocol.HostContext) (discovery.Provider, error) {
	var paths []string
	for _, dir := range descriptortrust.PackagedDirs("platforms") {
		if err := descriptortrust.ValidatePackagedDir(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return discovery.Provider{}, err
		}
		found, err := packagedDescriptors(dir)
		if err != nil {
			return discovery.Provider{}, err
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		return discovery.Provider{}, discovery.ErrNoProvider
	}
	providers, err := pc.Discover(ctx, paths, host)
	if err != nil {
		return discovery.Provider{}, err
	}
	if len(providers) != 1 {
		return discovery.Provider{}, fmt.Errorf("expected 1 platform provider, found %d", len(providers))
	}
	return providers[0], nil
}

func printExecutablePlanSummary(plan adapterv1.ChangePlan, target adapterv1.DetectedTarget, dmState adapterv1.DisplayManagerState, planDigest string) {
	fmt.Printf("Proposed fplogin installation plan\n")
	fmt.Printf("  Target:          %s (%s/%s)\n", target.DisplayName, plan.AdapterID, target.InstanceID)
	fmt.Printf("  Mode:            %s\n", plan.Mode)
	fmt.Printf("  Plan SHA-256:    %s\n", planDigest)
	if len(dmState.ConflictingInstances) > 0 {
		fmt.Printf("  Conflicting DM:  %s (requires separate explicit replacement approval)\n", strings.Join(dmState.ConflictingInstances, ", "))
	}
	fmt.Printf("  Operations (%d):\n", len(plan.Operations))
	for i, op := range plan.Operations {
		fmt.Printf("    %2d. [%s] %s\n", i+1, op.Kind, op.OperationID)
	}
}

func liveInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	artifactsDir := fs.String("artifacts-dir", "", "directory containing signed Arch package archives (.pkg.tar.zst/.xz + .sig)")
	target := fs.String("target", "", "target DM ID or ADAPTER_ID/INSTANCE_ID")
	activate := fs.Bool("activate", false, "start sddm.service immediately (and stop active conflicting DM) instead of waiting for next boot")
	approvePlan := fs.String("approve-plan", "", "exact 64-hex SHA-256 plan digest to approve non-interactively")
	approveReplaceDM := fs.Bool("approve-replace-dm", false, "explicitly approve disabling/stopping a conflicting alternative display manager")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage:
  fplogin install --dry-run [--target ADAPTER_ID/TARGET_ID]
  sudo fplogin install --artifacts-dir DIR [flags]

Flags for live installation (root required):
`)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := requireRoot("install"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if *artifactsDir == "" {
		fmt.Fprintf(os.Stderr, "Error: install: --artifacts-dir is required for offline verified installation\n")
		os.Exit(1)
	}
	absArtifacts, err := filepath.Abs(*artifactsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: install: %v\n", err)
		os.Exit(1)
	}
	artifacts, err := scanOfflineArtifacts(absArtifacts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: install: %v\n", err)
		os.Exit(1)
	}
	pc, ac, err := newLiveClients()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: install: %v\n", err)
		os.Exit(1)
	}
	bridge := &cliLiveBridge{
		pc:        pc,
		ac:        ac,
		artifacts: artifacts,
		activate:  *activate,
	}
	cfg := install.Config{
		AdapterDiscoverer:    ac,
		ProviderDiscoverer:   bridge,
		AdapterInvoker:       bridge,
		PlatformInvoker:      bridge,
		TargetDMID:           *target,
		DryRun:               false,
		JournalDir:           filepath.Join(systemStateRoot, "transactions"),
		ManifestPath:         filepath.Join(systemStateRoot, "manifest.json"),
		IsolatedArchiveCache: absArtifacts,
		Host:                 liveHostContext(),
		CoreVersion:          version,
		ApprovePlan: func(planDigest string, _ bool) error {
			printExecutablePlanSummary(bridge.lastPlan, bridge.selectedTgt, bridge.dmState, planDigest)
			needsReplaceApproval := len(bridge.dmState.ConflictingInstances) > 0
			if *approvePlan != "" {
				if !strings.EqualFold(strings.TrimSpace(*approvePlan), planDigest) {
					return fmt.Errorf("--approve-plan digest does not match computed plan %s", planDigest)
				}
				if needsReplaceApproval && !*approveReplaceDM {
					return fmt.Errorf("replacing conflicting display manager(s) %v requires --approve-replace-dm", bridge.dmState.ConflictingInstances)
				}
				return nil
			}
			if !isTerminal(os.Stdin) {
				extra := ""
				if needsReplaceApproval {
					extra = " --approve-replace-dm"
				}
				return fmt.Errorf("non-interactive run requires --approve-plan %s%s", planDigest, extra)
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Approve plan %s? [y/N]: ", planDigest[:12])
			ans, _ := reader.ReadString('\n')
			ans = strings.ToLower(strings.TrimSpace(ans))
			if ans != "y" && ans != "yes" {
				return errors.New("plan rejected by operator")
			}
			if needsReplaceApproval && !*approveReplaceDM {
				fmt.Printf("Type REPLACE to confirm disabling conflicting display manager(s) (%s): ", strings.Join(bridge.dmState.ConflictingInstances, ", "))
				repAns, _ := reader.ReadString('\n')
				if strings.TrimSpace(repAns) != "REPLACE" {
					return errors.New("display manager replacement rejected by operator")
				}
			}
			return nil
		},
	}

	res, err := install.Run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: install failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fplogin installation completed successfully.\n")
	fmt.Printf("  Transaction ID: %s\n", res.TransactionID)
	fmt.Printf("  Mode:           %s\n", res.Mode)
	fmt.Printf("  Manifest:       %s\n", res.ManifestPath)
	fmt.Printf("  Journal:        %s\n", res.JournalPath)
	fmt.Printf("  Note:           Verify fingerprint reader and enrolled prints with 'fprintd-list <user>'. Password login remains available.\n")
}

func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	modifiedPolicy := fs.String("modified-files", string(install.ModifiedFilePreserve), "policy for locally modified files: preserve, refuse, or restore")
	removeShared := fs.Bool("remove-shared-deps", false, "also remove shared dependencies (e.g. qt5-*) that were absent before installation")
	yes := fs.Bool("yes", false, "confirm uninstallation non-interactively")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sudo fplogin uninstall [flags]\n\nRestores the pre-fplogin baseline recorded in /var/lib/fplogin/manifest.json.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := requireRoot("uninstall"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	pc, ac, err := newLiveClients()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: uninstall: %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()
	host := liveHostContext()
	provider, err := discoverPackagedProvider(ctx, pc, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: uninstall: %v\n", err)
		os.Exit(1)
	}
	bridge := &cliLiveBridge{pc: pc, ac: ac, provider: provider}

	manifestPath := filepath.Join(systemStateRoot, "manifest.json")
	if m, err := manifest.Load(manifestPath); err == nil {
		fmt.Printf("Loaded fplogin manifest (%s, target %s)\n", m.TransactionID, m.Target.DisplayName)
	}

	res, err := install.Uninstall(ctx, install.UninstallConfig{
		StateRoot:                systemStateRoot,
		ManifestPath:             manifestPath,
		JournalDir:               filepath.Join(systemStateRoot, "transactions"),
		Platform:                 bridge,
		ModifiedFiles:            install.ModifiedFilePolicy(*modifiedPolicy),
		RemoveSharedDependencies: *removeShared,
		ApproveUninstall: func(planDigest string) error {
			if *yes {
				return nil
			}
			if !isTerminal(os.Stdin) {
				return fmt.Errorf("non-interactive uninstall requires --yes (plan %s)", planDigest[:12])
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Proceed with uninstall (modified-files=%s, remove-shared-deps=%t)? [y/N]: ", *modifiedPolicy, *removeShared)
			ans, _ := reader.ReadString('\n')
			ans = strings.ToLower(strings.TrimSpace(ans))
			if ans != "y" && ans != "yes" {
				return errors.New("uninstall rejected by operator")
			}
			return nil
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: uninstall failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fplogin uninstallation completed successfully.\n")
	fmt.Printf("  Transaction ID: %s\n", res.TransactionID)
	fmt.Printf("  Journal:        %s\n", res.JournalPath)
	if len(res.PreservedFiles) > 0 {
		fmt.Printf("  Preserved:      %s\n", strings.Join(res.PreservedFiles, ", "))
	}
	if len(res.KeptSharedPackages) > 0 {
		fmt.Printf("  Kept shared:    %s\n", strings.Join(res.KeptSharedPackages, ", "))
	}
}

func runRecover(args []string) {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sudo fplogin recover\n\nReconciles any interrupted fplogin install or uninstall transaction from /var/lib/fplogin.\n")
	}
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := requireRoot("recover"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	pc, ac, err := newLiveClients()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: recover: %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()
	host := liveHostContext()
	provider, err := discoverPackagedProvider(ctx, pc, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: recover: %v\n", err)
		os.Exit(1)
	}
	bridge := &cliLiveBridge{pc: pc, ac: ac, provider: provider}

	if err := install.RecoverPending(ctx, systemStateRoot, nil, bridge); err != nil {
		fmt.Fprintf(os.Stderr, "Error: recover failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Recovery completed cleanly.\n")
}
