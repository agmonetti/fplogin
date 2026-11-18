package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"fplogin/internal/adapterclient"
	"fplogin/internal/core/selection"
	"fplogin/internal/platformclient"
	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

const preflightCapability = "install.preview"

func runInstall(args []string) {
	if len(args) == 1 && protocol.OneOf(args[0], "--help", "-help", "-h") {
		fmt.Fprintln(os.Stderr, "Usage: fplogin install --dry-run [--target ADAPTER_ID/TARGET_ID]\nHost installation is disabled. Dry-run only reports proposed changes.")
		return
	}
	if len(args) == 0 || args[0] != "--dry-run" {
		disabledCommand("install", args, "host installation is disabled")
		return
	}
	fs := flag.NewFlagSet("install --dry-run", flag.ExitOnError)
	target := fs.String("target", "", "explicit adapter/target pair from preflight output")
	_ = fs.Parse(args[1:])
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := previewInstall(*target); err != nil {
		fmt.Fprintf(os.Stderr, "Preflight stopped: %v\nNo changes were made.\n", err)
		if errors.Is(err, selection.ErrNoCompatibleTarget) {
			os.Exit(selection.NoSelectableTargetExitCode)
		}
		os.Exit(1)
	}
}

func platformCall[T any](ctx context.Context, client platformclient.Client, p platformclient.Discovered, h protocol.HostContext, op string, payload any) (T, error) {
	var result T
	id, err := protocol.NewRequestID()
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	r, err := client.Invoke(ctx, p, platformv1.Request{ProtocolVersion: p.ProtocolVersion, RequestID: id, Operation: op, CoreVersion: version, Context: h, Payload: data})
	if err != nil {
		return result, fmt.Errorf("%s: %w", op, err)
	}
	if !r.OK {
		return result, fmt.Errorf("%s: %s: %s", op, r.Error.Code, r.Error.Message)
	}
	return result, protocol.DecodeStrict(r.Result, &result)
}

func adapterCall[T any](ctx context.Context, client adapterclient.Client, a adapterclient.Discovered, h protocol.HostContext, op string, payload any) (T, error) {
	var result T
	id, err := protocol.NewRequestID()
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	r, err := client.Invoke(ctx, a, adapterv1.Request{ProtocolVersion: a.ProtocolVersion, RequestID: id, Operation: op, CoreVersion: version, Context: h, Payload: data})
	if err != nil {
		return result, fmt.Errorf("%s: %w", op, err)
	}
	if !r.OK {
		return result, fmt.Errorf("%s: %s: %s", op, r.Error.Code, r.Error.Message)
	}
	return result, protocol.DecodeStrict(r.Result, &result)
}

func provides(caps []protocol.Capability, required ...string) bool {
	for _, want := range required {
		found := false
		for _, cap := range caps {
			found = found || cap.ID == want && cap.Status == "provided"
		}
		if !found {
			return false
		}
	}
	return true
}

func previewInstall(requested string) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return fmt.Errorf("run as an ordinary user")
	}
	const max = 1 << 20
	runner, err := processrunner.New(processrunner.Config{Timeout: 15 * time.Second, MaxInputBytes: max, MaxStdoutBytes: max, MaxStderrBytes: 4096})
	if err != nil {
		return err
	}
	pc, err := platformclient.New(platformclient.Config{Runner: runner, DescriptorMaxBytes: max, ProtocolMajor: 1, CoreVersion: version})
	if err != nil {
		return err
	}
	ac, err := adapterclient.New(adapterclient.Config{Runner: runner, DescriptorMaxBytes: max, ProtocolMajor: 1, CoreVersion: version})
	if err != nil {
		return err
	}
	h := componentHost()
	h.Deadline = time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339)
	ctx := context.Background()
	paths, err := packagedDescriptors("/usr/lib/fplogin/platforms")
	if err != nil {
		return err
	}
	providers, err := pc.Discover(ctx, paths, h)
	if err != nil {
		return err
	}
	p, host, err := chooseProvider(ctx, pc, h, providers)
	if err != nil {
		return err
	}
	h.Platform, h.Architecture, h.PackageManager, h.ServiceManager = host.Platform, host.Architecture, host.PackageManager, host.ServiceManager
	services, err := platformCall[platformv1.ServiceCandidateReport](ctx, pc, p, h, "ListServiceCandidates", platformv1.ListServiceCandidatesPayload{})
	if err != nil {
		return err
	}
	paths, err = packagedDescriptors("/usr/lib/fplogin/adapters")
	if err != nil {
		return err
	}
	adapters, err := ac.Discover(ctx, paths, h)
	if err != nil {
		return err
	}
	var usable []adapterclient.Discovered
	var hints []string
	for _, a := range adapters {
		if !provides(a.Descriptor.Capabilities, preflightCapability) {
			continue
		}
		usable = append(usable, a)
		for _, d := range a.Descriptor.Prerequisites {
			if name, ok := strings.CutPrefix(d.ID, "package."); d.Kind == "package" && ok && name != "" {
				hints = append(hints, name)
			}
		}
	}
	packages, err := platformCall[platformv1.PackageCandidateReport](ctx, pc, p, h, "ListPackageCandidates", platformv1.ListPackageCandidatesPayload{PackageHints: hints})
	if err != nil {
		return err
	}
	facts := adapterv1.PreflightFacts{Services: services.Services, Packages: packages.Packages}
	candidates, err := printInventory(facts)
	if err != nil {
		return err
	}
	fmt.Printf("Provider: %s (%s/%s)\n", p.Descriptor.PlatformID, string(host.Platform["distribution"]), host.Architecture)
	h.Platform["inventory"], err = json.Marshal(facts)
	if err != nil {
		return err
	}
	return selectAndPreview(ctx, ac, h, p, usable, facts, candidates, requested)
}

func chooseProvider(ctx context.Context, pc platformclient.Client, h protocol.HostContext, providers []platformclient.Discovered) (platformclient.Discovered, platformv1.PlatformHostReport, error) {
	var chosen platformclient.Discovered
	var host platformv1.PlatformHostReport
	for _, p := range providers {
		if !provides(p.Descriptor.Capabilities, "host.inspect", "package.query", "service.query") {
			continue
		}
		r, err := platformCall[platformv1.PlatformHostReport](ctx, pc, p, h, "InspectHost", platformv1.InspectHostPayload{})
		if err != nil {
			return chosen, host, err
		}
		var distro string
		if json.Unmarshal(r.Platform["distribution"], &distro) != nil || distro == "" || r.Architecture != h.Architecture || len(r.Evidence) == 0 {
			return chosen, host, fmt.Errorf("unknown or inconsistent provider host facts")
		}
		for _, match := range p.Descriptor.SupportedPlatforms {
			if distro == match.Distribution && r.Architecture == match.Architecture {
				if chosen.Descriptor.PlatformID != "" {
					return chosen, host, fmt.Errorf("multiple eligible platform providers")
				}
				chosen, host = p, r
				break
			}
		}
	}
	if chosen.Descriptor.PlatformID == "" {
		return chosen, host, fmt.Errorf("no platform provider matches the host and required capabilities")
	}
	return chosen, host, nil
}

func printInventory(facts adapterv1.PreflightFacts) ([]adapterv1.DisplayManagerCandidate, error) {
	if facts.Packages == nil || facts.Services == nil {
		return nil, fmt.Errorf("unknown package or service inventory")
	}
	packages := map[string]string{}
	for _, p := range facts.Packages {
		if p.PackageReference == "" || packages[p.PackageReference] != "" || !protocol.OneOf(p.Installed, "yes", "no") {
			return nil, fmt.Errorf("invalid package observation %q: %s", p.PackageReference, p.Installed)
		}
		packages[p.PackageReference] = p.Installed
		fmt.Printf("Package %q: installed=%s version=%s\n", p.PackageReference, p.Installed, p.Version)
	}
	candidates := []adapterv1.DisplayManagerCandidate{}
	seen := map[string]bool{}
	for _, s := range facts.Services {
		if s.ServiceReference == "" || seen[s.ServiceReference] || !protocol.OneOf(s.Active, "yes", "no") || !protocol.OneOf(s.Enabled, "yes", "no") || !protocol.OneOf(s.Configurable, "yes", "no") {
			return nil, fmt.Errorf("unknown service observation %q: active=%s enabled=%s configurable=%s", s.ServiceReference, s.Active, s.Enabled, s.Configurable)
		}
		seen[s.ServiceReference] = true
		installed := "no package owner confirmed"
		var pkg string
		for _, ref := range s.PackageReferences {
			if packages[ref] != "yes" {
				return nil, fmt.Errorf("package and service probes disagree for %q (%q)", s.ServiceReference, ref)
			}
			installed, pkg = "yes", ref
		}
		fmt.Printf("Service %q: installed=%s enabled=%s active=%s\n", s.ServiceReference, installed, s.Enabled, s.Active)
		candidates = append(candidates, adapterv1.DisplayManagerCandidate{CandidateID: s.ServiceReference, DisplayName: s.ServiceReference, ServiceName: s.ServiceReference, PackageName: pkg})
	}
	return candidates, nil
}

func selectAndPreview(ctx context.Context, ac adapterclient.Client, h protocol.HostContext, p platformclient.Discovered, adapters []adapterclient.Discovered, facts adapterv1.PreflightFacts, candidates []adapterv1.DisplayManagerCandidate, requested string) error {
	var detections []selection.AdapterDetection
	byPair := map[string]adapterv1.DetectedTarget{}
	byAdapter := map[string]adapterclient.Discovered{}
	for _, a := range adapters {
		r, err := adapterCall[adapterv1.DetectionReport](ctx, ac, a, h, "Detect", adapterv1.DetectPayload{Candidates: candidates})
		if err != nil {
			return err
		}
		id := a.Descriptor.AdapterID
		byAdapter[id] = a
		for _, t := range r.Targets {
			if err := t.Validate(); err != nil {
				return err
			}
			pair := id + "/" + t.InstanceID
			if _, duplicate := byPair[pair]; duplicate {
				return fmt.Errorf("duplicate target %q", pair)
			}
			byPair[pair] = t
			fmt.Printf("Target %q: %q version=%q compatibility=%s confidence=%s\n", pair, t.DisplayName, t.UpstreamVersion, t.Compatibility, t.Confidence)
		}
		detections = append(detections, selection.AdapterDetection{AdapterID: id, AdapterName: a.Descriptor.Name, Capabilities: a.Descriptor.Capabilities, Targets: r.Targets})
	}
	choices, err := selection.PreviewChoices(detections, []string{preflightCapability})
	if err != nil {
		return err
	}
	if requested == "" {
		for _, choice := range choices.Targets {
			fmt.Printf("Selectable preview: %s/%s (%s)\n", choice.AdapterID, choice.TargetInstanceID, choice.AdapterName)
		}
		fmt.Println("Select one explicitly with --target ADAPTER_ID/TARGET_ID to see its proposed changes. No changes were made.")
		return nil
	}
	for _, choice := range choices.Targets {
		if choice.AdapterID+"/"+choice.TargetInstanceID == requested {
			return printPreview(ctx, ac, h, p, byAdapter[choice.AdapterID], byPair[requested], facts)
		}
	}
	return selection.NoCompatibleError{Reason: "no_compatible_adapter", RequestedTarget: requested, Message: fmt.Sprintf("no compatible preview target %q", requested)}
}

func printPreview(ctx context.Context, ac adapterclient.Client, h protocol.HostContext, p platformclient.Discovered, a adapterclient.Discovered, t adapterv1.DetectedTarget, facts adapterv1.PreflightFacts) error {
	state, err := adapterCall[adapterv1.DisplayManagerState](ctx, ac, a, h, "InspectState", adapterv1.InspectStatePayload{Target: t})
	if err != nil {
		return err
	}
	if err := state.Validate(); err != nil {
		return err
	}
	if state.Enabled == "unknown" || state.Active == "unknown" || state.Configurable == "unknown" {
		return fmt.Errorf("target state is unknown")
	}
	caps := []string{preflightCapability}
	prereq, err := adapterCall[adapterv1.PrerequisiteReport](ctx, ac, a, h, "CheckPrerequisites", adapterv1.CheckPrerequisitesPayload{Target: t, Mode: "fresh_install", RequestedCapabilities: caps})
	if err != nil {
		return err
	}
	statuses := map[string]string{}
	for _, f := range prereq.Findings {
		if f.PrerequisiteID == "" || statuses[f.PrerequisiteID] != "" || !protocol.OneOf(f.Status, "satisfied", "missing", "unknown") {
			return fmt.Errorf("malformed prerequisite report")
		}
		statuses[f.PrerequisiteID] = f.Status
		fmt.Printf("Prerequisite %q: %s (%v)\n", f.PrerequisiteID, f.Status, f.Remediation)
	}
	for _, d := range a.Descriptor.Prerequisites {
		if d.Required && statuses[d.ID] == "" {
			return fmt.Errorf("required prerequisite %q was not assessed", d.ID)
		}
	}
	report, err := json.Marshal(prereq.Findings)
	if err != nil {
		return err
	}
	plan, err := adapterCall[adapterv1.InstallPreview](ctx, ac, a, h, "PlanInstall", adapterv1.PlanInstallPayload{Target: t, CurrentState: state, Mode: "fresh_install", RequestedCapabilities: caps, RemediationPolicy: protocol.Object{}, PrerequisiteReport: protocol.Object{"findings": report}})
	if err != nil {
		return err
	}
	if plan.TargetInstanceID != t.InstanceID || len(plan.Changes) == 0 {
		return fmt.Errorf("incomplete proposal or target mismatch")
	}
	// Evidence timestamps are not part of the semantic identity.
	for i := range facts.Packages {
		facts.Packages[i].Evidence = nil
	}
	for i := range facts.Services {
		facts.Services[i].Evidence = nil
	}
	for i := range prereq.Findings {
		prereq.Findings[i].Evidence = nil
	}
	state.Evidence = nil
	sort.Strings(plan.Replacement)
	encoded, err := json.Marshal(struct {
		Provider, Adapter, ProviderDigest, AdapterDigest, Architecture string
		Facts                                                          adapterv1.PreflightFacts
		State                                                          adapterv1.DisplayManagerState
		Prerequisites                                                  adapterv1.PrerequisiteReport
		Plan                                                           adapterv1.InstallPreview
	}{p.Descriptor.PlatformID, a.Descriptor.AdapterID, p.DescriptorSHA256, a.DescriptorSHA256, h.Architecture, facts, state, prereq, plan})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	fmt.Printf("Preview SHA-256: %x\n", digest)
	for _, change := range plan.Changes {
		fmt.Printf("  %s %q %q\n", change.Action, change.Resource, change.Detail)
	}
	for _, limit := range plan.Limitations {
		fmt.Println(limit)
	}
	fmt.Println("Conditional preview only, not eligible for execution or approval. A verified plan will require its own approval.")
	if len(plan.Replacement) > 0 {
		fmt.Printf("Replacing %q would require separate approval (preview %x).\n", plan.Replacement, digest)
	}
	fmt.Println("No changes were made.")
	return nil
}
