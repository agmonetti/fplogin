package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func inspectHost() (platformv1.PlatformHostReport, error) {
	var r platformv1.PlatformHostReport
	id, err := osReleaseID("/etc/os-release", "/usr/lib/os-release")
	if err != nil {
		return r, err
	}
	r.Architecture = runtime.GOARCH
	switch r.Architecture {
	case "amd64":
		r.Architecture = "x86_64"
	case "arm64":
		r.Architecture = "aarch64"
	}
	encodedID, _ := json.Marshal(id)
	r.Platform = protocol.Object{"distribution": encodedID}
	if id == "arch" {
		r.PackageManager = json.RawMessage(`{"kind":"pacman"}`)
		r.ServiceManager = json.RawMessage(`{"kind":"systemd"}`)
	}
	r.FilesystemPolicy = protocol.Object{}
	r.Packages = []platformv1.PackageCandidate{}
	r.Services = []platformv1.ServiceCandidate{}
	r.Evidence = []protocol.Evidence{evidence("path", "os-release", id)}
	return r, nil
}

func evidence(kind, subject, observed string) protocol.Evidence {
	return protocol.Evidence{Source: "platform", Kind: kind, Subject: subject, Timestamp: time.Now().UTC().Format(time.RFC3339), ObservedValue: observed}
}

func readOnlyQuery(ctx context.Context, executable string, args ...string) (string, error) {
	runner, err := processrunner.New(processrunner.Config{
		Timeout: 3 * time.Second, MaxInputBytes: 1, MaxStdoutBytes: 16 << 20, MaxStderrBytes: 4096,
		Arguments: args, Environment: []string{"SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"},
	})
	if err != nil {
		return "", err
	}
	res, err := runner.Run(ctx, executable, nil)
	if err != nil || len(res.Stderr) > 0 {
		return "", fmt.Errorf("%s %v: %v; stderr=%q", executable, args, err, res.Stderr)
	}
	return string(res.Stdout), nil
}

// An explicit unit mapping also covers older packages that did not declare the
// virtual display-manager capability. Unmapped providers are not absence.
var dmUnits = map[string]string{
	"sddm": "sddm.service", "sddm-fplogin": "sddm.service", "gdm": "gdm.service",
	"lightdm": "lightdm.service", "greetd": "greetd.service", "lxdm": "lxdm.service",
	"xdm-archlinux": "xdm.service", "xorg-xdm": "xdm.service", "ly": "ly.service",
}

func parsePackages(text string, hints []string) ([]platformv1.PackageCandidate, error) {
	wanted := map[string]bool{}
	for _, name := range hints {
		wanted[name] = true
	}
	result := []platformv1.PackageCandidate{}
	seen := map[string]bool{}
	for _, block := range strings.Split(strings.TrimSpace(text), "\n\n") {
		if block == "" {
			continue
		}
		fields := map[string]string{}
		key := ""
		for _, line := range strings.Split(block, "\n") {
			if line == "" {
				continue
			}
			if line[0] == ' ' || line[0] == '\t' {
				fields[key] += " " + strings.TrimSpace(line)
				continue
			}
			if k, v, ok := strings.Cut(line, ":"); ok {
				key = strings.TrimSpace(k)
				fields[key] = strings.TrimSpace(v)
			}
		}
		name, version, provides := fields["Name"], fields["Version"], fields["Provides"]
		if name == "" || version == "" || provides == "" || seen[name] {
			return nil, fmt.Errorf("unrecognized or duplicate pacman package record %q", name)
		}
		seen[name] = true
		dm := dmUnits[name] != ""
		for _, provide := range strings.Fields(provides) {
			capability, _, _ := strings.Cut(provide, "=")
			dm = dm || capability == "display-manager"
		}
		if !dm && !wanted[name] {
			continue
		}
		caps := []string{}
		if dm {
			caps = append(caps, "display-manager")
		}
		encodedVersion, _ := json.Marshal(version)
		result = append(result, platformv1.PackageCandidate{PackageReference: name, DisplayName: name,
			Version: encodedVersion, Installed: "yes", ProvidedCapabilities: caps, Evidence: []protocol.Evidence{evidence("package", name, version)}})
	}
	if !seen["pacman"] {
		return nil, fmt.Errorf("local package inventory did not contain pacman")
	}
	for name := range wanted {
		if !seen[name] {
			result = append(result, platformv1.PackageCandidate{PackageReference: name, DisplayName: name,
				Version: json.RawMessage(`null`), Installed: "no", ProvidedCapabilities: []string{}, Evidence: []protocol.Evidence{evidence("package", name, "absent from local pacman inventory")}})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PackageReference < result[j].PackageReference })
	return result, nil
}

var unitName = regexp.MustCompile(`^[a-zA-Z0-9_.@-]+\.service$`)

type systemQuery func(context.Context, string, ...string) (string, error)

func checkGraphicalAlias(ctx context.Context, query systemQuery, props map[string]string) error {
	if props["FragmentPath"] != "/usr/lib/systemd/system/graphical.target" || props["DropInPaths"] != "" {
		return fmt.Errorf("cannot verify graphical.target display-manager dependency: nonstandard fragment or drop-ins")
	}
	// systemd presents merged, canonicalized dependencies, not their source.
	text, err := query(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--all", "--property=UnitPath")
	if err != nil {
		return err
	}
	value, ok := strings.CutPrefix(strings.TrimSpace(text), "UnitPath=")
	paths := strings.Fields(value)
	if !ok || len(paths) == 0 || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("unknown systemd unit search path")
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("invalid systemd unit search path %q", path)
		}
		for _, suffix := range []string{".wants", ".requires", ".upholds"} {
			dir := filepath.Join(path, "graphical.target"+suffix)
			entries, err := os.ReadDir(dir)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("cannot inspect graphical.target dependencies in %s: %w", dir, err)
			}
			if len(entries) != 0 {
				return fmt.Errorf("cannot verify graphical.target display-manager dependency: additional dependencies in %s", dir)
			}
		}
	}
	return nil
}

func queryServices(ctx context.Context, packages []platformv1.PackageCandidate, query systemQuery) ([]platformv1.ServiceCandidate, error) {
	refs := map[string][]string{}
	for _, pkg := range packages {
		if pkg.Installed != "yes" || len(pkg.ProvidedCapabilities) == 0 {
			continue
		}
		unit := dmUnits[pkg.PackageReference]
		if unit == "" {
			return nil, fmt.Errorf("unknown service for installed display-manager package %q", pkg.PackageReference)
		}
		refs[unit] = append(refs[unit], pkg.PackageReference)
	}
	known := map[string]bool{"display-manager.service": true}
	for _, unit := range dmUnits {
		known[unit] = true
	}
	files, err := query(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "--no-legend", "list-unit-files", "--type=service", "--full")
	if err != nil {
		return nil, err
	}
	loaded, err := query(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "--no-legend", "list-units", "--all", "--type=service", "--plain", "--full")
	if err != nil {
		return nil, err
	}
	graphical, err := query(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--all", "--property=Wants,Requires,BindsTo,Upholds,LoadState,FragmentPath,DropInPaths,NeedDaemonReload", "--", "graphical.target")
	if err != nil {
		return nil, err
	}
	graphicalProps := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(graphical), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if _, duplicate := graphicalProps[key]; !ok || duplicate {
			return nil, fmt.Errorf("unknown graphical.target dependencies")
		}
		graphicalProps[key] = value
	}
	if graphicalProps["LoadState"] != "loaded" || graphicalProps["NeedDaemonReload"] != "no" || graphicalProps["FragmentPath"] == "" {
		return nil, fmt.Errorf("unknown or stale graphical.target configuration")
	}
	if _, ok := graphicalProps["DropInPaths"]; !ok {
		return nil, fmt.Errorf("incomplete graphical.target dependencies")
	}
	bootService := ""
	for _, property := range []string{"Wants", "Requires", "BindsTo", "Upholds"} {
		value, ok := graphicalProps[property]
		if !ok {
			return nil, fmt.Errorf("incomplete graphical.target dependencies: missing %s", property)
		}
		for _, unit := range strings.Fields(value) {
			if !strings.HasSuffix(unit, ".service") {
				continue
			}
			if !known[unit] && !strings.HasPrefix(unit, "ly@") {
				return nil, fmt.Errorf("unclassified graphical.target service %q", unit)
			}
			if property != "Wants" || bootService != "" {
				return nil, fmt.Errorf("unexpected graphical.target display-manager dependency: %s=%s", property, unit)
			}
			bootService = unit
		}
	}
	present := map[string]bool{}
	for _, list := range []string{files, loaded} {
		for _, line := range strings.Split(list, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) < 2 || !strings.HasSuffix(fields[0], ".service") {
				return nil, fmt.Errorf("unrecognized systemctl inventory row %q", line)
			}
			if known[fields[0]] || strings.HasPrefix(fields[0], "ly@") && fields[0] != "ly@.service" {
				present[fields[0]] = true
			}
		}
	}
	if bootService != "" {
		if !present["display-manager.service"] {
			return nil, fmt.Errorf("graphical.target display-manager dependency %q has no standard alias", bootService)
		}
		if err := checkGraphicalAlias(ctx, query, graphicalProps); err != nil {
			return nil, err
		}
	}
	for unit := range refs {
		if present[unit] {
			continue
		}
		foundLy := false
		for name := range present {
			foundLy = foundLy || strings.HasPrefix(name, "ly@")
		}
		if unit != "ly.service" || !foundLy {
			return nil, fmt.Errorf("display-manager package installed but %s was not found", unit)
		}
	}
	units := make([]string, 0, len(present))
	for unit := range present {
		units = append(units, unit)
	}
	sort.Strings(units)
	found := map[string]platformv1.ServiceCandidate{}
	for _, unit := range units {
		if !unitName.MatchString(unit) || strings.HasPrefix(unit, "-") {
			return nil, fmt.Errorf("invalid service name %q", unit)
		}
		text, err := query(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--property=Id,LoadState,ActiveState,UnitFileState", "--", unit)
		if err != nil {
			return nil, err
		}
		props := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || props[key] != "" {
				return nil, fmt.Errorf("malformed service properties for %s", unit)
			}
			props[key] = value
		}
		id := props["Id"]
		if !(known[id] && id != "display-manager.service" || unitName.MatchString(id) && strings.HasPrefix(id, "ly@")) || props["LoadState"] != "loaded" {
			return nil, fmt.Errorf("unknown display-manager unit %s: id=%q load=%q", unit, id, props["LoadState"])
		}
		active, enabled := props["ActiveState"], props["UnitFileState"]
		s := platformv1.ServiceCandidate{ServiceReference: id, Active: "unknown", Enabled: "unknown", Configurable: "unknown",
			PackageReferences: refs[id], Evidence: []protocol.Evidence{evidence("service", unit, active+"/"+enabled)}}
		if strings.HasPrefix(id, "ly@") {
			s.PackageReferences = refs["ly.service"]
		}
		switch active {
		case "active":
			s.Active = "yes"
		case "inactive", "failed":
			s.Active = "no"
		}
		switch enabled {
		case "enabled":
			s.Enabled, s.Configurable = "yes", "yes"
		case "disabled":
			s.Enabled, s.Configurable = "no", "yes"
		case "static":
			s.Enabled, s.Configurable = "no", "no"
		}
		if unit == "display-manager.service" && bootService != "" && bootService != unit && bootService != id {
			return nil, fmt.Errorf("graphical.target dependency %q differs from display-manager.service (%q)", bootService, id)
		}
		if unit == "display-manager.service" && s.Enabled != "yes" || s.Active == "unknown" || s.Enabled == "unknown" {
			return nil, fmt.Errorf("unknown or contradictory service state: %s -> %s (%s/%s)", unit, id, active, enabled)
		}
		if prior, ok := found[id]; ok {
			if prior.Active != s.Active || prior.Enabled != s.Enabled {
				return nil, fmt.Errorf("service %s changed during preflight", id)
			}
			s.Evidence = append(prior.Evidence, s.Evidence...)
		}
		found[id] = s
	}
	result := make([]platformv1.ServiceCandidate, 0, len(found))
	for _, s := range found {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ServiceReference < result[j].ServiceReference })
	return result, nil
}

func preflightQuery(req platformv1.Request) (json.RawMessage, error) {
	if req.Context.Root != "/" || !req.Context.DryRun || req.Context.Elevated || os.Geteuid() == 0 || os.Getuid() == 0 {
		return nil, fmt.Errorf("Arch preflight requires an ordinary user and the local root")
	}
	host, err := inspectHost()
	if err != nil {
		return nil, err
	}
	if string(host.Platform["distribution"]) != `"arch"` {
		return nil, fmt.Errorf("Arch package/service queries are unavailable on %q", host.Platform["distribution"])
	}
	deadline, _ := time.Parse(time.RFC3339, req.Context.Deadline)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	var hints []string
	if req.Operation == "ListPackageCandidates" {
		var p platformv1.ListPackageCandidatesPayload
		if err := json.Unmarshal(req.Payload, &p); err != nil {
			return nil, err
		}
		hints = p.PackageHints
	}
	dbPath, err := readOnlyQuery(ctx, "/usr/bin/pacman-conf", "DBPath")
	if err != nil {
		return nil, err
	}
	dbPath = filepath.Clean(strings.TrimSpace(dbPath))
	if !filepath.IsAbs(dbPath) || strings.ContainsAny(dbPath, "\r\n") {
		return nil, fmt.Errorf("unknown pacman database path %q", dbPath)
	}
	// Do not load sync databases for a local-only inventory.
	out, err := readOnlyQuery(ctx, "/usr/bin/pacman", "--config", "/dev/null", "--dbpath", dbPath, "-Qi")
	if err != nil {
		return nil, err
	}
	pkgs, err := parsePackages(out, hints)
	if err != nil {
		return nil, err
	}
	if req.Operation == "ListPackageCandidates" {
		return json.Marshal(platformv1.PackageCandidateReport{Packages: pkgs})
	}
	services, err := queryServices(ctx, pkgs, readOnlyQuery)
	if err != nil {
		return nil, err
	}
	return json.Marshal(platformv1.ServiceCandidateReport{Services: services})
}
