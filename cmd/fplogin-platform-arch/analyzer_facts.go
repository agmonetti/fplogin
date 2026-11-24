package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"fplogin/internal/processrunner"
	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

var (
	validUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	watchedAnalyzerPkgs  = []string{
		"fprintd",
		"kwallet",
		"kwallet5",
		"kwallet-pam",
		"gnome-keyring",
		"pam_mount",
	}
	knownDMServiceUnits = []string{
		"display-manager.service",
		"sddm.service",
		"gdm.service",
		"lightdm.service",
		"greetd.service",
		"lxdm.service",
		"xdm.service",
		"ly.service",
	}
)

type rawCommandRunner func(ctx context.Context, executable string, args ...string) (stdout, stderr string, err error)

type analyzerProber struct {
	runCmd          rawCommandRunner
	statFile        func(string) (os.FileInfo, error)
	readDir         func(string) ([]os.DirEntry, error)
	openFile        func(string) (*os.File, error)
	pamFprintdPath  string
	fprintdListPath string
	dbusServicesDir string
}

func defaultAnalyzerProber() analyzerProber {
	return analyzerProber{
		runCmd:          runBoundedReadOnly,
		statFile:        os.Stat,
		readDir:         os.ReadDir,
		openFile:        os.Open,
		pamFprintdPath:  "/usr/lib/security/pam_fprintd.so",
		fprintdListPath: "/usr/bin/fprintd-list",
		dbusServicesDir: "/usr/share/dbus-1/services",
	}
}

func runBoundedReadOnly(ctx context.Context, executable string, args ...string) (string, string, error) {
	runner, err := processrunner.New(processrunner.Config{
		Timeout:        3 * time.Second,
		MaxInputBytes:  1,
		MaxStdoutBytes: 4 << 20,
		MaxStderrBytes: 16384,
		Arguments:      args,
		Environment:    []string{"LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"},
	})
	if err != nil {
		return "", "", err
	}
	res, err := runner.Run(ctx, executable, nil)
	return string(res.Stdout), string(res.Stderr), err
}

func collectAnalyzerFacts(req platformv1.Request) (json.RawMessage, error) {
	if req.Context.Root != "/" {
		return nil, &opError{code: "host_read_failed", message: "Arch analyzer probes require local root /"}
	}
	host, err := inspectHost()
	if err != nil {
		return nil, &opError{code: "host_read_failed", message: err.Error()}
	}
	if string(host.Platform["distribution"]) != `"arch"` {
		return nil, &opError{code: "unsupported_platform", message: fmt.Sprintf("Arch analyzer probes unavailable on %q", host.Platform["distribution"])}
	}

	var payload platformv1.CollectAnalyzerFactsPayload
	if err := protocol.DecodeStrict(req.Payload, &payload, "scope", "probe_ids"); err != nil {
		return nil, &opError{code: "invalid_request", message: err.Error()}
	}

	deadlineStr := req.Context.Deadline
	if payload.Deadline != "" {
		deadlineStr = payload.Deadline
	}
	deadline, err := time.Parse(time.RFC3339, deadlineStr)
	if err != nil {
		deadline = time.Now().Add(10 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	facts := defaultAnalyzerProber().collect(ctx, payload)
	if err := facts.Validate(); err != nil {
		return nil, &opError{code: "internal_error", message: fmt.Sprintf("invalid analyzer facts: %v", err)}
	}
	return json.Marshal(facts)
}

func (p analyzerProber) collect(ctx context.Context, payload platformv1.CollectAnalyzerFactsPayload) platformv1.PlatformAnalyzerFacts {
	want := map[string]bool{}
	if len(payload.ProbeIDs) == 0 {
		want["fprintd"] = true
		want["packages"] = true
		want["secret_service"] = true
		want["display_managers"] = true
	} else {
		for _, id := range payload.ProbeIDs {
			if id == "all" {
				want["fprintd"] = true
				want["packages"] = true
				want["secret_service"] = true
				want["display_managers"] = true
			} else {
				want[id] = true
			}
		}
	}

	username := ""
	if rawUser, ok := payload.TargetContext["username"]; ok {
		var u string
		if json.Unmarshal(rawUser, &u) == nil && validUsernamePattern.MatchString(u) {
			username = u
		}
	}

	facts := platformv1.PlatformAnalyzerFacts{
		Scope:       payload.Scope,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Evidence:    []protocol.Evidence{},
		ProbeErrors: []platformv1.ProbeError{},
	}

	if want["packages"] || want["fprintd"] || want["display_managers"] {
		p.probePackages(ctx, want, &facts)
	}
	if want["fprintd"] {
		p.probeFprintd(ctx, username, &facts)
	}
	if want["secret_service"] {
		p.probeSecretService(&facts)
	}
	if want["display_managers"] {
		p.probeDisplayManagers(ctx, &facts)
	}

	return facts
}

func (p analyzerProber) probePackages(ctx context.Context, want map[string]bool, facts *platformv1.PlatformAnalyzerFacts) {
	stdout, stderr, err := p.runCmd(ctx, "/usr/bin/pacman-conf", "DBPath")
	if err != nil || strings.TrimSpace(stderr) != "" {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "packages",
			Message: fmt.Sprintf("pacman-conf DBPath failed: %v (stderr=%q)", err, strings.TrimSpace(stderr)),
		})
		return
	}
	dbPath := filepath.Clean(strings.TrimSpace(stdout))
	if !filepath.IsAbs(dbPath) || strings.ContainsAny(dbPath, "\r\n") {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "packages",
			Message: fmt.Sprintf("invalid pacman DBPath %q", dbPath),
		})
		return
	}

	qOut, qErrStr, qErr := p.runCmd(ctx, "/usr/bin/pacman", "--config", "/dev/null", "--dbpath", dbPath, "-Q")
	if qErr != nil || strings.TrimSpace(qErrStr) != "" {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "packages",
			Message: fmt.Sprintf("pacman -Q failed: %v (stderr=%q)", qErr, strings.TrimSpace(qErrStr)),
		})
		return
	}

	installed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(qOut), "\n") {
		if name, ver, ok := strings.Cut(strings.TrimSpace(line), " "); ok && name != "" {
			installed[name] = strings.TrimSpace(ver)
		}
	}

	emitted := map[string]bool{}
	if want["packages"] || want["fprintd"] {
		for _, pkg := range watchedAnalyzerPkgs {
			if !want["packages"] && pkg != "fprintd" {
				continue
			}
			emitted[pkg] = true
			if ver, ok := installed[pkg]; ok {
				facts.Evidence = append(facts.Evidence, evidence("package", pkg, fmt.Sprintf("version=%s, status=installed", ver)))
			} else {
				facts.Evidence = append(facts.Evidence, evidence("package", pkg, "status=absent"))
			}
		}
	}

	if want["display_managers"] {
		dmNames := make([]string, 0, len(dmUnits))
		for name := range dmUnits {
			dmNames = append(dmNames, name)
		}
		sort.Strings(dmNames)
		for _, pkg := range dmNames {
			if emitted[pkg] {
				continue
			}
			if ver, ok := installed[pkg]; ok {
				facts.Evidence = append(facts.Evidence, evidence("package", pkg, fmt.Sprintf("version=%s, status=installed, role=display-manager", ver)))
			}
		}
	}
}

func (p analyzerProber) probeFprintd(ctx context.Context, username string, facts *platformv1.PlatformAnalyzerFacts) {
	// 1. pam_fprintd.so presence
	if _, err := p.statFile(p.pamFprintdPath); err == nil {
		facts.Evidence = append(facts.Evidence, evidence("path", p.pamFprintdPath, "status=present"))
	} else if os.IsNotExist(err) {
		facts.Evidence = append(facts.Evidence, evidence("path", p.pamFprintdPath, "status=absent"))
	} else {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "fprintd.pam_module",
			Message: fmt.Sprintf("stat %q failed: %v", p.pamFprintdPath, err),
		})
	}

	// 2. fprintd.service state (read-only systemctl show)
	svcOut, svcErrStr, svcErr := p.runCmd(ctx, "/usr/bin/systemctl", "--system", "--no-pager", "show", "--all", "--property=LoadState,ActiveState,UnitFileState", "--", "fprintd.service")
	if svcErr != nil {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "fprintd.service",
			Message: fmt.Sprintf("systemctl show fprintd.service failed: %v (stderr=%q)", svcErr, strings.TrimSpace(svcErrStr)),
		})
	} else {
		props := parseSystemctlProps(svcOut)
		load := props["LoadState"]
		active := props["ActiveState"]
		enabled := props["UnitFileState"]
		if enabled == "" {
			enabled = "none"
		}
		facts.Evidence = append(facts.Evidence, evidence(
			"service",
			"fprintd.service",
			fmt.Sprintf("load=%s, active=%s, enabled=%s", load, active, enabled),
		))
	}

	// 3. Read-only reader & enrollment query via fprintd-list <username>
	if username == "" {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "fprintd.enrollment",
			Message: "target username not provided; skipped read-only fprintd-list enrollment query",
		})
		return
	}
	if _, err := p.statFile(p.fprintdListPath); err != nil {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "fprintd.enrollment",
			Message: fmt.Sprintf("fprintd-list unavailable at %q: %v", p.fprintdListPath, err),
		})
		return
	}

	listOut, listErrStr, listErr := p.runCmd(ctx, p.fprintdListPath, username)
	combinedLower := strings.ToLower(listOut + "\n" + listErrStr)
	switch {
	case strings.Contains(combinedLower, "no devices available") || strings.Contains(combinedLower, "nosuchdevice"):
		facts.Evidence = append(facts.Evidence, evidence("command", "fprintd-list", "status=no_reader, reader=absent"))
	case listErr == nil && strings.Contains(combinedLower, "has no fingers enrolled"):
		facts.Evidence = append(facts.Evidence, evidence("command", "fprintd-list", "status=no_enrolled_fingers, reader=present, enrolled_count=0"))
	case listErr == nil && strings.Contains(combinedLower, "fingerprints for user"):
		count := 0
		for _, line := range strings.Split(listOut, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "- ") {
				count++
			}
		}
		if count > 0 {
			facts.Evidence = append(facts.Evidence, evidence("command", "fprintd-list", fmt.Sprintf("status=enrolled, reader=present, enrolled_count=%d", count)))
		} else {
			facts.Evidence = append(facts.Evidence, evidence("command", "fprintd-list", "status=no_enrolled_fingers, reader=present, enrolled_count=0"))
		}
	default:
		msg := strings.TrimSpace(listErrStr)
		if msg == "" && listErr != nil {
			msg = listErr.Error()
		}
		if msg == "" {
			msg = "unrecognized fprintd-list output"
		}
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "fprintd.enrollment",
			Message: fmt.Sprintf("fprintd-list failed: %s", msg),
		})
	}
}

func (p analyzerProber) probeSecretService(facts *platformv1.PlatformAnalyzerFacts) {
	entries, err := p.readDir(p.dbusServicesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "secret_service",
			Message: fmt.Sprintf("read %q failed: %v", p.dbusServicesDir, err),
		})
		return
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
			continue
		}
		fullPath := filepath.Join(p.dbusServicesDir, entry.Name())
		f, openErr := p.openFile(fullPath)
		if openErr != nil {
			facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
				ProbeID: "secret_service",
				Message: fmt.Sprintf("open %q failed: %v", fullPath, openErr),
			})
			continue
		}
		var nameVal, execVal string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if k, v, ok := strings.Cut(line, "="); ok {
				switch strings.TrimSpace(k) {
				case "Name":
					nameVal = strings.TrimSpace(v)
				case "Exec":
					execVal = strings.TrimSpace(v)
				}
			}
		}
		f.Close()

		if nameVal == "org.freedesktop.secrets" {
			execBase := "unknown"
			if fields := strings.Fields(execVal); len(fields) > 0 {
				execBase = filepath.Base(fields[0])
			}
			facts.Evidence = append(facts.Evidence, evidence(
				"path",
				fullPath,
				fmt.Sprintf("dbus_service=org.freedesktop.secrets, exec=%s", execBase),
			))
		}
	}
}

func (p analyzerProber) probeDisplayManagers(ctx context.Context, facts *platformv1.PlatformAnalyzerFacts) {
	args := append([]string{"--system", "--no-pager", "show", "--all", "--property=Id,LoadState,ActiveState,UnitFileState", "--"}, knownDMServiceUnits...)
	out, errStr, err := p.runCmd(ctx, "/usr/bin/systemctl", args...)
	if err != nil {
		facts.ProbeErrors = append(facts.ProbeErrors, platformv1.ProbeError{
			ProbeID: "display_managers",
			Message: fmt.Sprintf("systemctl show display managers failed: %v (stderr=%q)", err, strings.TrimSpace(errStr)),
		})
		return
	}

	seen := map[string]bool{}
	for _, block := range strings.Split(strings.TrimSpace(out), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		props := parseSystemctlProps(block)
		id := props["Id"]
		load := props["LoadState"]
		if id == "" || load != "loaded" || id == "display-manager.service" || seen[id] {
			continue
		}
		seen[id] = true
		active := props["ActiveState"]
		enabled := props["UnitFileState"]
		if enabled == "" {
			enabled = "none"
		}
		facts.Evidence = append(facts.Evidence, evidence(
			"service",
			id,
			fmt.Sprintf("active=%s, enabled=%s, role=display-manager", active, enabled),
		))
	}
}

func parseSystemctlProps(block string) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(block), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k != "" {
			props[k] = v
		}
	}
	return props
}
