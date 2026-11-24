// Package analyze implements read-only probes and findings generation for
// password-derived facilities that may be impacted by biometric authentication.
package analyze

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fplogin/internal/protocol"
)

// ProbeIssue represents a non-fatal read, parse, or visibility issue discovered by a core probe.
type ProbeIssue struct {
	Code     string
	Path     string
	Message  string
	Evidence []protocol.Evidence
}

// PAMModule represents a single directive inside a resolved PAM configuration stack.
type PAMModule struct {
	SourceFile        string
	LineNumber        int
	Type              string // "auth", "account", "session", "password"
	OptionalIfMissing bool   // true when directive had leading '-' (e.g. "-auth")
	Control           string // "required", "sufficient", "optional", "[success=1 default=ignore]", etc.
	Module            string // e.g. "pam_kwallet5.so", "pam_gnome_keyring.so"
	Args              []string
}

// PAMStack holds the resolved directives for a PAM service, grouped by type.
type PAMStack struct {
	ServiceName   string
	Root          string
	Modules       map[string][]PAMModule // grouped by type ("auth", "session", etc.)
	CustomModules []PAMModule            // unrecognized auth/session modules whose credential coupling is unknown
	FilesParsed   []string
	Evidence      []protocol.Evidence
	Issues        []ProbeIssue
}

// standardPAMModules are common base Linux/systemd PAM modules whose auth/session
// behavior is known not to represent an unrecognized custom password-derived secret store.
var standardPAMModules = map[string]bool{
	"pam_access.so":        true,
	"pam_apparmor.so":      true,
	"pam_cap.so":           true,
	"pam_ck_connector.so":  true,
	"pam_cracklib.so":      true,
	"pam_deny.so":          true,
	"pam_echo.so":          true,
	"pam_elogind.so":       true,
	"pam_env.so":           true,
	"pam_faillock.so":      true,
	"pam_fprintd.so":       true,
	"pam_gnome_keyring.so": true,
	"pam_issue.so":         true,
	"pam_keyinit.so":       true,
	"pam_kwallet.so":       true,
	"pam_kwallet5.so":      true,
	"pam_lastlog.so":       true,
	"pam_lastlog2.so":      true,
	"pam_limits.so":        true,
	"pam_listfile.so":      true,
	"pam_localuser.so":     true,
	"pam_loginuid.so":      true,
	"pam_mail.so":          true,
	"pam_motd.so":          true,
	"pam_mount.so":         true,
	"pam_namespace.so":     true,
	"pam_nologin.so":       true,
	"pam_permit.so":        true,
	"pam_pwhistory.so":     true,
	"pam_pwquality.so":     true,
	"pam_rootok.so":        true,
	"pam_securetty.so":     true,
	"pam_selinux.so":       true,
	"pam_shells.so":        true,
	"pam_succeed_if.so":    true,
	"pam_systemd.so":       true,
	"pam_systemd_home.so":  true,
	"pam_tally2.so":        true,
	"pam_time.so":          true,
	"pam_umask.so":         true,
	"pam_unix.so":          true,
	"pam_warn.so":          true,
	"pam_wheel.so":         true,
	"pam_wtmpdb.so":        true,
	"pam_xauth.so":         true,
}

// ParsePAM resolves the PAM stack for serviceName starting at root/etc/pam.d/<serviceName>
// traversing include, substack, and @include directives up to maxDepth.
func ParsePAM(root, serviceName string, maxDepth int) (*PAMStack, error) {
	if root == "" {
		root = "/"
	}
	if maxDepth <= 0 {
		maxDepth = 10
	}

	stack := &PAMStack{
		ServiceName: serviceName,
		Root:        root,
		Modules: map[string][]PAMModule{
			"auth":     {},
			"account":  {},
			"session":  {},
			"password": {},
		},
		CustomModules: []PAMModule{},
		FilesParsed:   []string{},
		Evidence:      []protocol.Evidence{},
		Issues:        []ProbeIssue{},
	}

	pamDir := filepath.Join(root, "etc", "pam.d")
	serviceFile := filepath.Join(pamDir, filepath.Base(serviceName))

	parsed := make(map[string]bool)
	inStack := make(map[string]bool)
	err := stack.parseFile(pamDir, serviceFile, 0, maxDepth, parsed, inStack, true)
	if err != nil && !os.IsNotExist(err) {
		return stack, err
	}

	return stack, nil
}

func coreEvidence(kind, subject, observed string) protocol.Evidence {
	return protocol.Evidence{
		Source:        "core",
		Kind:          kind,
		Subject:       subject,
		ObservedValue: observed,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}
}

func coreErrorEvidence(kind, subject, observed, errMsg string) protocol.Evidence {
	return protocol.Evidence{
		Source:        "core",
		Kind:          kind,
		Subject:       subject,
		ObservedValue: observed,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Error:         errMsg,
	}
}

func (s *PAMStack) parseFile(pamDir, filePath string, depth, maxDepth int, parsed, inStack map[string]bool, isRoot bool) error {
	cleanPath := filepath.Clean(filePath)
	if inStack[cleanPath] {
		ev := coreEvidence("path", cleanPath, "circular include detected")
		s.Issues = append(s.Issues, ProbeIssue{
			Code:     "pam_include_cycle",
			Path:     cleanPath,
			Message:  fmt.Sprintf("Circular PAM include detected at %q", cleanPath),
			Evidence: []protocol.Evidence{ev},
		})
		return nil
	}
	if parsed[cleanPath] {
		return nil
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			ev := coreErrorEvidence("path", cleanPath, "file does not exist", err.Error())
			s.Evidence = append(s.Evidence, ev)
			code := "pam_missing_include"
			msg := fmt.Sprintf("Included PAM file %q does not exist", cleanPath)
			if isRoot {
				code = "pam_service_missing"
				msg = fmt.Sprintf("PAM service file %q does not exist", cleanPath)
			}
			s.Issues = append(s.Issues, ProbeIssue{
				Code:     code,
				Path:     cleanPath,
				Message:  msg,
				Evidence: []protocol.Evidence{ev},
			})
			return err
		}
		ev := coreErrorEvidence("path", cleanPath, "file unreadable", err.Error())
		s.Evidence = append(s.Evidence, ev)
		s.Issues = append(s.Issues, ProbeIssue{
			Code:     "pam_read_error",
			Path:     cleanPath,
			Message:  fmt.Sprintf("Failed to read PAM file %q: %v", cleanPath, err),
			Evidence: []protocol.Evidence{ev},
		})
		return fmt.Errorf("open PAM file %q: %w", cleanPath, err)
	}
	defer file.Close()

	inStack[cleanPath] = true
	defer delete(inStack, cleanPath)
	parsed[cleanPath] = true
	s.FilesParsed = append(s.FilesParsed, cleanPath)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var observedLines []string

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle @include directive (common in Debian/Ubuntu PAM)
		if strings.HasPrefix(line, "@include") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				observedLines = append(observedLines, line)
				s.followInclude(pamDir, fields[1], depth, maxDepth, parsed, inStack)
			}
			continue
		}

		modType, optionalMissing, control, module, args, parseErr := parsePAMDirective(line)
		if parseErr != nil {
			ev := coreErrorEvidence("path", cleanPath, fmt.Sprintf("line %d malformed", lineNum), parseErr.Error())
			s.Issues = append(s.Issues, ProbeIssue{
				Code:     "pam_parse_error",
				Path:     cleanPath,
				Message:  fmt.Sprintf("Unparseable PAM directive in %q line %d: %v", cleanPath, lineNum, parseErr),
				Evidence: []protocol.Evidence{ev},
			})
			continue
		}
		if modType == "" {
			continue
		}

		observedLines = append(observedLines, line)

		if control == "include" || control == "substack" {
			s.followInclude(pamDir, module, depth, maxDepth, parsed, inStack)
			continue
		}

		if _, valid := s.Modules[modType]; valid {
			baseMod := filepath.Base(module)
			mod := PAMModule{
				SourceFile:        cleanPath,
				LineNumber:        lineNum,
				Type:              modType,
				OptionalIfMissing: optionalMissing,
				Control:           control,
				Module:            baseMod,
				Args:              args,
			}
			s.Modules[modType] = append(s.Modules[modType], mod)
			if (modType == "auth" || modType == "session") && !standardPAMModules[baseMod] {
				s.CustomModules = append(s.CustomModules, mod)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		ev := coreErrorEvidence("path", cleanPath, "scan error", err.Error())
		s.Issues = append(s.Issues, ProbeIssue{
			Code:     "pam_read_error",
			Path:     cleanPath,
			Message:  fmt.Sprintf("Failed to scan PAM file %q: %v", cleanPath, err),
			Evidence: []protocol.Evidence{ev},
		})
		return fmt.Errorf("scan PAM file %q: %w", cleanPath, err)
	}

	s.Evidence = append(s.Evidence, coreEvidence("path", cleanPath, strings.Join(observedLines, "\n")))
	return nil
}

func (s *PAMStack) followInclude(pamDir, target string, depth, maxDepth int, parsed, inStack map[string]bool) {
	subFile := resolveIncludePath(s.Root, pamDir, target)
	if depth >= maxDepth {
		ev := coreEvidence("path", subFile, fmt.Sprintf("include truncated at max depth %d", maxDepth))
		s.Issues = append(s.Issues, ProbeIssue{
			Code:     "pam_depth_truncated",
			Path:     subFile,
			Message:  fmt.Sprintf("PAM include %q was not followed because max depth (%d) was reached", target, maxDepth),
			Evidence: []protocol.Evidence{ev},
		})
		return
	}
	_ = s.parseFile(pamDir, subFile, depth+1, maxDepth, parsed, inStack, false)
}

func resolveIncludePath(root, pamDir, target string) string {
	if filepath.IsAbs(target) {
		return filepath.Join(root, strings.TrimPrefix(filepath.Clean(target), string(filepath.Separator)))
	}
	return filepath.Join(pamDir, filepath.Base(target))
}

// parsePAMDirective parses a single non-comment PAM line, supporting leading '-'
// modifiers and bracketed control syntax such as "[success=1 default=ignore]".
func parsePAMDirective(line string) (modType string, optionalIfMissing bool, control, module string, args []string, err error) {
	rest := strings.TrimSpace(line)
	idx := strings.IndexAny(rest, " \t")
	if idx <= 0 {
		return "", false, "", "", nil, nil
	}
	rawType := strings.ToLower(rest[:idx])
	optionalIfMissing = strings.HasPrefix(rawType, "-")
	modType = strings.TrimPrefix(rawType, "-")
	rest = strings.TrimSpace(rest[idx:])
	if rest == "" {
		return "", false, "", "", nil, nil
	}

	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return "", false, "", "", nil, fmt.Errorf("unclosed bracketed control expression")
		}
		control = strings.ToLower(strings.TrimSpace(rest[:end+1]))
		rest = strings.TrimSpace(rest[end+1:])
	} else {
		next := strings.IndexAny(rest, " \t")
		if next <= 0 {
			return "", false, "", "", nil, nil
		}
		control = strings.ToLower(rest[:next])
		rest = strings.TrimSpace(rest[next:])
	}

	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false, "", "", nil, nil
	}
	if strings.HasPrefix(fields[0], "-") {
		optionalIfMissing = true
	}
	module = strings.TrimPrefix(fields[0], "-")
	args = fields[1:]
	return modType, optionalIfMissing, control, module, args, nil
}

// HasModule reports whether a specific PAM module (e.g. "pam_kwallet5.so") is present
// in any of the specified types ("auth", "session", etc.).
func (s *PAMStack) HasModule(moduleName string, types ...string) bool {
	if s == nil {
		return false
	}
	if len(types) == 0 {
		types = []string{"auth", "session", "account", "password"}
	}
	base := filepath.Base(moduleName)
	for _, t := range types {
		for _, mod := range s.Modules[t] {
			if mod.Module == base || strings.TrimSuffix(mod.Module, ".so") == strings.TrimSuffix(base, ".so") {
				return true
			}
		}
	}
	return false
}

// FindModules returns all occurrences of a module across the stack in deterministic type order.
func (s *PAMStack) FindModules(moduleName string) []PAMModule {
	if s == nil {
		return nil
	}
	var found []PAMModule
	base := filepath.Base(moduleName)
	for _, t := range []string{"auth", "account", "password", "session"} {
		for _, mod := range s.Modules[t] {
			if mod.Module == base || strings.TrimSuffix(mod.Module, ".so") == strings.TrimSuffix(base, ".so") {
				found = append(found, mod)
			}
		}
	}
	return found
}

// AllOptionalIfMissing reports whether every occurrence of moduleName in auth/session
// carries the leading '-' (ignore-if-absent) PAM modifier.
func (s *PAMStack) AllOptionalIfMissing(moduleName string) bool {
	if s == nil {
		return true
	}
	base := filepath.Base(moduleName)
	for _, t := range []string{"auth", "session"} {
		for _, mod := range s.Modules[t] {
			if mod.Module == base || strings.TrimSuffix(mod.Module, ".so") == strings.TrimSuffix(base, ".so") {
				if !mod.OptionalIfMissing {
					return false
				}
			}
		}
	}
	return true
}

// ModuleEvidence returns targeted evidence records for occurrences of moduleName.
func (s *PAMStack) ModuleEvidence(moduleName string) []protocol.Evidence {
	mods := s.FindModules(moduleName)
	if len(mods) == 0 {
		return nil
	}
	out := make([]protocol.Evidence, 0, len(mods))
	for _, m := range mods {
		obs := fmt.Sprintf("line=%d %s %s %s", m.LineNumber, m.Type, m.Control, m.Module)
		if len(m.Args) > 0 {
			obs += " " + strings.Join(m.Args, " ")
		}
		out = append(out, coreEvidence("path", m.SourceFile, obs))
	}
	return out
}
