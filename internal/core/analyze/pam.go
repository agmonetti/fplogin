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

// PAMModule represents a single directive inside a resolved PAM configuration stack.
type PAMModule struct {
	SourceFile string
	LineNumber int
	Type       string // "auth", "account", "session", "password"
	Control    string // "required", "sufficient", "optional", "requisite", etc.
	Module     string // e.g. "pam_kwallet5.so", "pam_gnome_keyring.so"
	Args       []string
}

// PAMStack holds the resolved directives for a PAM service, grouped by type.
type PAMStack struct {
	ServiceName string
	Root        string
	Modules     map[string][]PAMModule // grouped by type ("auth", "session", etc.)
	FilesParsed []string
	Evidence    []protocol.Evidence
}

// ParsePAM resolves the PAM stack for serviceName starting at root/etc/pam.d/<serviceName>
// traversing include and substack directives up to maxDepth.
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
		FilesParsed: []string{},
		Evidence:    []protocol.Evidence{},
	}

	pamDir := filepath.Join(root, "etc", "pam.d")
	serviceFile := filepath.Join(pamDir, serviceName)

	visited := make(map[string]bool)
	err := stack.parseFile(pamDir, serviceFile, 0, maxDepth, visited)
	if err != nil && !os.IsNotExist(err) {
		return stack, err
	}

	return stack, nil
}

func (s *PAMStack) parseFile(pamDir, filePath string, depth, maxDepth int, visited map[string]bool) error {
	cleanPath := filepath.Clean(filePath)
	if visited[cleanPath] {
		return nil // avoid cycles
	}
	visited[cleanPath] = true

	file, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.Evidence = append(s.Evidence, protocol.Evidence{
				Source:        "platform",
				Kind:          "path",
				Subject:       cleanPath,
				ObservedValue: "file does not exist",
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			})
			return err
		}
		return fmt.Errorf("open PAM file %q: %w", cleanPath, err)
	}
	defer file.Close()

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
			if len(fields) >= 2 && depth < maxDepth {
				subFile := filepath.Join(pamDir, fields[1])
				_ = s.parseFile(pamDir, subFile, depth+1, maxDepth, visited)
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		modType := strings.ToLower(fields[0])
		control := strings.ToLower(fields[1])
		module := fields[2]
		args := fields[3:]

		// Strip leading '-' if present in module or type
		modType = strings.TrimPrefix(modType, "-")
		module = strings.TrimPrefix(module, "-")

		observedLines = append(observedLines, line)

		if control == "include" || control == "substack" {
			if depth < maxDepth {
				subFile := filepath.Join(pamDir, module)
				_ = s.parseFile(pamDir, subFile, depth+1, maxDepth, visited)
			}
			continue
		}

		if _, valid := s.Modules[modType]; valid {
			mod := PAMModule{
				SourceFile: cleanPath,
				LineNumber: lineNum,
				Type:       modType,
				Control:    control,
				Module:     filepath.Base(module),
				Args:       args,
			}
			s.Modules[modType] = append(s.Modules[modType], mod)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan PAM file %q: %w", cleanPath, err)
	}

	s.Evidence = append(s.Evidence, protocol.Evidence{
		Source:        "platform",
		Kind:          "path",
		Subject:       cleanPath,
		ObservedValue: strings.Join(observedLines, "\n"),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	})

	return nil
}

// HasModule reports whether a specific PAM module (e.g. "pam_kwallet5.so") is present
// in any of the specified types ("auth", "session", etc.).
func (s *PAMStack) HasModule(moduleName string, types ...string) bool {
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

// FindModules returns all occurrences of a module across the stack.
func (s *PAMStack) FindModules(moduleName string) []PAMModule {
	var found []PAMModule
	base := filepath.Base(moduleName)
	for _, mods := range s.Modules {
		for _, mod := range mods {
			if mod.Module == base || strings.TrimSuffix(mod.Module, ".so") == strings.TrimSuffix(base, ".so") {
				found = append(found, mod)
			}
		}
	}
	return found
}
