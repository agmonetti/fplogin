package analyze

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fplogin/internal/protocol"
)

// SessionFacts captures facts observed in desktop session startup scripts,
// XDG autostart entries, and user systemd units.
type SessionFacts struct {
	AutostartGnomeKeyring bool
	AutostartKWallet      bool
	AutostartFiles        []string
	UserSystemdUnits      []string
	HyprlandConfigPath    string
	HyprlandExecOnce      []string

	Evidence []protocol.Evidence
	Issues   []ProbeIssue
}

// ProbeSession inspects /etc/xdg/autostart, ~/.config/autostart, ~/.config/systemd/user,
// and ~/.config/hypr/hyprland.conf to detect if keyring/wallet services are launched
// via session startup rather than PAM.
func ProbeSession(root, userHome string) (*SessionFacts, error) {
	if root == "" {
		root = "/"
	}

	facts := &SessionFacts{
		AutostartFiles:   []string{},
		UserSystemdUnits: []string{},
		HyprlandExecOnce: []string{},
		Evidence:         []protocol.Evidence{},
		Issues:           []ProbeIssue{},
	}

	// 1. Inspect /etc/xdg/autostart/*.desktop
	facts.inspectAutostartDir(filepath.Join(root, "etc", "xdg", "autostart"))

	if userHome != "" {
		// 2. Inspect ~/.config/autostart/*.desktop
		facts.inspectAutostartDir(filepath.Join(userHome, ".config", "autostart"))

		// 3. Inspect ~/.config/systemd/user/*.service and *.wants/*.service
		facts.inspectUserSystemdDir(filepath.Join(userHome, ".config", "systemd", "user"))

		// 4. Inspect ~/.config/hypr/hyprland.conf
		facts.inspectHyprlandConfig(filepath.Join(userHome, ".config", "hypr", "hyprland.conf"))
	}

	return facts, nil
}

func (f *SessionFacts) inspectAutostartDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			ev := coreErrorEvidence("path", dir, "unreadable", err.Error())
			f.Issues = append(f.Issues, ProbeIssue{
				Code:     "session_read_error",
				Path:     dir,
				Message:  fmt.Sprintf("Could not read autostart directory %q: %v", dir, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
		return
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
			continue
		}
		desktopPath := filepath.Join(dir, e.Name())
		f.AutostartFiles = append(f.AutostartFiles, desktopPath)

		hidden, execLine, readErr := inspectDesktopEntry(desktopPath)
		if readErr != nil {
			ev := coreErrorEvidence("path", desktopPath, "unreadable", readErr.Error())
			f.Issues = append(f.Issues, ProbeIssue{
				Code:     "session_read_error",
				Path:     desktopPath,
				Message:  fmt.Sprintf("Could not read autostart entry %q: %v", desktopPath, readErr),
				Evidence: []protocol.Evidence{ev},
			})
			continue
		}
		if hidden {
			continue
		}

		combined := strings.ToLower(e.Name() + " " + execLine)
		if strings.Contains(combined, "gnome-keyring") {
			f.AutostartGnomeKeyring = true
			f.Evidence = append(f.Evidence, coreEvidence("path", desktopPath, "gnome-keyring autostart desktop entry"))
		}
		if strings.Contains(combined, "kwallet") {
			f.AutostartKWallet = true
			f.Evidence = append(f.Evidence, coreEvidence("path", desktopPath, "kwallet autostart desktop entry"))
		}
	}
}

func inspectDesktopEntry(path string) (hidden bool, execLine string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return false, "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if strings.EqualFold(k, "Hidden") && strings.EqualFold(v, "true") {
			hidden = true
		}
		if strings.EqualFold(k, "X-GNOME-Autostart-enabled") && strings.EqualFold(v, "false") {
			hidden = true
		}
		if strings.EqualFold(k, "Exec") {
			execLine = v
		}
	}
	return hidden, execLine, scanner.Err()
}

func (f *SessionFacts) inspectUserSystemdDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			ev := coreErrorEvidence("path", dir, "unreadable", err.Error())
			f.Issues = append(f.Issues, ProbeIssue{
				Code:     "session_read_error",
				Path:     dir,
				Message:  fmt.Sprintf("Could not read user systemd directory %q: %v", dir, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
		return
	}

	inspectUnit := func(unitPath, unitName string) {
		f.UserSystemdUnits = append(f.UserSystemdUnits, unitPath)
		lowerName := strings.ToLower(unitName)
		execStart := ""
		if file, openErr := os.Open(unitPath); openErr == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "ExecStart=") {
					execStart += " " + strings.TrimPrefix(line, "ExecStart=")
				}
			}
			file.Close()
		}
		combined := strings.ToLower(lowerName + " " + execStart)
		if strings.Contains(combined, "gnome-keyring") {
			f.AutostartGnomeKeyring = true
			f.Evidence = append(f.Evidence, coreEvidence("path", unitPath, "gnome-keyring user systemd unit"))
		}
		if strings.Contains(combined, "kwallet") {
			f.AutostartKWallet = true
			f.Evidence = append(f.Evidence, coreEvidence("path", unitPath, "kwallet user systemd unit"))
		}
	}

	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() && strings.HasSuffix(e.Name(), ".wants") {
			subEntries, subErr := os.ReadDir(full)
			if subErr != nil {
				if !os.IsNotExist(subErr) {
					ev := coreErrorEvidence("path", full, "unreadable", subErr.Error())
					f.Issues = append(f.Issues, ProbeIssue{
						Code:     "session_read_error",
						Path:     full,
						Message:  fmt.Sprintf("Could not read user systemd wants directory %q: %v", full, subErr),
						Evidence: []protocol.Evidence{ev},
					})
				}
				continue
			}
			for _, se := range subEntries {
				if strings.HasSuffix(se.Name(), ".service") {
					inspectUnit(filepath.Join(full, se.Name()), se.Name())
				}
			}
			continue
		}
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".service") {
			inspectUnit(full, e.Name())
		}
	}
}

func (f *SessionFacts) inspectHyprlandConfig(hyprConfig string) {
	info, err := os.Stat(hyprConfig)
	if err != nil {
		if !os.IsNotExist(err) {
			ev := coreErrorEvidence("path", hyprConfig, "unreadable", err.Error())
			f.Issues = append(f.Issues, ProbeIssue{
				Code:     "session_read_error",
				Path:     hyprConfig,
				Message:  fmt.Sprintf("Could not stat Hyprland config %q: %v", hyprConfig, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
		return
	}
	if info.IsDir() {
		return
	}

	f.HyprlandConfigPath = hyprConfig
	file, openErr := os.Open(hyprConfig)
	if openErr != nil {
		ev := coreErrorEvidence("path", hyprConfig, "unreadable", openErr.Error())
		f.Issues = append(f.Issues, ProbeIssue{
			Code:     "session_read_error",
			Path:     hyprConfig,
			Message:  fmt.Sprintf("Could not read Hyprland config %q: %v", hyprConfig, openErr),
			Evidence: []protocol.Evidence{ev},
		})
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "exec-once") {
			f.HyprlandExecOnce = append(f.HyprlandExecOnce, line)
			lower := strings.ToLower(line)
			if strings.Contains(lower, "gnome-keyring") {
				f.AutostartGnomeKeyring = true
			}
			if strings.Contains(lower, "kwallet") {
				f.AutostartKWallet = true
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		ev := coreErrorEvidence("path", hyprConfig, "scan error", scanErr.Error())
		f.Issues = append(f.Issues, ProbeIssue{
			Code:     "session_read_error",
			Path:     hyprConfig,
			Message:  fmt.Sprintf("Error scanning Hyprland config %q: %v", hyprConfig, scanErr),
			Evidence: []protocol.Evidence{ev},
		})
		return
	}
	if len(f.HyprlandExecOnce) > 0 {
		f.Evidence = append(f.Evidence, coreEvidence(
			"path",
			hyprConfig,
			fmt.Sprintf("hyprland_exec_once_entries=%d", len(f.HyprlandExecOnce)),
		))
	}
}
