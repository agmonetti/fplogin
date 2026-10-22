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

// SessionFacts captures facts observed in desktop session startup scripts and autostart files.
type SessionFacts struct {
	AutostartGnomeKeyring bool
	AutostartKWallet      bool
	AutostartFiles        []string
	HyprlandConfigPath    string
	HyprlandExecOnce      []string

	Evidence []protocol.Evidence
}

// ProbeSession inspects /etc/xdg/autostart and user compositor/window manager configs (e.g. Hyprland)
// to detect if keyring/wallet services are launched via session startup rather than PAM.
func ProbeSession(root, userHome string) (*SessionFacts, error) {
	if root == "" {
		root = "/"
	}

	facts := &SessionFacts{
		AutostartFiles:   []string{},
		HyprlandExecOnce: []string{},
		Evidence:         []protocol.Evidence{},
	}

	// 1. Inspect /etc/xdg/autostart/*.desktop
	autostartDir := filepath.Join(root, "etc", "xdg", "autostart")
	if entries, err := os.ReadDir(autostartDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".desktop") {
				desktopPath := filepath.Join(autostartDir, e.Name())
				facts.AutostartFiles = append(facts.AutostartFiles, desktopPath)

				lower := strings.ToLower(e.Name())
				if strings.Contains(lower, "gnome-keyring") {
					facts.AutostartGnomeKeyring = true
					facts.Evidence = append(facts.Evidence, protocol.Evidence{
						Source:        "platform",
						Kind:          "path",
						Subject:       desktopPath,
						ObservedValue: "gnome-keyring autostart desktop file present",
						Timestamp:     time.Now().UTC().Format(time.RFC3339),
					})
				}
				if strings.Contains(lower, "kwallet") {
					facts.AutostartKWallet = true
					facts.Evidence = append(facts.Evidence, protocol.Evidence{
						Source:        "platform",
						Kind:          "path",
						Subject:       desktopPath,
						ObservedValue: "kwallet autostart desktop file present",
						Timestamp:     time.Now().UTC().Format(time.RFC3339),
					})
				}
			}
		}
	}

	// 2. Inspect ~/.config/hypr/hyprland.conf if userHome provided
	if userHome != "" {
		hyprConfig := filepath.Join(userHome, ".config", "hypr", "hyprland.conf")
		if info, err := os.Stat(hyprConfig); err == nil && !info.IsDir() {
			facts.HyprlandConfigPath = hyprConfig
			file, err := os.Open(hyprConfig)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if strings.HasPrefix(line, "exec-once") {
						facts.HyprlandExecOnce = append(facts.HyprlandExecOnce, line)
						lower := strings.ToLower(line)
						if strings.Contains(lower, "gnome-keyring") || strings.Contains(lower, "keyring") {
							facts.AutostartGnomeKeyring = true
						}
						if strings.Contains(lower, "kwallet") {
							facts.AutostartKWallet = true
						}
					}
				}
				file.Close()

				if len(facts.HyprlandExecOnce) > 0 {
					facts.Evidence = append(facts.Evidence, protocol.Evidence{
						Source:        "platform",
						Kind:          "path",
						Subject:       hyprConfig,
						ObservedValue: fmt.Sprintf("hyprland_exec_once_entries=%d", len(facts.HyprlandExecOnce)),
						Timestamp:     time.Now().UTC().Format(time.RFC3339),
					})
				}
			}
		}
	}

	return facts, nil
}
