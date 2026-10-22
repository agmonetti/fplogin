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

// StorageFacts captures observed facts about encrypted storage and home directories.
type StorageFacts struct {
	SystemdHomedDetected bool
	HomedIdentityPath    string

	CrypttabHasUserHome bool
	CrypttabPath        string
	CrypttabEntries     []string

	Evidence []protocol.Evidence
}

// ProbeStorage checks for systemd-homed managed identities and LUKS crypttab entries.
func ProbeStorage(root, username string) (*StorageFacts, error) {
	if root == "" {
		root = "/"
	}

	facts := &StorageFacts{
		CrypttabEntries: []string{},
		Evidence:        []protocol.Evidence{},
	}

	// 1. systemd-homed detection: /var/lib/systemd/home/<username>.identity
	if username != "" {
		homedPath := filepath.Join(root, "var", "lib", "systemd", "home", username+".identity")
		if info, err := os.Stat(homedPath); err == nil && !info.IsDir() {
			facts.SystemdHomedDetected = true
			facts.HomedIdentityPath = homedPath
			facts.Evidence = append(facts.Evidence, protocol.Evidence{
				Source:        "platform",
				Kind:          "path",
				Subject:       homedPath,
				ObservedValue: "systemd-homed managed identity file present",
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	// 2. crypttab inspection: /etc/crypttab
	crypttabPath := filepath.Join(root, "etc", "crypttab")
	if info, err := os.Stat(crypttabPath); err == nil && !info.IsDir() {
		facts.CrypttabPath = crypttabPath
		file, err := os.Open(crypttabPath)
		if err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					name := fields[0]
					if strings.Contains(strings.ToLower(name), "home") || (username != "" && strings.Contains(name, username)) {
						facts.CrypttabHasUserHome = true
						facts.CrypttabEntries = append(facts.CrypttabEntries, line)
					}
				}
			}
			file.Close()

			if len(facts.CrypttabEntries) > 0 {
				facts.Evidence = append(facts.Evidence, protocol.Evidence{
					Source:        "platform",
					Kind:          "path",
					Subject:       crypttabPath,
					ObservedValue: fmt.Sprintf("crypttab_home_entries=%d", len(facts.CrypttabEntries)),
					Timestamp:     time.Now().UTC().Format(time.RFC3339),
				})
			}
		}
	}

	return facts, nil
}
