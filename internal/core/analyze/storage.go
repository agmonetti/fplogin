package analyze

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fplogin/internal/protocol"
)

// StorageFacts captures observed facts about encrypted storage, pam_mount, and home directories.
type StorageFacts struct {
	SystemdHomedDetected bool
	HomedIdentityPath    string
	HomedDirChecked      bool
	HomedDirUnreadable   bool

	PamMountConfigPresent bool
	PamMountConfigPath    string
	PamMountVolumeCount   int
	PamMountHomeVolume    bool

	CrypttabPresent          bool
	CrypttabHasUserHome      bool
	CrypttabBootHome         bool
	CrypttabLoginCoupled     bool
	CrypttabPath             string
	CrypttabEntries          []string
	CrypttabBootEntries      []string
	CrypttabKeyscriptEntries []string

	Evidence []protocol.Evidence
	Issues   []ProbeIssue
}

// ProbeStorage checks for systemd-homed managed identities, pam_mount volumes,
// and LUKS crypttab entries without reading any secret key material.
func ProbeStorage(root, username string) (*StorageFacts, error) {
	if root == "" {
		root = "/"
	}

	facts := &StorageFacts{
		CrypttabEntries:          []string{},
		CrypttabBootEntries:      []string{},
		CrypttabKeyscriptEntries: []string{},
		Evidence:                 []protocol.Evidence{},
		Issues:                   []ProbeIssue{},
	}

	// 1. systemd-homed detection: /var/lib/systemd/home/<username>.identity
	if username != "" {
		homedDir := filepath.Join(root, "var", "lib", "systemd", "home")
		homedPath := filepath.Join(homedDir, username+".identity")
		info, err := os.Stat(homedPath)
		switch {
		case err == nil && !info.IsDir():
			facts.HomedDirChecked = true
			facts.SystemdHomedDetected = true
			facts.HomedIdentityPath = homedPath
			facts.Evidence = append(facts.Evidence, coreEvidence(
				"path",
				homedPath,
				"systemd-homed managed identity file present",
			))
		case err == nil:
			facts.HomedDirChecked = true
		case os.IsNotExist(err):
			facts.HomedDirChecked = true
		default:
			facts.HomedDirUnreadable = true
			ev := coreErrorEvidence("path", homedPath, "unreadable", err.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "storage_read_error",
				Path:     homedPath,
				Message:  fmt.Sprintf("Could not check systemd-homed identity %q: %v", homedPath, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
	}

	// 2. pam_mount structure check: /etc/security/pam_mount.conf.xml (read-only metadata only)
	pamMountPath := filepath.Join(root, "etc", "security", "pam_mount.conf.xml")
	if info, err := os.Stat(pamMountPath); err != nil {
		if !os.IsNotExist(err) {
			ev := coreErrorEvidence("path", pamMountPath, "unreadable", err.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "storage_read_error",
				Path:     pamMountPath,
				Message:  fmt.Sprintf("Could not stat pam_mount config %q: %v", pamMountPath, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
	} else if !info.IsDir() {
		facts.PamMountConfigPresent = true
		facts.PamMountConfigPath = pamMountPath
		file, openErr := os.Open(pamMountPath)
		if openErr != nil {
			ev := coreErrorEvidence("path", pamMountPath, "unreadable", openErr.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "storage_read_error",
				Path:     pamMountPath,
				Message:  fmt.Sprintf("Could not read pam_mount config %q: %v", pamMountPath, openErr),
				Evidence: []protocol.Evidence{ev},
			})
		} else {
			scanner := bufio.NewScanner(file)
			inComment := false
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.Contains(line, "<!--") {
					if !strings.Contains(line, "-->") {
						inComment = true
					}
					continue
				}
				if inComment {
					if strings.Contains(line, "-->") {
						inComment = false
					}
					continue
				}
				lower := strings.ToLower(line)
				if strings.Contains(lower, "<volume") {
					facts.PamMountVolumeCount++
					if strings.Contains(lower, `mountpoint="~"`) ||
						strings.Contains(lower, `mountpoint="/home`) ||
						strings.Contains(lower, "mountpoint='~'") ||
						strings.Contains(lower, "mountpoint='/home") {
						facts.PamMountHomeVolume = true
					}
				}
			}
			scanErr := scanner.Err()
			file.Close()
			if scanErr != nil {
				ev := coreErrorEvidence("path", pamMountPath, "scan error", scanErr.Error())
				facts.Issues = append(facts.Issues, ProbeIssue{
					Code:     "storage_read_error",
					Path:     pamMountPath,
					Message:  fmt.Sprintf("Error scanning pam_mount config %q: %v", pamMountPath, scanErr),
					Evidence: []protocol.Evidence{ev},
				})
			} else {
				facts.Evidence = append(facts.Evidence, coreEvidence(
					"path",
					pamMountPath,
					fmt.Sprintf("pam_mount_volumes=%d, home_volume=%t", facts.PamMountVolumeCount, facts.PamMountHomeVolume),
				))
			}
		}
	}

	// 3. crypttab inspection: /etc/crypttab
	crypttabPath := filepath.Join(root, "etc", "crypttab")
	if info, err := os.Stat(crypttabPath); err != nil {
		if !os.IsNotExist(err) {
			ev := coreErrorEvidence("path", crypttabPath, "unreadable", err.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "storage_read_error",
				Path:     crypttabPath,
				Message:  fmt.Sprintf("Could not stat %q: %v", crypttabPath, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
	} else if !info.IsDir() {
		facts.CrypttabPresent = true
		facts.CrypttabPath = crypttabPath
		file, openErr := os.Open(crypttabPath)
		if openErr != nil {
			ev := coreErrorEvidence("path", crypttabPath, "unreadable", openErr.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "storage_read_error",
				Path:     crypttabPath,
				Message:  fmt.Sprintf("Could not read %q (often root-only 0600): %v", crypttabPath, openErr),
				Evidence: []protocol.Evidence{ev},
			})
		} else {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				name := fields[0]
				lowerName := strings.ToLower(name)
				isUserHome := strings.Contains(lowerName, "home") || (username != "" && strings.Contains(lowerName, strings.ToLower(username)))
				options := ""
				if len(fields) >= 4 {
					options = strings.ToLower(fields[3])
				}
				hasKeyscript := strings.Contains(options, "keyscript=")
				if !isUserHome && !hasKeyscript {
					continue
				}
				// Sanitize entry summary: keep only target name and presence of keyscript/noauto, never keyfile paths or secrets.
				facts.CrypttabEntries = append(facts.CrypttabEntries, name)
				if isUserHome {
					facts.CrypttabHasUserHome = true
				}
				if hasKeyscript {
					facts.CrypttabLoginCoupled = true
					facts.CrypttabKeyscriptEntries = append(facts.CrypttabKeyscriptEntries, name)
				} else if isUserHome {
					facts.CrypttabBootHome = true
					facts.CrypttabBootEntries = append(facts.CrypttabBootEntries, name)
				}
			}
			scanErr := scanner.Err()
			file.Close()
			if scanErr != nil {
				ev := coreErrorEvidence("path", crypttabPath, "scan error", scanErr.Error())
				facts.Issues = append(facts.Issues, ProbeIssue{
					Code:     "storage_read_error",
					Path:     crypttabPath,
					Message:  fmt.Sprintf("Error scanning %q: %v", crypttabPath, scanErr),
					Evidence: []protocol.Evidence{ev},
				})
			} else if len(facts.CrypttabEntries) > 0 {
				facts.Evidence = append(facts.Evidence, coreEvidence(
					"path",
					crypttabPath,
					fmt.Sprintf("crypttab_home_boot_entries=%d, crypttab_keyscript_entries=%d",
						len(facts.CrypttabBootEntries), len(facts.CrypttabKeyscriptEntries)),
				))
			}
		}
	}

	return facts, nil
}
