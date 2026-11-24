package analyze

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fplogin/internal/protocol"
)

// WalletFacts stores observed evidence about secret store and keyring configurations.
type WalletFacts struct {
	KWalletConfigPresent      bool
	KWalletEnabled            bool
	KWalletExplicitlyDisabled bool
	KWalletConfigPath         string
	KWalletDataPresent        bool
	KWalletAutoUnlock         bool

	GnomeKeyringDirExists  bool
	GnomeKeyringPresent    bool // true only when keyring files (not an empty directory) are observed
	GnomeKeyringDir        string
	GnomeKeyringHasLogin   bool
	GnomeKeyringHasDefault bool
	GnomeKeyringFileCount  int

	Evidence []protocol.Evidence
	Issues   []ProbeIssue
}

// ProbeWallets inspects user home configuration files for KWallet and GNOME Keyring
// in a strictly read-only, secret-free manner.
func ProbeWallets(userHome string) (*WalletFacts, error) {
	facts := &WalletFacts{
		Evidence: []protocol.Evidence{},
		Issues:   []ProbeIssue{},
	}

	if userHome == "" {
		return facts, nil
	}

	// 1. KWallet config probe: ~/.config/kwalletrc (non-secret INI preferences only)
	kwalletPath := filepath.Join(userHome, ".config", "kwalletrc")
	info, err := os.Stat(kwalletPath)
	if err != nil {
		if !os.IsNotExist(err) {
			ev := coreErrorEvidence("path", kwalletPath, "unreadable", err.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "wallet_read_error",
				Path:     kwalletPath,
				Message:  fmt.Sprintf("Could not stat KWallet configuration %q: %v", kwalletPath, err),
				Evidence: []protocol.Evidence{ev},
			})
		}
	} else if !info.IsDir() {
		facts.KWalletConfigPresent = true
		facts.KWalletConfigPath = kwalletPath
		facts.KWalletEnabled = true
		facts.KWalletAutoUnlock = true // default in KDE unless explicitly disabled

		file, openErr := os.Open(kwalletPath)
		if openErr != nil {
			ev := coreErrorEvidence("path", kwalletPath, "unreadable", openErr.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "wallet_read_error",
				Path:     kwalletPath,
				Message:  fmt.Sprintf("Could not read KWallet configuration %q: %v", kwalletPath, openErr),
				Evidence: []protocol.Evidence{ev},
			})
		} else {
			scanner := bufio.NewScanner(file)
			inWalletSection := false
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					inWalletSection = strings.EqualFold(line, "[Wallet]")
					continue
				}
				if inWalletSection {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						k := strings.TrimSpace(parts[0])
						v := strings.TrimSpace(parts[1])
						if strings.EqualFold(k, "Enabled") && strings.EqualFold(v, "false") {
							facts.KWalletEnabled = false
							facts.KWalletExplicitlyDisabled = true
						}
					}
				}
			}
			scanErr := scanner.Err()
			file.Close()
			if scanErr != nil {
				ev := coreErrorEvidence("path", kwalletPath, "scan error", scanErr.Error())
				facts.Issues = append(facts.Issues, ProbeIssue{
					Code:     "wallet_read_error",
					Path:     kwalletPath,
					Message:  fmt.Sprintf("Error scanning KWallet configuration %q: %v", kwalletPath, scanErr),
					Evidence: []protocol.Evidence{ev},
				})
			} else {
				facts.Evidence = append(facts.Evidence, coreEvidence(
					"path",
					kwalletPath,
					fmt.Sprintf("kwallet_enabled=%t", facts.KWalletEnabled),
				))
			}
		}
	}

	// 1b. KWallet data directory metadata check: ~/.local/share/kwalletd (filenames only; never read contents)
	kwalletDataDir := filepath.Join(userHome, ".local", "share", "kwalletd")
	if entries, readErr := os.ReadDir(kwalletDataDir); readErr != nil {
		if !os.IsNotExist(readErr) {
			ev := coreErrorEvidence("path", kwalletDataDir, "unreadable", readErr.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "wallet_read_error",
				Path:     kwalletDataDir,
				Message:  fmt.Sprintf("Could not inspect KWallet data directory %q: %v", kwalletDataDir, readErr),
				Evidence: []protocol.Evidence{ev},
			})
		}
	} else {
		walletFiles := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(e.Name())
			if strings.HasSuffix(lower, ".kwl") || strings.HasSuffix(lower, ".salt") {
				walletFiles++
			}
		}
		if walletFiles > 0 {
			facts.KWalletDataPresent = true
			if !facts.KWalletExplicitlyDisabled {
				facts.KWalletEnabled = true
			}
			facts.Evidence = append(facts.Evidence, coreEvidence(
				"path",
				kwalletDataDir,
				fmt.Sprintf("kwallet_files=%d", walletFiles),
			))
		}
	}

	// 2. GNOME Keyring probe: ~/.local/share/keyrings (filenames only; never read keyring contents)
	keyringDir := filepath.Join(userHome, ".local", "share", "keyrings")
	krInfo, krErr := os.Stat(keyringDir)
	if krErr != nil {
		if !os.IsNotExist(krErr) {
			ev := coreErrorEvidence("path", keyringDir, "unreadable", krErr.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "wallet_read_error",
				Path:     keyringDir,
				Message:  fmt.Sprintf("Could not stat keyring directory %q: %v", keyringDir, krErr),
				Evidence: []protocol.Evidence{ev},
			})
		}
	} else if krInfo.IsDir() {
		facts.GnomeKeyringDirExists = true
		facts.GnomeKeyringDir = keyringDir

		entries, readErr := os.ReadDir(keyringDir)
		if readErr != nil {
			ev := coreErrorEvidence("path", keyringDir, "unreadable", readErr.Error())
			facts.Issues = append(facts.Issues, ProbeIssue{
				Code:     "wallet_read_error",
				Path:     keyringDir,
				Message:  fmt.Sprintf("Could not read keyring directory %q: %v", keyringDir, readErr),
				Evidence: []protocol.Evidence{ev},
			})
		} else {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				lower := strings.ToLower(e.Name())
				switch {
				case lower == "login.keyring":
					facts.GnomeKeyringHasLogin = true
					facts.GnomeKeyringFileCount++
				case lower == "default":
					facts.GnomeKeyringHasDefault = true
					facts.GnomeKeyringFileCount++
				case strings.HasSuffix(lower, ".keyring"):
					facts.GnomeKeyringFileCount++
				}
			}
			facts.GnomeKeyringPresent = facts.GnomeKeyringFileCount > 0
			facts.Evidence = append(facts.Evidence, coreEvidence(
				"path",
				keyringDir,
				fmt.Sprintf("keyring_files=%d, has_login_keyring=%t, has_default=%t",
					facts.GnomeKeyringFileCount, facts.GnomeKeyringHasLogin, facts.GnomeKeyringHasDefault),
			))
		}
	}

	return facts, nil
}
