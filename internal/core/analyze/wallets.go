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

// WalletFacts stores observed evidence about secret store and keyring configurations.
type WalletFacts struct {
	KWalletEnabled    bool
	KWalletConfigPath string
	KWalletAutoUnlock bool

	GnomeKeyringPresent  bool
	GnomeKeyringDir      string
	GnomeKeyringHasLogin bool

	Evidence []protocol.Evidence
}

// ProbeWallets inspects user home configuration files for KWallet and GNOME Keyring
// in a strictly read-only, secret-free manner.
func ProbeWallets(userHome string) (*WalletFacts, error) {
	facts := &WalletFacts{
		Evidence: []protocol.Evidence{},
	}

	if userHome == "" {
		return facts, nil
	}

	// 1. KWallet probe: ~/.config/kwalletrc
	kwalletPath := filepath.Join(userHome, ".config", "kwalletrc")
	if info, err := os.Stat(kwalletPath); err == nil && !info.IsDir() {
		facts.KWalletConfigPath = kwalletPath
		facts.KWalletEnabled = true
		facts.KWalletAutoUnlock = true // default in KDE unless disabled

		file, err := os.Open(kwalletPath)
		if err == nil {
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
						}
					}
				}
			}
			file.Close()

			facts.Evidence = append(facts.Evidence, protocol.Evidence{
				Source:        "platform",
				Kind:          "path",
				Subject:       kwalletPath,
				ObservedValue: fmt.Sprintf("kwallet_enabled=%t", facts.KWalletEnabled),
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			})
		}
	}

	// 2. GNOME Keyring probe: ~/.local/share/keyrings
	keyringDir := filepath.Join(userHome, ".local", "share", "keyrings")
	if info, err := os.Stat(keyringDir); err == nil && info.IsDir() {
		facts.GnomeKeyringDir = keyringDir
		facts.GnomeKeyringPresent = true

		entries, _ := os.ReadDir(keyringDir)
		for _, e := range entries {
			if strings.EqualFold(e.Name(), "login.keyring") {
				facts.GnomeKeyringHasLogin = true
			}
		}

		facts.Evidence = append(facts.Evidence, protocol.Evidence{
			Source:        "platform",
			Kind:          "path",
			Subject:       keyringDir,
			ObservedValue: fmt.Sprintf("gnome_keyring_present=true, has_login_keyring=%t", facts.GnomeKeyringHasLogin),
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
		})
	}

	return facts, nil
}
