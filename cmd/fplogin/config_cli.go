package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	defaultConfigDropIn = "/etc/sddm.conf.d/90-fplogin.conf"
	systemSDDMConf      = "/etc/sddm.conf"
)

type persistentConfig struct {
	AutoLegacy bool
	Timeout    int
	Theme      string // "preserve" means no [Theme] override
}

func defaultPersistentConfig() persistentConfig {
	return persistentConfig{
		AutoLegacy: true,
		Timeout:    30,
		Theme:      "preserve",
	}
}

func runConfig(args []string) {
	if len(args) == 0 || args[0] == "show" {
		subArgs := args
		if len(args) > 0 && args[0] == "show" {
			subArgs = args[1:]
		}
		runConfigShow(subArgs)
		return
	}
	switch args[0] {
	case "set":
		runConfigSet(args[1:])
	case "help", "-h", "--help":
		printConfigUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown config action %q\n\n", args[0])
		printConfigUsage()
		os.Exit(2)
	}
}

func printConfigUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  fplogin config [show] [--path FILE]
  sudo fplogin config set [--auto-legacy true|false] [--timeout 5..120] [--theme preserve|fplogin|<name>]

Persistent settings are stored in %s and survive reboots and package upgrades.
`, defaultConfigDropIn)
}

func runConfigShow(args []string) {
	fs := flag.NewFlagSet("config show", flag.ExitOnError)
	path := fs.String("path", defaultConfigDropIn, "path to SDDM fplogin drop-in")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		printConfigUsage()
		os.Exit(2)
	}

	cfg, exists, err := loadPersistentConfig(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fplogin Persistent Configuration (%s)\n", *path)
	if !exists {
		fmt.Printf("  File Status:                   absent (showing defaults)\n")
	} else {
		fmt.Printf("  File Status:                   present\n")
	}
	fmt.Printf("  auto_fingerprint_legacy_themes: %t\n", cfg.AutoLegacy)
	fmt.Printf("  fingerprint_timeout_seconds:    %d\n", cfg.Timeout)
	fmt.Printf("  theme:                          %s\n", cfg.Theme)

	if cfg.Theme != "preserve" {
		if override := detectMainSDDMTheme(systemSDDMConf); override != "" && override != cfg.Theme {
			fmt.Printf("  Note: %s sets Current=%s, which overrides drop-ins in /etc/sddm.conf.d/.\n", systemSDDMConf, override)
		}
	}
}

func runConfigSet(args []string) {
	fs := flag.NewFlagSet("config set", flag.ExitOnError)
	path := fs.String("path", defaultConfigDropIn, "path to SDDM fplogin drop-in")
	autoLegacy := fs.String("auto-legacy", "", "auto-start fingerprint on untouched Qt5/Qt6 themes (true|false)")
	timeout := fs.Int("timeout", 0, "fingerprint scan deadline in seconds (5..120)")
	theme := fs.String("theme", "", "theme mode: preserve (keep existing theme), fplogin, or installed theme name")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || (*autoLegacy == "" && *timeout == 0 && *theme == "") {
		printConfigUsage()
		os.Exit(2)
	}

	if *path == defaultConfigDropIn && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Error: modifying system configuration requires root privileges (use sudo)")
		os.Exit(1)
	}

	cfg, _, err := loadPersistentConfig(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if *autoLegacy != "" {
		v, err := strconv.ParseBool(*autoLegacy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid --auto-legacy value %q (want true or false)\n", *autoLegacy)
			os.Exit(2)
		}
		cfg.AutoLegacy = v
	}
	if *timeout != 0 {
		if *timeout < 5 || *timeout > 120 {
			fmt.Fprintf(os.Stderr, "Error: --timeout must be between 5 and 120 seconds (got %d)\n", *timeout)
			os.Exit(2)
		}
		cfg.Timeout = *timeout
	}
	if *theme != "" {
		if err := validateThemeName(*theme); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		cfg.Theme = *theme
	}

	if err := savePersistentConfig(*path, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Saved persistent configuration to %s\n", *path)
	fmt.Printf("  auto_fingerprint_legacy_themes: %t\n", cfg.AutoLegacy)
	fmt.Printf("  fingerprint_timeout_seconds:    %d\n", cfg.Timeout)
	fmt.Printf("  theme:                          %s\n", cfg.Theme)
	if cfg.Theme != "preserve" {
		if override := detectMainSDDMTheme(systemSDDMConf); override != "" && override != cfg.Theme {
			fmt.Printf("  Note: %s sets Current=%s, which overrides /etc/sddm.conf.d/ drop-ins.\n", systemSDDMConf, override)
		}
	}
}

func validateThemeName(name string) error {
	if name == "preserve" {
		return nil
	}
	if name == "" || len(name) > 128 || name == "." || name == ".." {
		return fmt.Errorf("invalid theme name %q", name)
	}
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if !ok {
			return fmt.Errorf("invalid character in theme name %q", name)
		}
	}
	return nil
}

func loadPersistentConfig(path string) (persistentConfig, bool, error) {
	cfg := defaultPersistentConfig()
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, false, nil
		}
		return cfg, false, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return cfg, false, fmt.Errorf("%s must be a regular file", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return cfg, false, fmt.Errorf("read %s: %w", path, err)
	}

	section := ""
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch section {
		case "General":
			if k == "AutoFingerprintForLegacyThemes" {
				if b, err := strconv.ParseBool(v); err == nil {
					cfg.AutoLegacy = b
				}
			} else if k == "FingerprintAuthTimeout" {
				if n, err := strconv.Atoi(v); err == nil && n >= 5 && n <= 120 {
					cfg.Timeout = n
				}
			}
		case "Theme":
			if k == "Current" && v != "" && validateThemeName(v) == nil {
				cfg.Theme = v
			}
		}
	}
	return cfg, true, nil
}

func formatPersistentConfig(cfg persistentConfig) string {
	var b strings.Builder
	b.WriteString("[General]\n")
	fmt.Fprintf(&b, "AutoFingerprintForLegacyThemes=%t\n", cfg.AutoLegacy)
	if cfg.Timeout != 30 {
		fmt.Fprintf(&b, "FingerprintAuthTimeout=%d\n", cfg.Timeout)
	}
	if cfg.Theme != "" && cfg.Theme != "preserve" {
		b.WriteString("\n[Theme]\n")
		fmt.Fprintf(&b, "Current=%s\n", cfg.Theme)
	}
	return b.String()
}

func savePersistentConfig(path string, cfg persistentConfig) error {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(dir); err != nil {
		return fmt.Errorf("config directory %s: %w", dir, err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("config directory %s must be a real directory", dir)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file (symlinks rejected)", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".90-fplogin.conf.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.WriteString(formatPersistentConfig(cfg)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func detectMainSDDMTheme(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return ""
	}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section == "Theme" {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "Current" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}
