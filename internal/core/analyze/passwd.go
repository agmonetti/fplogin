package analyze

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveUserHome resolves username's home directory from <root>/etc/passwd
// without accessing /etc/shadow or mutating the filesystem.
func ResolveUserHome(root, username string) (string, bool, error) {
	if username == "" {
		return "", false, nil
	}
	if root == "" {
		root = "/"
	}
	passwdPath := filepath.Join(root, "etc", "passwd")
	file, err := os.Open(passwdPath)
	if err != nil {
		return "", false, fmt.Errorf("open %q: %w", passwdPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 6 || fields[0] != username {
			continue
		}
		rawHome := filepath.Clean(fields[5])
		if !filepath.IsAbs(rawHome) {
			return "", false, fmt.Errorf("non-absolute home %q for user %q in %q", fields[5], username, passwdPath)
		}
		if filepath.Clean(root) == "/" {
			return rawHome, true, nil
		}
		joined := filepath.Join(root, strings.TrimPrefix(rawHome, string(filepath.Separator)))
		return joined, true, nil
	}
	if err := scanner.Err(); err != nil {
		return "", false, fmt.Errorf("scan %q: %w", passwdPath, err)
	}
	return "", false, nil
}
