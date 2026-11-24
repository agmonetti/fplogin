// Package manifest manages the atomic publication, verification, and removal
// of the durable fplogin installation manifest (/var/lib/fplogin/manifest.json).
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

var (
	ErrManifestNotFound = errors.New("installation manifest not found")
	ErrCorruptManifest  = errors.New("installation manifest is corrupt or invalid")
	ErrModifiedFiles    = errors.New("installed files have been modified since installation; refusing uninstall without explicit approval")
	ErrSecretDetected   = errors.New("potential secret or sensitive credential rejected in manifest")
)

// FileMismatch records a file that is missing or has a modified checksum.
type FileMismatch struct {
	Path     string
	Kind     string // "missing" or "modified"
	Expected string
	Actual   string
}

// Publish writes the install manifest atomically to path, with file and directory fsync.
// It strictly validates the manifest schema and ensures no sensitive data is leaked.
func Publish(path string, m manifestv1.InstallManifest) error {
	if m.InstalledAt == "" {
		m.InstalledAt = time.Now().UTC().Format(time.RFC3339)
	}
	if m.SchemaVersion == "" {
		m.SchemaVersion = manifestv1.SchemaVersion
	}

	if err := m.Validate(); err != nil {
		return fmt.Errorf("validate manifest before publication: %w", err)
	}

	encoded, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	if err := checkNoSecrets(encoded); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create manifest directory %q: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp manifest file in %q: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod %q: %w", tmpPath, err)
	}

	if _, err := tmpFile.Write(encoded); err != nil {
		return fmt.Errorf("write %q: %w", tmpPath, err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync %q: %w", tmpPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %q -> %q: %w", tmpPath, path, err)
	}
	cleanedUp = true

	return syncDir(dir)
}

// Remove deletes the manifest file and fsyncs its parent directory so removal is durable.
func Remove(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrManifestNotFound
		}
		return fmt.Errorf("remove manifest %q: %w", path, err)
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Load reads and strictly validates the manifest from disk, refusing symlinks or non-regular files.
func Load(path string) (manifestv1.InstallManifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return manifestv1.InstallManifest{}, ErrManifestNotFound
		}
		return manifestv1.InstallManifest{}, fmt.Errorf("stat manifest %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return manifestv1.InstallManifest{}, fmt.Errorf("%w: manifest %q is not a regular file", ErrCorruptManifest, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return manifestv1.InstallManifest{}, fmt.Errorf("read manifest %q: %w", path, err)
	}

	m, err := manifestv1.DecodeInstallManifest(data)
	if err != nil {
		return manifestv1.InstallManifest{}, fmt.Errorf("%w: %v", ErrCorruptManifest, err)
	}

	return m, nil
}

// VerifyFiles checks the on-disk state of all files recorded in the manifest.
// It returns any files that are missing or whose SHA-256 does not match.
func VerifyFiles(m manifestv1.InstallManifest) ([]FileMismatch, error) {
	var mismatches []FileMismatch

	for _, file := range m.InstalledFiles {
		info, err := os.Lstat(file.Path)
		if err != nil {
			if os.IsNotExist(err) {
				mismatches = append(mismatches, FileMismatch{
					Path:     file.Path,
					Kind:     "missing",
					Expected: file.SHA256,
				})
				continue
			}
			return nil, fmt.Errorf("stat installed file %q: %w", file.Path, err)
		}
		if !info.Mode().IsRegular() {
			mismatches = append(mismatches, FileMismatch{
				Path:     file.Path,
				Kind:     "modified",
				Expected: file.SHA256,
				Actual:   "non-regular-file",
			})
			continue
		}

		data, err := os.ReadFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("read installed file %q: %w", file.Path, err)
		}

		sum := sha256.Sum256(data)
		actual := hex.EncodeToString(sum[:])
		if actual != file.SHA256 {
			mismatches = append(mismatches, FileMismatch{
				Path:     file.Path,
				Kind:     "modified",
				Expected: file.SHA256,
				Actual:   actual,
			})
		}
	}

	return mismatches, nil
}

func checkNoSecrets(data []byte) error {
	lower := bytes.ToLower(data)
	forbidden := []string{
		`"password"`,
		`"secret"`,
		`"fingerprint_template"`,
		`"raw_template"`,
		`"pam_authtok"`,
		`"pam_response"`,
	}
	for _, term := range forbidden {
		if bytes.Contains(lower, []byte(term)) {
			return fmt.Errorf("%w: matched forbidden term %s", ErrSecretDetected, term)
		}
	}
	return nil
}
