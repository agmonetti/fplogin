// Package manifest manages the atomic publication, verification, and
// uninstallation of the durable fplogin installation manifest (/var/lib/fplogin/manifest.json).
package manifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

// PlatformApplier abstracts the execution of platform-specific operations.
type PlatformApplier interface {
	ApplyOperation(ctx context.Context, op protocol.Operation) (manifestv1.OperationReceipt, error)
}

var (
	ErrManifestNotFound = errors.New("installation manifest not found")
	ErrCorruptManifest  = errors.New("installation manifest is corrupt or invalid")
	ErrModifiedFiles    = errors.New("installed files have been modified since installation; refusing uninstall without force")
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

	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Load reads and strictly validates the manifest from disk.
func Load(path string) (manifestv1.InstallManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return manifestv1.InstallManifest{}, ErrManifestNotFound
		}
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
		data, err := os.ReadFile(file.Path)
		if err != nil {
			if os.IsNotExist(err) {
				mismatches = append(mismatches, FileMismatch{
					Path:     file.Path,
					Kind:     "missing",
					Expected: file.SHA256,
				})
				continue
			}
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

// UninstallConfig holds parameters for the uninstaller.
type UninstallConfig struct {
	ManifestPath string
	Force        bool // Allow uninstall even if installed files were modified
	Platform     PlatformApplier
}

// Uninstall executes a safe, checksum-aware removal of fplogin components
// based on the installed manifest.
func Uninstall(ctx context.Context, cfg UninstallConfig) error {
	root := filepath.Dir(cfg.ManifestPath)
	if os.Getuid() == 0 || os.Geteuid() == 0 || root == "/var/lib/fplogin" {
		return errors.New("system uninstall requires transactional manifest support")
	}
	if filepath.Join(root, "manifest.json") != cfg.ManifestPath || filepath.Base(cfg.ManifestPath) != "manifest.json" {
		return ErrCorruptManifest
	}
	lock, err := transaction.AcquireLock(root)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := transaction.CheckNoUnresolved(filepath.Join(root, "transactions")); err != nil {
		return err
	}
	m, err := Load(cfg.ManifestPath)
	if err != nil {
		return err
	}

	// Step 1: Verify file checksums
	mismatches, err := VerifyFiles(m)
	if err != nil {
		return fmt.Errorf("verify installed files: %w", err)
	}

	var modified []FileMismatch
	for _, mm := range mismatches {
		if mm.Kind == "modified" {
			modified = append(modified, mm)
		}
	}

	if len(modified) > 0 && !cfg.Force {
		return fmt.Errorf("%w: %d modified files detected: %v", ErrModifiedFiles, len(modified), modified)
	}

	// Step 2: Remove installed files
	for _, file := range m.InstalledFiles {
		if err := os.Remove(file.Path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove installed file %q: %w", file.Path, err)
		}
	}

	// Step 3: Remove owned packages via platform provider if configured
	if cfg.Platform != nil {
		for _, pkg := range m.InstalledPackages {
			op := protocol.Operation{
				OperationID:    "uninstall-pkg-" + pkg.PackageReference,
				Kind:           protocol.RemoveOwnedPackage,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"installed": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(fmt.Sprintf(`{"package_reference":%q}`, pkg.PackageReference)),
				Compensation:   json.RawMessage(`{"kind":"none"}`),
			}
			_, _ = cfg.Platform.ApplyOperation(ctx, op)
		}

		// Step 4: Restore previous DM / services
		if m.PreviousDMState.ServiceName != "" {
			restoreOp := protocol.Operation{
				OperationID:    "restore-prev-dm",
				Kind:           protocol.RestoreServiceState,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{},
				ExpectedAfter:  protocol.Object{},
				Parameters: json.RawMessage(fmt.Sprintf(`{"service_reference":%q,"enabled":%q,"active":%q}`,
					m.PreviousDMState.ServiceName, m.PreviousDMState.Enabled, m.PreviousDMState.Active)),
				Compensation: json.RawMessage(`{"kind":"none"}`),
			}
			_, _ = cfg.Platform.ApplyOperation(ctx, restoreOp)
		}
	}

	// Step 5: Remove manifest file itself
	if err := os.Remove(cfg.ManifestPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove manifest file %q: %w", cfg.ManifestPath, err)
	}

	return nil
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
