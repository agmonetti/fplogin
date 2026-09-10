// Package descriptortrust validates descriptor files and their referenced
// executable and asset root before any discovered process is started.
package descriptortrust

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"fplogin/internal/protocol"
)

type Policy struct {
	OwnerUID uint32
}

type TrustedFile struct {
	DescriptorPath string
	ExecutablePath string
	AssetRootPath  string
	DescriptorData []byte
	SHA256         string
}

func Read(policy Policy, descriptorPath string, maxBytes int64) (TrustedFile, error) {
	absoluteDescriptor, err := filepath.Abs(descriptorPath)
	if err != nil {
		return TrustedFile{}, err
	}
	absoluteDescriptor = filepath.Clean(absoluteDescriptor)
	if err := validatePath(absoluteDescriptor, policy.OwnerUID, false, false); err != nil {
		return TrustedFile{}, fmt.Errorf("descriptor: %w", err)
	}
	if err := validatePath(filepath.Dir(absoluteDescriptor), policy.OwnerUID, true, false); err != nil {
		return TrustedFile{}, fmt.Errorf("descriptor directory: %w", err)
	}
	file, err := os.Open(absoluteDescriptor)
	if err != nil {
		return TrustedFile{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return TrustedFile{}, err
	}
	if int64(len(data)) > maxBytes {
		return TrustedFile{}, fmt.Errorf("descriptor exceeds %d bytes", maxBytes)
	}
	digest := sha256.Sum256(data)
	return TrustedFile{
		DescriptorPath: absoluteDescriptor,
		DescriptorData: data,
		SHA256:         fmt.Sprintf("%x", digest),
	}, nil
}

func ValidateReferences(policy Policy, trusted TrustedFile, executable, assetRoot string) (TrustedFile, error) {
	root := filepath.Dir(trusted.DescriptorPath)
	executablePath, err := resolveLocal(root, executable)
	if err != nil {
		return TrustedFile{}, fmt.Errorf("executable: %w", err)
	}
	assetRootPath, err := resolveLocal(root, assetRoot)
	if err != nil {
		return TrustedFile{}, fmt.Errorf("asset root: %w", err)
	}
	if err := validateDirectoryChain(root, filepath.Dir(executablePath), policy.OwnerUID); err != nil {
		return TrustedFile{}, fmt.Errorf("executable directory: %w", err)
	}
	if err := validateDirectoryChain(root, filepath.Dir(assetRootPath), policy.OwnerUID); err != nil {
		return TrustedFile{}, fmt.Errorf("asset directory: %w", err)
	}
	if err := validatePath(executablePath, policy.OwnerUID, false, true); err != nil {
		return TrustedFile{}, fmt.Errorf("executable: %w", err)
	}
	if err := validatePath(assetRootPath, policy.OwnerUID, true, false); err != nil {
		return TrustedFile{}, fmt.Errorf("asset root: %w", err)
	}
	trusted.ExecutablePath = executablePath
	trusted.AssetRootPath = assetRootPath
	return trusted, nil
}

func resolveLocal(root, relative string) (string, error) {
	if err := protocol.ValidRelativePath(relative); err != nil {
		return "", err
	}
	candidate := filepath.Join(root, relative)
	rel, err := filepath.Rel(root, candidate)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errors.New("path escapes descriptor directory")
	}
	return candidate, nil
}

func validateDirectoryChain(root, directory string, owner uint32) error {
	current := directory
	for {
		if err := validatePath(current, owner, true, false); err != nil {
			return err
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("directory chain escapes descriptor directory")
		}
		current = parent
	}
}

func validatePath(path string, owner uint32, wantDirectory, wantExecutable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return errors.New("symbolic links are not trusted")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if filepath.Clean(resolved) != path {
		return errors.New("path is not canonical")
	}
	if wantDirectory {
		if !info.IsDir() {
			return errors.New("path is not a directory")
		}
	} else if !info.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("filesystem ownership is unavailable")
	}
	if stat.Uid != owner {
		return fmt.Errorf("owner uid %d does not match trusted uid %d", stat.Uid, owner)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("path is group/world writable: %s", info.Mode().Perm())
	}
	if wantExecutable && info.Mode().Perm()&0o111 == 0 {
		return errors.New("file is not executable")
	}
	return nil
}
