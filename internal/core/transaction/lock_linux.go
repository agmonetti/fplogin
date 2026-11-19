package transaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrTransactionBusy       = errors.New("another transaction holds the state lock")
	ErrUnresolvedTransaction = errors.New("transaction needs recovery")
)

// CheckNoUnresolved is called only while holding the state lock.
func CheckNoUnresolved(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		if info.Mode() != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
			return fmt.Errorf("%w: unsafe journal %q", ErrUnresolvedTransaction, entry.Name())
		}
		j, err := Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrUnresolvedTransaction, entry.Name(), err)
		}
		if state := j.State(); state != "completed" && state != "rolled_back" {
			return fmt.Errorf("%w: journal %q is %s", ErrUnresolvedTransaction, entry.Name(), state)
		}
	}
	return nil
}

// AcquireLock prepares the private state root and transactions directory, and
// takes the shared lock for install, uninstall and recovery. The absolute root
// must be under an existing trusted parent (e.g. /var/lib in production).
// Keep the returned file open for the entire transaction; never remove it.
func AcquireLock(root string) (*os.File, error) {
	return acquireLock(root, (*os.File).Sync)
}

func acquireLock(root string, syncDir func(*os.File) error) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, fmt.Errorf("invalid transaction state root %q", root)
	}
	parent, err := os.Open(filepath.Dir(root))
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	state, err := openPrivateDir(parent, filepath.Base(root))
	if err != nil {
		return nil, err
	}
	defer state.Close()

	fd, err := syscall.Openat(int(state.Fd()), "transaction.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open transaction lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), "transaction.lock")
	ok := false
	defer func() {
		if !ok {
			_ = lock.Close()
		}
	}()
	if err := checkPrivate(lock, syscall.S_IFREG, 0o600); err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrTransactionBusy
		}
		return nil, fmt.Errorf("lock transactions: %w", err)
	}

	journals, err := openPrivateDir(state, "transactions")
	if err != nil {
		return nil, err
	}
	defer journals.Close()
	// Sync even preexisting names: a previous attempt may have failed after mkdir.
	for _, dir := range []*os.File{journals, state, parent} {
		if err := syncDir(dir); err != nil {
			return nil, fmt.Errorf("sync transaction directory %q: %w", dir.Name(), err)
		}
	}
	ok = true
	return lock, nil
}

func openPrivateDir(parent *os.File, name string) (*os.File, error) {
	if err := syscall.Mkdirat(int(parent.Fd()), name, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("create private directory %q: %w", name, err)
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open private directory %q: %w", name, err)
	}
	dir := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	if err := checkPrivate(dir, syscall.S_IFDIR, 0o700); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

func checkPrivate(file *os.File, kind, perm uint32) error {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Uid != uint32(os.Geteuid()) || uint32(stat.Mode) != kind|perm || (kind == syscall.S_IFREG && stat.Nlink != 1) {
		return fmt.Errorf("unsafe transaction state entry %q", file.Name())
	}
	return nil
}
