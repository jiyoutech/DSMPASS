package helperserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

var errShadowLockUnsupported = errors.New("DSM account write lock is unavailable; temporary shadow writes are disabled")

// DSM account writers must use this same flock protocol. File availability
// alone does not prove that every DSM version or third-party writer does so.
const dsmAccountLockPath = "/run/synosdk/lock/lock_pw"

func shadowSystemLockPath(cfg config.HelperConfig) (string, error) {
	path, err := filepath.EvalSymlinks(cfg.ShadowPath)
	if err != nil {
		return "", err
	}
	if path != "/etc/shadow" {
		// Isolated files used by unit tests. Production always uses /etc/shadow.
		return cfg.ShadowLockPath + ".system", nil
	}
	if runtime.GOOS != "linux" {
		return "", errShadowLockUnsupported
	}
	f, err := openAccountLockFile(dsmAccountLockPath, false)
	if err != nil {
		return "", errors.Join(errShadowLockUnsupported, err)
	}
	defer f.Close()
	return dsmAccountLockPath, nil
}

func openLockFile(path string) (*os.File, error) {
	// Never create DSM's lock, including if it disappears between the health
	// check and acquisition. A private replacement would not coordinate writers.
	return openAccountLockFile(path, path != dsmAccountLockPath)
}

func openAccountLockFile(path string, allowCreate bool) (*os.File, error) {
	if path == "" {
		return nil, errors.New("account lock path is empty")
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if allowCreate {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		flags |= syscall.O_CREAT
	}
	fd, err := syscall.Open(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open account lock %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 {
			err = errors.New("account lock must be a regular file with one link")
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
