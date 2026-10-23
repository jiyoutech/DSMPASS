package helperserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

var errShadowLockUnsupported = errors.New("DSM account lock compatibility is unverified; temporary shadow login is disabled")

// Verified on DSM 7.3-81180 amd64 with synouser add/setpw/modify/del and
// SYNO.Core.User.set. Do not extend this profile without the real DSM lock test.
var verifiedDSMAccountLibraries = map[string]string{
	"/etc.defaults/VERSION":                       "ac225ae9acd15b293c51d385f3fe543db3192d4131f299a4d67133aa4227ca74",
	"/usr/syno/synoman/webapi/SYNO.Core.User.lib": "e29a8c0fff1d3dc7ae3e080cc5df3b8d9bfa7aea4c8ef63406384e8e2e9e3af8",
	"/usr/lib/libsynocore.so.7":                   "1b34bb97f6ba8a3a6b5a0d9d49a7594a41460a631bb21f212f5e74fafa89d073",
	"/usr/lib/libsynolocalaccount.so.7":           "1b0d1bf2dccb03caa63c3aa5b89d455e00feb4850561e192203bb07273e1137e",
	"/usr/lib/libsynosdk.so.7":                    "931e21adcbac79d54d4f22ce76803fc22dd03adf987e62e502096122408e81be",
	"/usr/syno/sbin/synouser":                     "ee2880c96ea3d673e937efb43a18844bd4cfb2294ffbebf9a1a8d99b2f5db0a4",
}

func shadowSystemLockPath(cfg config.HelperConfig) (string, error) {
	path, err := filepath.EvalSymlinks(cfg.ShadowPath)
	if err != nil {
		return "", err
	}
	if path != "/etc/shadow" {
		// Isolated files used by unit tests. Production always uses /etc/shadow.
		return cfg.ShadowLockPath + ".system", nil
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return "", errShadowLockUnsupported
	}
	for path, expected := range verifiedDSMAccountLibraries {
		if err := verifyAccountLibrary(path, expected); err != nil {
			return "", errors.Join(errShadowLockUnsupported, err)
		}
	}
	return "/run/synosdk/lock/lock_pw", nil
}

func verifyAccountLibrary(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("unverified account component: %s", path)
	}
	return nil
}

func openLockFile(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("account lock path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
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
