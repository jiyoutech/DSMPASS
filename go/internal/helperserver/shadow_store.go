package helperserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var (
	errShadowChanged          = errors.New("shadow file changed by another process")
	errShadowSafetyValidation = errors.New("shadow safety validation failed after atomic replace")
)

func rewriteShadowAtomically(path string, expected, updated []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular shadow file: %s", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return fmt.Errorf("refusing to replace shadow file with %d hard links", stat.Nlink)
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".dsmpass-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	tempClosed := false
	defer func() {
		if !tempClosed {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()

	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		if err := temp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	expectedXattrs, err := copyExtendedAttributes(path, tempPath)
	if err != nil {
		return fmt.Errorf("copy shadow extended attributes: %w", err)
	}
	if err := writeAll(temp, updated); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	tempClosed = true

	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return errShadowChanged
	}
	latestInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, latestInfo) {
		return errShadowChanged
	}
	if err := validateExtendedAttributes(path, expectedXattrs); err != nil {
		return fmt.Errorf("%w: extended attributes changed: %v", errShadowChanged, err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return err
	}

	verified, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: cannot read replaced shadow: %v", errShadowSafetyValidation, err)
	}
	if !bytes.Equal(verified, updated) {
		return fmt.Errorf("%w: content mismatch", errShadowSafetyValidation)
	}
	verifiedInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: cannot stat replaced shadow: %v", errShadowSafetyValidation, err)
	}
	if verifiedInfo.Mode().Perm() != info.Mode().Perm() {
		return fmt.Errorf("%w: permissions changed", errShadowSafetyValidation)
	}
	if before, ok := info.Sys().(*syscall.Stat_t); ok {
		if after, ok := verifiedInfo.Sys().(*syscall.Stat_t); ok && (before.Uid != after.Uid || before.Gid != after.Gid) {
			return fmt.Errorf("%w: ownership changed", errShadowSafetyValidation)
		}
	}
	if err := validateExtendedAttributes(path, expectedXattrs); err != nil {
		return fmt.Errorf("%w: extended attributes changed: %v", errShadowSafetyValidation, err)
	}
	return syncDirectory(dir)
}

func writeFileAtomically(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	tempClosed := false
	defer func() {
		if !tempClosed {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(perm); err != nil {
		return err
	}
	if err := writeAll(temp, data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	tempClosed = true
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
