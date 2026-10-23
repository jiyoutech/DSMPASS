// Package securefs protects files used by the privileged Helper from replacement
// by the package account. Protected paths must not contain symbolic links.
package securefs

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func CheckRootPath(path string) error {
	return checkPath(path, "/", 0)
}

func checkPath(path, boundary string, owner int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("protected path must be absolute and clean: %s", path)
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != owner || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("protected path has unsafe ownership, permissions or symlink: %s", current)
		}
		if current != path && !info.IsDir() {
			return fmt.Errorf("protected parent is not a directory: %s", current)
		}
		if current == boundary {
			return nil
		}
		if current == "/" {
			return fmt.Errorf("protected path is outside boundary: %s", path)
		}
	}
}

func EnsureRootDir(path string, mode os.FileMode) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		parent := filepath.Dir(path)
		if _, err := os.Lstat(parent); os.IsNotExist(err) {
			if err := EnsureRootDir(parent, 0755); err != nil {
				return err
			}
		} else if err := CheckRootPath(parent); err != nil {
			return err
		}
		if err := os.Mkdir(path, mode); err != nil && !os.IsExist(err) {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := CheckRootPath(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("protected path is not a directory: %s", path)
	}
	return os.Chmod(path, mode)
}

// WriteRootFile uses a new inode in a protected directory, never truncating a
// path that could be a link to another root-owned file.
func WriteRootFile(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	if err := CheckRootPath(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := CheckRootPath(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(parent, ".dsmpass-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
