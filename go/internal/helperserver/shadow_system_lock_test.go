package helperserver

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestExistingAccountLockDoesNotCreateMissingPaths(t *testing.T) {
	for _, name := range []string{"lock", "missing-parent/lock"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			file, err := openAccountLockFile(path, false)
			if err == nil {
				file.Close()
				t.Fatal("missing system lock was accepted")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("system lock check created a file or directory: %v", err)
			}
		})
	}
}

func TestExistingAccountLockPreservesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, []byte("existing DSM lock"), 0444); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openAccountLockFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	// A separate descriptor must observe the same lock even when the lock file
	// is read-only; opening it must not replace its inode or permissions.
	other, err := openAccountLockFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
		t.Fatalf("second writer did not observe held lock: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatalf("existing lock identity or permissions changed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing DSM lock" {
		t.Fatalf("existing lock contents changed: %v", err)
	}
}

func TestExistingAccountLockRejectsInvalidFiles(t *testing.T) {
	for _, kind := range []string{"empty", "directory", "symlink", "dangling symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "lock")
			target := filepath.Join(dir, "target")
			var err error
			switch kind {
			case "empty":
				path = ""
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink", "hardlink":
				if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
			case "dangling symlink":
				err = os.Symlink(target, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			file, err := openAccountLockFile(path, false)
			if err == nil {
				file.Close()
				t.Fatal("invalid system lock was accepted")
			}
		})
	}
}
