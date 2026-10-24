package helperserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

func uninstallPrivilegedHelper(cfg config.HelperConfig, purge bool) error {
	if err := stopPrivilegedHelper(cfg); err != nil {
		return err
	}
	return withFileLock(filepath.Join(cfg.LockDir, "helper.instance.lock"), func() error {
		paths := []string{config.HelperSocketPath, filepath.Join(config.HelperRunDir, "helper.pid")}
		if purge {
			paths = append(paths, filepath.Dir(config.HelperConfigPath), config.HelperDataDir)
		}
		paths = append(paths, helperSudoersPath, config.HelperInstallDir)
		// Runtime lock inodes stay until reboot to serialize already queued
		// control processes. No executable, credentials or socket remain there.
		return cleanupHelperFiles(cfg.JournalDir, paths, checkHelperCleanupPath)
	})
}

func checkHelperCleanupPath(path string) error {
	if path != config.HelperSocketPath {
		return securefs.CheckRootPath(path)
	}
	// The socket is intentionally group-writable; its parent is root-controlled
	// and prevents the package account from replacing the directory entry.
	if err := securefs.CheckRootPath(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to remove non-socket Helper endpoint")
	}
	return nil
}

func cleanupHelperFiles(journalDir string, paths []string, check func(string) error) error {
	if err := assertNoPendingJournals(journalDir); err != nil {
		return fmt.Errorf("uninstall cancelled; keep password recovery files: %w", err)
	}
	// Validate every target before deleting anything, never follow an unexpected
	// symlink or delete a package-controlled path with root privileges.
	for _, path := range paths {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := check(path); err != nil {
			return err
		}
	}
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove protected Helper path %s: %w", path, err)
		}
	}
	return nil
}
