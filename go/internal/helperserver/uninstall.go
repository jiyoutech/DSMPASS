package helperserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

// Retained by the root administrator's preserve action. Package hooks can read
// this marker, but only the protected controller can change it.
const retainedHelperMarker = config.HelperInstallDir + "/retained"

func helperIsRetained() (bool, error) {
	_, err := os.Lstat(retainedHelperMarker)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, securefs.CheckRootPath(retainedHelperMarker)
}

func uninstallPrivilegedHelper(cfg config.HelperConfig, purge bool) error {
	if err := stopPrivilegedHelper(cfg); err != nil {
		return err
	}
	return withFileLock(filepath.Join(cfg.LockDir, "helper.instance.lock"), func() error {
		paths := []string{config.HelperSocketPath, filepath.Join(config.HelperRunDir, "helper.pid")}
		if purge {
			paths = append(paths, filepath.Dir(config.HelperConfigPath), config.HelperDataDir, helperSudoersPath, config.HelperInstallDir)
		}
		// Runtime lock inodes stay until reboot to serialize already queued
		// control processes. No executable, credentials or socket remain there.
		if err := cleanupHelperFiles(cfg.JournalDir, paths, checkHelperCleanupPath); err != nil || purge {
			return err
		}
		// Block ordinary control calls before narrowing sudo privileges. The root
		// gate also covers a power loss between the two atomic replacements.
		if err := securefs.WriteRootFile(retainedHelperMarker, []byte("retained\n"), 0644); err != nil {
			return err
		}
		if err := installHelperSudoersRule(retainedHelperRule(), "upgrade"); err != nil {
			return errors.Join(err, os.Remove(retainedHelperMarker))
		}
		return nil
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
