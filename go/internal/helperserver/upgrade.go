package helperserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperupdate"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

func upgradePrivilegedHelper(cfg config.HelperConfig) error {
	currentEpoch, err := strconv.ParseInt(buildinfo.BuildEpoch, 10, 64)
	if err != nil || currentEpoch < 0 {
		return errors.New("installed Helper has invalid build metadata")
	}
	payload, err := helperupdate.Load(installedPackageDir, runtime.GOARCH, currentEpoch)
	if err != nil {
		return fmt.Errorf("automatic Helper update refused: %w; unsigned builds require explicit root installation", err)
	}
	previousBinary, err := helperupdate.ReadFile(config.HelperBinaryPath, 100<<20)
	if err != nil {
		return err
	}
	previousController, err := helperupdate.ReadFile(config.HelperControlPath, 64<<10)
	if err != nil {
		return err
	}
	if payload.Manifest.BuildEpoch == currentEpoch {
		if payload.Manifest.Helper != helperupdate.Digest(previousBinary) || payload.Manifest.Controller != helperupdate.Digest(previousController) {
			return errors.New("same-build Helper payload differs from installed files; explicit root installation required")
		}
		return startPrivilegedHelper(cfg)
	}
	// Signature, architecture, replay protection and both payload hashes have
	// been checked before stopping the healthy instance or writing root files.
	if err := stopPrivilegedHelper(cfg); err != nil {
		return err
	}
	settingsData, err := os.ReadFile(config.HelperConfigPath)
	if err != nil {
		return errors.Join(err, startPrivilegedHelper(cfg))
	}
	previousRule, err := os.ReadFile(helperSudoersPath)
	if err != nil {
		return errors.Join(err, startPrivilegedHelper(cfg))
	}
	previous := []protectedHelperFile{
		{config.HelperBinaryPath, previousBinary, 0755},
		{config.HelperControlPath, previousController, 0755},
		{config.HelperConfigPath, settingsData, 0600},
		{helperSudoersPath, previousRule, 0440},
	}
	backupDir := filepath.Join(config.HelperDataDir, "previous-helper")
	if err := securefs.EnsureRootDir(backupDir, 0700); err != nil {
		return errors.Join(err, startPrivilegedHelper(cfg))
	}
	for _, file := range previous {
		if err := securefs.WriteRootFile(filepath.Join(backupDir, filepath.Base(file.path)), file.data, 0600); err != nil {
			return errors.Join(err, startPrivilegedHelper(cfg))
		}
	}
	installErr := withFileLock(filepath.Join(cfg.LockDir, "helper.instance.lock"), func() error {
		if err := assertNoPendingJournals(cfg.JournalDir); err != nil {
			return err
		}
		// Root settings and account grants are deliberately retained verbatim.
		if err := securefs.WriteRootFile(config.HelperBinaryPath, payload.Binary, 0755); err != nil {
			return err
		}
		if err := securefs.WriteRootFile(config.HelperControlPath, payload.Controller, 0755); err != nil {
			return err
		}
		// Execute only the verified protected copy, which installs its own fixed
		// rule so future control actions are not lost during automatic upgrades.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, config.HelperBinaryPath, "finalize-upgrade")
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("finalize signed Helper update: %w: %s", err, output)
		}
		return nil
	})
	if installErr == nil {
		installErr = startPrivilegedHelperVersion(cfg, payload.Manifest.Version, payload.Manifest.Revision)
	}
	if installErr == nil {
		return nil
	}
	// Never roll back over an instance that may still have a temporary password.
	if err := stopPrivilegedHelper(cfg); err != nil {
		return errors.Join(installErr, fmt.Errorf("recovery prevented rollback; protected backup: %s: %w", backupDir, err))
	}
	rollbackErr := restoreProtectedHelperFiles(previous, securefs.WriteRootFile)
	if rollbackErr != nil {
		return errors.Join(installErr, fmt.Errorf("restore protected backup %s: %w", backupDir, rollbackErr))
	}
	return errors.Join(fmt.Errorf("Helper update failed and previous files were restored: %w", installErr), startPrivilegedHelper(cfg))
}

type protectedHelperFile struct {
	path string
	data []byte
	mode os.FileMode
}

func FinalizePrivilegedUpgrade(cfg config.HelperConfig) error {
	if err := PreparePrivilegedRuntime(cfg); err != nil {
		return err
	}
	return installHelperSudoers()
}

func restoreProtectedHelperFiles(files []protectedHelperFile, write func(string, []byte, os.FileMode) error) error {
	var result error
	for _, file := range files {
		result = errors.Join(result, write(file.path, file.data, file.mode))
	}
	return result
}
