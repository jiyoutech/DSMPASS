package helperserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

const installedPackageDir = "/var/packages/DSMPASS/target"
const installedPackageVar = "/var/packages/DSMPASS/var"
const helperSudoersPath = "/etc/sudoers.d/DSMPASS-helper"

func InstallPrivilegedHelper() error {
	if os.Geteuid() != 0 {
		return errors.New("Helper installation requires a root administrator")
	}
	account, err := user.Lookup("DSMPASS")
	if err != nil {
		return fmt.Errorf("lookup DSMPASS package account: %w", err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return errors.New("DSMPASS package account must not be root")
	}
	settings := config.RootHelperSettings{PackageUID: uid, PackageGID: gid,
		DatabasePath: installedPackageVar + "/data/dsmpass.db",
		DSMLoginAPI:  "auto"}
	if _, err := os.Lstat(config.HelperConfigPath); err == nil {
		// Preserve root-approved settings on upgrades, never reload package env.
		if err := securefs.CheckRootPath(config.HelperConfigPath); err != nil {
			return err
		}
		data, err := os.ReadFile(config.HelperConfigPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &settings); err != nil {
			return err
		}
		settings.PackageUID, settings.PackageGID = uid, gid
	} else if !os.IsNotExist(err) {
		return err
	} else {
		data, err := os.ReadFile(installedPackageVar + "/dsmpass.env")
		if err != nil {
			return err
		}
		settings.HMACSecret, err = bootstrapHelperSecret(string(data))
		if err != nil {
			return err
		}
	}
	if err := config.ValidateRootHelperSettings(settings); err != nil {
		return err
	}
	// Installation payloads are trusted only during this explicit root action.
	binary, err := os.ReadFile(installedPackageDir + "/bin/dsmpass-helper")
	if err != nil {
		return err
	}
	controller, err := os.ReadFile(installedPackageDir + "/helper-control.sh")
	if err != nil {
		return err
	}
	for _, dir := range []string{config.HelperInstallDir, filepath.Dir(config.HelperConfigPath), config.HelperDataDir, config.HelperRunDir, config.HelperRunDir + "/locks"} {
		mode := os.FileMode(0700)
		if dir == config.HelperInstallDir {
			mode = 0755
		}
		if dir == config.HelperRunDir {
			mode = 0750
		}
		if err := securefs.EnsureRootDir(dir, mode); err != nil {
			return err
		}
	}
	return withFileLock(config.HelperRunDir+"/locks/helper.instance.lock", func() error {
		if err := assertNoPendingJournals(config.HelperDataDir + "/journal"); err != nil {
			return err
		}
		if err := installProtectedHelperFiles(settings, binary, controller); err != nil {
			return err
		}
		cfg, err := config.LoadPrivilegedHelper()
		if err != nil {
			return err
		}
		result, err := migrateInstalledAccounts(cfg)
		if err != nil {
			return fmt.Errorf("automatic account enrollment failed; start the backend to initialize its database and retry setup: %w", err)
		}
		log.Printf("account enrollment migration: users=%d groups=%d skipped=%d already_complete=%t", result.Users, result.Groups, result.Skipped, result.AlreadyComplete)
		return nil
	})
}

func installProtectedHelperFiles(settings config.RootHelperSettings, binary, controller []byte) error {
	if err := os.Chmod(config.HelperInstallDir, 0755); err != nil {
		return err
	}
	if err := os.Chown(config.HelperRunDir, 0, settings.PackageGID); err != nil {
		return err
	}
	if err := os.Chmod(config.HelperRunDir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := securefs.WriteRootFile(config.HelperConfigPath, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := securefs.WriteRootFile(config.HelperBinaryPath, binary, 0755); err != nil {
		return err
	}
	if err := securefs.WriteRootFile(config.HelperControlPath, controller, 0755); err != nil {
		return err
	}
	if err := securefs.EnsureRootDir(filepath.Dir(helperSudoersPath), 0755); err != nil {
		return err
	}
	return installHelperSudoers()
}

func assertNoPendingJournals(dir string) error {
	indexes, err := os.ReadDir(filepath.Join(dir, "active-index"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range indexes {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			return errors.New("account recovery index is pending; resolve password recovery before changing Helper")
		}
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		var record struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(data, &record); err != nil {
			return errors.New("unreadable password recovery journal; resolve recovery before changing Helper")
		}
		if record.Status != "restored" && record.Status != journalStatusSuperseded {
			return errors.New("password recovery is pending; complete recovery before changing Helper")
		}
	}
	return nil
}

func bootstrapHelperSecret(data string) (string, error) {
	secret := ""
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "DSMPASS_HELPER_HMAC_SECRET=") {
			continue
		}
		if secret != "" {
			return "", errors.New("duplicate Helper signing secret in package configuration")
		}
		secret = strings.TrimPrefix(line, "DSMPASS_HELPER_HMAC_SECRET=")
		if len(secret) != 64 || strings.Trim(secret, "0123456789abcdefABCDEF") != "" {
			return "", errors.New("package Helper signing secret must be a 64-character hexadecimal value")
		}
	}
	if secret == "" {
		return "", errors.New("package Helper signing secret is missing")
	}
	return secret, nil
}

func helperSudoersRule() string {
	controller := config.HelperControlPath
	return "Defaults!" + controller + " env_reset, !setenv, secure_path=\"/usr/sbin:/usr/bin:/sbin:/bin\"\n" +
		"DSMPASS ALL=(root) NOPASSWD: NOSETENV: " + controller + " start, " + controller + " stop, " + controller + " restart, " + controller + " status, " + controller + " upgrade, " + controller + " uninstall-preserve, " + controller + " uninstall-purge\n"
}
