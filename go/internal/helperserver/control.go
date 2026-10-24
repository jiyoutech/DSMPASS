package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

type helperProcess struct {
	PID       int    `json:"pid"`
	StartTime string `json:"start_time"`
}

func PreparePrivilegedRuntime(cfg config.HelperConfig) error {
	if !cfg.Privileged || os.Geteuid() != 0 {
		return errors.New("trusted Helper runtime requires root")
	}
	for _, path := range []string{config.HelperBinaryPath, config.HelperControlPath, config.HelperConfigPath} {
		if err := securefs.CheckRootPath(path); err != nil {
			return err
		}
	}
	for _, path := range []string{config.HelperDataDir, cfg.JournalDir, cfg.LockDir} {
		if err := securefs.EnsureRootDir(path, 0700); err != nil {
			return err
		}
	}
	if err := securefs.CheckRootPath(config.HelperRunDir); err != nil {
		return err
	}
	if err := os.Chown(config.HelperRunDir, 0, cfg.PackageGID); err != nil {
		return err
	}
	return os.Chmod(config.HelperRunDir, 0750)
}

func ControlPrivilegedHelper(cfg config.HelperConfig, action string) error {
	if action != "start" && action != "stop" && action != "restart" && action != "status" && action != "upgrade" && action != "uninstall-preserve" && action != "uninstall-purge" {
		return errors.New("unsupported Helper control action")
	}
	if err := PreparePrivilegedRuntime(cfg); err != nil {
		return err
	}
	return withFileLock(filepath.Join(config.HelperRunDir, "control.lock"), func() error {
		// Recheck after waiting: a preceding uninstall may have removed the
		// protected files while this process was queued on the control lock.
		if err := PreparePrivilegedRuntime(cfg); err != nil {
			return err
		}
		if action == "uninstall-preserve" || action == "uninstall-purge" {
			return uninstallPrivilegedHelper(cfg, action == "uninstall-purge")

		}
		if action == "upgrade" {
			return upgradePrivilegedHelper(cfg)
		}
		if action == "stop" || action == "restart" {
			if err := stopPrivilegedHelper(cfg); err != nil {
				return err
			}
		}
		if action == "start" || action == "restart" {
			return startPrivilegedHelper(cfg)
		}
		if action == "status" {
			_, running, err := installedHelperProcess()
			if err != nil {
				return err
			}
			if !running {
				return errors.New("Helper is not running")
			}
		}
		return nil
	})
}

func startPrivilegedHelper(cfg config.HelperConfig) error {
	return startPrivilegedHelperVersion(cfg, buildinfo.Version, buildinfo.Revision)
}

func startPrivilegedHelperVersion(cfg config.HelperConfig, version, revision string) error {
	if _, running, err := installedHelperProcess(); err != nil || running {
		return err
	}
	// Refuse an untracked/old instance instead of killing a PID from package data.
	if err := withFileLock(filepath.Join(cfg.LockDir, "helper.instance.lock"), func() error { return nil }); err != nil {
		return fmt.Errorf("another Helper is running; stop it before migration: %w", err)
	}
	logPath := filepath.Join(config.HelperDataDir, "helper.log")
	if _, err := os.Lstat(logPath); err == nil {
		if err := securefs.CheckRootPath(logPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	fd, err := syscall.Open(logPath, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	logFile := os.NewFile(uintptr(fd), logPath)
	defer logFile.Close()
	info, err := logFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Helper log must be a regular file")
	}
	cmd := exec.Command(config.HelperBinaryPath)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Process.Release()
	start, err := processStartTime(cmd.Process.Pid)
	if err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	record, err := json.Marshal(helperProcess{PID: cmd.Process.Pid, StartTime: start})
	if err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	if err := securefs.WriteRootFile(filepath.Join(config.HelperRunDir, "helper.pid"), record, 0600); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	client := helperclient.UnixSocketClient{SocketPath: cfg.SocketPath, Secret: cfg.HMACSecret, Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.HealthCheck(context.Background())
		if err == nil && response["version"] == version && response["revision"] == revision && response["privileged_boundary"] == true {
			return nil
		}
		if _, running, err := installedHelperProcess(); err != nil || !running {
			return errors.New("Helper exited during startup; inspect the root-owned Helper log")
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return errors.New("Helper health check timed out; inspect the root-owned Helper log")
}

func stopPrivilegedHelper(cfg config.HelperConfig) error {
	process, running, err := installedHelperProcess()
	if err != nil {
		return err
	}
	if running {
		p, err := os.FindProcess(process.PID)
		if err != nil {
			return err
		}
		defer p.Release()
		if err := p.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			_, running, err = installedHelperProcess()
			if err != nil {
				return err
			}
			if !running {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if running {
			return errors.New("Helper did not stop; refusing to start a second instance")
		}
	}
	if err := withFileLock(filepath.Join(cfg.LockDir, "helper.instance.lock"), func() error {
		if err := recoverPending(cfg); err != nil {
			return err
		}
		return assertNoPendingJournals(cfg.JournalDir)
	}); err != nil {
		// An aborted stop/uninstall must not leave every other account offline.
		// The instance lock has been released; restart the protected recovery loop.
		restartErr := startPrivilegedHelper(cfg)
		if restartErr != nil {
			return errors.Join(fmt.Errorf("password recovery incomplete; uninstall/update was cancelled: %w", err), fmt.Errorf("restart Helper recovery service: %w", restartErr))
		}
		return fmt.Errorf("password recovery incomplete; Helper was restarted to continue recovery, uninstall/update was cancelled: %w", err)
	}
	err = os.Remove(filepath.Join(config.HelperRunDir, "helper.pid"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func installedHelperProcess() (helperProcess, bool, error) {
	var process helperProcess
	path := filepath.Join(config.HelperRunDir, "helper.pid")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return process, false, nil
	} else if err != nil {
		return process, false, err
	}
	if err := securefs.CheckRootPath(path); err != nil {
		return process, false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return process, false, err
	}
	if err := json.Unmarshal(data, &process); err != nil || process.PID <= 1 || process.StartTime == "" {
		return process, false, errors.New("invalid protected Helper PID record")
	}
	start, err := processStartTime(process.PID)
	if os.IsNotExist(err) {
		return process, false, nil
	} else if err != nil {
		return process, false, err
	}
	if start != process.StartTime {
		return process, false, nil
	}
	executable, err := os.Readlink("/proc/" + strconv.Itoa(process.PID) + "/exe")
	if os.IsNotExist(err) {
		return process, false, nil
	}
	if err != nil || (executable != config.HelperBinaryPath && executable != config.HelperBinaryPath+" (deleted)") {
		return process, false, errors.New("protected PID does not identify the installed Helper")
	}
	return process, true, nil
}

func processStartTime(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	return parseProcessStartTime(string(data))
}

func parseProcessStartTime(stat string) (string, error) {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return "", errors.New("incomplete process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("invalid process start time")
	}
	return fields[19], nil
}
