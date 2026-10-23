package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

var errPasswordResetUnknown = errors.New("DSM/SMB 密码重置结果待确认，请检查 DSM 后重新手动执行全量同步")

type passwordResetRecord struct {
	RequestID      string `json:"request_id"`
	Username       string `json:"username"`
	SourceSlug     string `json:"source_slug"`
	AccountID      string `json:"account_id"`
	PasswordDigest string `json:"password_digest"`
	Status         string `json:"status"`
}

func passwordResetPath(cfg config.HelperConfig, username string) string {
	return filepath.Join(cfg.JournalDir, "password-resets", lineHash(strings.ToLower(username))+".json")
}

func loadPasswordReset(cfg config.HelperConfig, username string) (passwordResetRecord, error) {
	return readPasswordReset(passwordResetPath(cfg, username), username)
}

func passwordResetRequestPath(cfg config.HelperConfig, requestID string) string {
	return filepath.Join(cfg.JournalDir, "password-resets", "requests", lineHash(requestID)+".json")
}

func readPasswordReset(path, username string) (passwordResetRecord, error) {
	var record passwordResetRecord
	data, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, err
	}
	if !strings.EqualFold(record.Username, username) || record.RequestID == "" || record.SourceSlug == "" || record.AccountID == "" || len(record.PasswordDigest) != 64 || (record.Status != "applying" && record.Status != "unknown" && record.Status != "completed") {
		return record, errors.New("invalid password reset record")
	}
	return record, nil
}

func savePasswordReset(cfg config.HelperConfig, record passwordResetRecord) error {
	return writePasswordReset(passwordResetPath(cfg, record.Username), record)
}

func writePasswordReset(path string, record passwordResetRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeFileAtomically(path, data, 0o600)
}

func checkPasswordResetPending(cfg config.HelperConfig, username string) error {
	record, err := loadPasswordReset(cfg, username)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || record.Status != "completed" {
		return errors.Join(errPasswordResetUnknown, err)
	}
	return nil
}

// Caller holds both project locks. A failed or killed native command may have
// updated only one credential store. Never restore shadow or auto-retry it.
func applyPermanentPassword(cfg config.HelperConfig, values map[string]string) error {
	record := passwordResetRecord{
		RequestID: values["request_id"], Username: values["dsm_username"],
		SourceSlug: values["source_slug"], AccountID: values["account_id"],
		PasswordDigest: lineHash(values["password"]), Status: "applying",
	}
	requestPath := passwordResetRequestPath(cfg, record.RequestID)
	previous, err := readPasswordReset(requestPath, record.Username)
	if err != nil && !os.IsNotExist(err) {
		return errors.Join(errPasswordResetUnknown, err)
	}
	if err == nil {
		if previous.RequestID != record.RequestID || previous.PasswordDigest != record.PasswordDigest || previous.SourceSlug != record.SourceSlug || previous.AccountID != record.AccountID {
			return errors.New("password reset request ID was reused with different arguments")
		}
		if previous.Status == "completed" {
			current, err := loadPasswordReset(cfg, record.Username)
			if err != nil {
				return errors.Join(errPasswordResetUnknown, err)
			}
			if current.RequestID == record.RequestID {
				// Recover a crash after recording the successful command but
				// before updating the account's current marker.
				return savePasswordReset(cfg, previous)
			}
			return nil
		}
		return errPasswordResetUnknown
	}
	// Retain request history as well as the current account marker. A delayed
	// request must not reapply an old password after a newer full sync finished.
	if err := writePasswordReset(requestPath, record); err != nil {
		return err
	}
	if err := savePasswordReset(cfg, record); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := runAccountCommand(ctx, cfg.SynoUserPath, "--setpw", record.Username, values["password"]); err != nil {
		record.Status = "unknown"
		return errors.Join(errPasswordResetUnknown, err, writePasswordReset(requestPath, record), savePasswordReset(cfg, record))
	}
	record.Status = "completed"
	if err := writePasswordReset(requestPath, record); err != nil {
		return errors.Join(errPasswordResetUnknown, err)
	}
	if err := savePasswordReset(cfg, record); err != nil {
		return errors.Join(errPasswordResetUnknown, err)
	}
	return nil
}

func runAccountCommand(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = time.Second
	// Do not return command output: native commands can echo password arguments.
	if err := command.Run(); err != nil {
		return fmt.Errorf("DSM account command did not complete successfully: %w", err)
	}
	return nil
}
