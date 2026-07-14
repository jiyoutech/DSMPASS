package helperserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/diaglog"
)

type journal struct {
	RequestID             string `json:"request_id"`
	DSMUsername           string `json:"dsm_username"`
	Status                string `json:"status"`
	OriginalLine          string `json:"original_line,omitempty"`
	OriginalLineEncrypted string `json:"original_line_encrypted,omitempty"`
	OriginalLineNonce     string `json:"original_line_nonce,omitempty"`
	OriginalLineHash      string `json:"original_line_hash"`
	TempPassword          string `json:"temp_password,omitempty"`
	TempPasswordEncrypted string `json:"temp_password_encrypted,omitempty"`
	TempPasswordNonce     string `json:"temp_password_nonce,omitempty"`
	TempLineHash          string `json:"temp_line_hash,omitempty"`
	ExpiresAt             string `json:"expires_at,omitempty"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

const (
	journalStatusPendingBrowser   = "pending_browser_login"
	journalStatusActiveBrowser    = "active_browser_login"
	journalStatusRestoringBrowser = "restoring_browser_login"
)

var (
	errBrowserLoginInProgress = errors.New("DSM 用户已有登录流程正在进行")
	errBrowserLoginUnresolved = errors.New("DSM 用户上一次登录的密码恢复状态无法确认")
)

type relayCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	MaxAge   int    `json:"max_age"`
	HTTPOnly bool   `json:"http_only"`
}

type relayLoginResult struct {
	SID     string        `json:"sid"`
	Cookies []relayCookie `json:"cookies"`
}

type browserLoginResult struct {
	Username     string `json:"username"`
	TempPassword string `json:"temp_password"`
	ExpiresAt    string `json:"expires_at"`
	TTLSeconds   int    `json:"ttl_seconds"`
}

func relayLoginReal(cfg config.HelperConfig, requestID, username string) (relayLoginResult, error) {
	diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.start", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"dsm_username":     username,
		"lock_dir":         cfg.LockDir,
		"shadow_path":      cfg.ShadowPath,
		"shadow_lock_path": cfg.ShadowLockPath,
		"synouser_path":    cfg.SynoUserPath,
		"journal_dir":      cfg.JournalDir,
	})
	if err := withFileLock(lockPath(cfg.LockDir, username), func() error {
		return nil
	}); err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.user_lock_probe.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
		return relayLoginResult{}, err
	}
	var result relayLoginResult
	err := withFileLock(lockPath(cfg.LockDir, username), func() error {
		diaglog.Append(cfg.DataDir, requestID, "helper.lock.user.acquired", cfg.LoginDiagnosticsEnabled, diaglog.Event{"lock_path": lockPath(cfg.LockDir, username)})
		if _, found, err := browserLeaseForUser(cfg, username); err != nil {
			return err
		} else if found {
			return errBrowserLoginInProgress
		}
		return withFileLock(cfg.ShadowLockPath, func() error {
			diaglog.Append(cfg.DataDir, requestID, "helper.lock.shadow.acquired", cfg.LoginDiagnosticsEnabled, diaglog.Event{"lock_path": cfg.ShadowLockPath})
			originalLine, err := shadowLine(cfg.ShadowPath, username)
			if err != nil {
				diaglog.Append(cfg.DataDir, requestID, "helper.shadow.read_original.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "shadow_path": cfg.ShadowPath})
				return err
			}
			diaglog.Append(cfg.DataDir, requestID, "helper.shadow.read_original.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{
				"shadow_path":        cfg.ShadowPath,
				"original_line":      originalLine,
				"original_line_hash": lineHash(originalLine),
			})
			j := journal{
				RequestID:        requestID,
				DSMUsername:      username,
				Status:           "pending",
				OriginalLine:     originalLine,
				OriginalLineHash: lineHash(originalLine),
				CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
			}
			if err := saveJournal(cfg, j); err != nil {
				diaglog.Append(cfg.DataDir, requestID, "helper.journal.save_pending.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "journal_dir": cfg.JournalDir})
				return err
			}
			diaglog.Append(cfg.DataDir, requestID, "helper.journal.save_pending.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{"journal_dir": cfg.JournalDir, "status": j.Status})
			tempPassword := randomPassword(cfg.TempPasswordLength)
			diaglog.Append(cfg.DataDir, requestID, "helper.password.generated", cfg.LoginDiagnosticsEnabled, diaglog.Event{
				"temp_password_length": len(tempPassword),
			})
			if err := runWithDiag(cfg, requestID, "helper.synouser.setpw", cfg.SynoUserPath, "--setpw", username, tempPassword); err != nil {
				j.Status = "failed"
				_ = saveJournal(cfg, j)
				diaglog.Append(cfg.DataDir, requestID, "helper.synouser.setpw.failed", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
				return err
			}
			tempLine, err := shadowLine(cfg.ShadowPath, username)
			if err != nil {
				diaglog.Append(cfg.DataDir, requestID, "helper.shadow.read_temp.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "shadow_path": cfg.ShadowPath})
				return err
			}
			diaglog.Append(cfg.DataDir, requestID, "helper.shadow.read_temp.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{
				"shadow_path":    cfg.ShadowPath,
				"temp_line":      tempLine,
				"temp_line_hash": lineHash(tempLine),
				"line_changed":   tempLine != originalLine,
				"original_line":  originalLine,
				"dsm_username":   username,
				"journal_status": j.Status,
			})
			j.TempLineHash = lineHash(tempLine)
			if err := saveJournal(cfg, j); err != nil {
				diaglog.Append(cfg.DataDir, requestID, "helper.journal.save_temp_hash.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "journal_dir": cfg.JournalDir})
				return err
			}
			diaglog.Append(cfg.DataDir, requestID, "helper.journal.save_temp_hash.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{"journal_dir": cfg.JournalDir, "temp_line_hash": j.TempLineHash})
			result, err = dsmLogin(cfg, requestID, username, tempPassword)
			if err != nil {
				restoreErr := restoreIfCurrentMatches(cfg.ShadowPath, username, originalLine, tempLine)
				diaglog.Append(cfg.DataDir, requestID, "helper.shadow.restore_after_dsm_login_error", cfg.LoginDiagnosticsEnabled, diaglog.Event{
					"dsm_login_error": err.Error(),
					"restore_error":   errorString(restoreErr),
					"original_line":   originalLine,
					"expected_line":   tempLine,
				})
				j.Status = "failed"
				_ = saveJournal(cfg, j)
				return err
			}
			diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.sid_received", cfg.LoginDiagnosticsEnabled, diaglog.Event{"sid": result.SID, "cookies": result.Cookies})
			validateDSMDesktopSession(cfg, requestID, result, "after_dsm_login_before_shadow_restore")
			if err := restoreIfCurrentMatches(cfg.ShadowPath, username, originalLine, tempLine); err != nil {
				j.Status = "conflict"
				_ = saveJournal(cfg, j)
				diaglog.Append(cfg.DataDir, requestID, "helper.shadow.restore.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{
					"error":         err.Error(),
					"original_line": originalLine,
					"expected_line": tempLine,
				})
				return err
			}
			restoredLine, restoredErr := shadowLine(cfg.ShadowPath, username)
			diaglog.Append(cfg.DataDir, requestID, "helper.shadow.restore.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{
				"restored_line":      restoredLine,
				"restored_line_hash": lineHash(restoredLine),
				"restore_read_error": errorString(restoredErr),
				"matches_original":   restoredErr == nil && restoredLine == originalLine,
				"matches_temp":       restoredErr == nil && restoredLine == tempLine,
			})
			validateDSMDesktopSession(cfg, requestID, result, "after_shadow_restore")
			j.Status = "restored"
			diaglog.Append(cfg.DataDir, requestID, "helper.journal.save_restored.start", cfg.LoginDiagnosticsEnabled, diaglog.Event{"journal_dir": cfg.JournalDir, "status": j.Status})
			return saveJournal(cfg, j)
		})
	})
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.finish.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
	} else {
		diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.finish.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{"sid": result.SID, "cookies": result.Cookies})
	}
	return result, err
}

func prepareBrowserLogin(cfg config.HelperConfig, requestID, username string) (browserLoginResult, error) {
	ttlSeconds := cfg.DSMBrowserLoginTTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = 30
	}
	diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.start", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"dsm_username": username,
		"ttl_seconds":  ttlSeconds,
	})
	var result browserLoginResult
	err := withFileLock(lockPath(cfg.LockDir, username), func() error {
		existing, found, err := browserLeaseForUser(cfg, username)
		if err != nil {
			return err
		}
		if found {
			if existing.RequestID != requestID {
				return errBrowserLoginInProgress
			}
			result, err = browserResultFromLease(cfg, existing)
			return err
		}
		expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second).UTC()
		return withFileLock(cfg.ShadowLockPath, func() error {
			originalLine, err := shadowLine(cfg.ShadowPath, username)
			if err != nil {
				return err
			}
			tempPassword := randomPassword(cfg.TempPasswordLength)
			j := journal{
				RequestID:        requestID,
				DSMUsername:      username,
				Status:           journalStatusPendingBrowser,
				OriginalLine:     originalLine,
				OriginalLineHash: lineHash(originalLine),
				TempPassword:     tempPassword,
				ExpiresAt:        expiresAt.Format(time.RFC3339Nano),
				CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
			}
			if err := saveJournal(cfg, j); err != nil {
				return err
			}
			diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.password_generated", cfg.LoginDiagnosticsEnabled, diaglog.Event{
				"temp_password_length": len(tempPassword),
			})
			if err := runWithDiag(cfg, requestID, "helper.prepare_browser_login.synouser.setpw", cfg.SynoUserPath, "--setpw", username, tempPassword); err != nil {
				return err
			}
			tempLine, err := shadowLine(cfg.ShadowPath, username)
			if err != nil {
				return err
			}
			j.TempLineHash = lineHash(tempLine)
			j.Status = journalStatusActiveBrowser
			if err := saveJournal(cfg, j); err != nil {
				return err
			}
			result = browserLoginResult{
				Username:     username,
				TempPassword: tempPassword,
				ExpiresAt:    expiresAt.Format(time.RFC3339Nano),
				TTLSeconds:   ttlSeconds,
			}
			go restoreBrowserLoginAfterTTL(cfg, requestID, username, time.Until(expiresAt))
			return nil
		})
	})
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.finish.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
	} else {
		diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.finish.success", cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"dsm_username": username,
			"expires_at":   result.ExpiresAt,
			"ttl_seconds":  result.TTLSeconds,
		})
	}
	return result, err
}

func restoreBrowserLoginAfterTTL(cfg config.HelperConfig, requestID, username string, delay time.Duration) {
	if delay > 0 {
		time.Sleep(delay)
	}
	if err := restorePendingJournal(cfg, requestID, "expired"); err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.restore_after_ttl.error", cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"dsm_username": username,
			"error":        err.Error(),
		})
	}
}

func recoverPending(cfg config.HelperConfig) {
	entries, err := os.ReadDir(cfg.JournalDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(cfg.JournalDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var j journal
		if json.Unmarshal(data, &j) != nil || !journalNeedsRecovery(j.Status) {
			continue
		}
		_ = restorePendingJournal(cfg, j.RequestID, "startup")
	}
}

func restorePendingJournal(cfg config.HelperConfig, requestID, reason string) error {
	j, err := loadJournal(cfg, requestID)
	if err != nil {
		return err
	}
	return withFileLock(lockPath(cfg.LockDir, j.DSMUsername), func() error {
		j, err = loadJournal(cfg, requestID)
		if err != nil {
			return err
		}
		if j.Status == "restored" {
			return nil
		}
		if !journalNeedsRecovery(j.Status) {
			return fmt.Errorf("%w: journal status is %s", errBrowserLoginUnresolved, j.Status)
		}
		return withFileLock(cfg.ShadowLockPath, func() error {
			current, err := shadowLine(cfg.ShadowPath, j.DSMUsername)
			if err != nil {
				return err
			}
			originalLine, err := j.decryptedOriginalLine(cfg)
			if err != nil {
				return err
			}
			if current == originalLine {
				j.Status = "restored"
				j.clearTempPassword()
				return saveJournal(cfg, j)
			}
			if j.TempLineHash == "" || lineHash(current) != j.TempLineHash {
				j.Status = "conflict"
				if err := saveJournal(cfg, j); err != nil {
					return err
				}
				return errBrowserLoginUnresolved
			}
			if isBrowserJournalStatus(j.Status) {
				j.Status = journalStatusRestoringBrowser
				if err := saveJournal(cfg, j); err != nil {
					return err
				}
			}
			if err := restoreIfCurrentMatches(cfg.ShadowPath, j.DSMUsername, originalLine, current); err != nil {
				return err
			}
			j.Status = "restored"
			j.clearTempPassword()
			diaglog.Append(cfg.DataDir, requestID, "helper.shadow.restore_pending_journal", cfg.LoginDiagnosticsEnabled, diaglog.Event{
				"dsm_username": j.DSMUsername,
				"status":       j.Status,
				"reason":       reason,
			})
			return saveJournal(cfg, j)
		})
	})
}

func browserLeaseForUser(cfg config.HelperConfig, username string) (journal, bool, error) {
	entries, err := os.ReadDir(cfg.JournalDir)
	if os.IsNotExist(err) {
		return journal{}, false, nil
	}
	if err != nil {
		return journal{}, false, err
	}
	var found journal
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cfg.JournalDir, entry.Name()))
		if err != nil {
			return journal{}, false, err
		}
		var existing journal
		if err := json.Unmarshal(data, &existing); err != nil {
			return journal{}, false, fmt.Errorf("%w: journal %s cannot be read", errBrowserLoginUnresolved, entry.Name())
		}
		if existing.DSMUsername != username || !browserLeaseBlocksNewLogin(existing.Status) {
			continue
		}
		if found.RequestID != "" && found.RequestID != existing.RequestID {
			return journal{}, false, fmt.Errorf("%w: multiple active journals", errBrowserLoginUnresolved)
		}
		found = existing
	}
	return found, found.RequestID != "", nil
}

func browserLeaseBlocksNewLogin(status string) bool {
	switch status {
	case "pending", journalStatusPendingBrowser, journalStatusActiveBrowser, journalStatusRestoringBrowser, "conflict":
		return true
	default:
		return false
	}
}

func isBrowserJournalStatus(status string) bool {
	switch status {
	case journalStatusPendingBrowser, journalStatusActiveBrowser, journalStatusRestoringBrowser:
		return true
	default:
		return false
	}
}

func journalNeedsRecovery(status string) bool {
	return status == "pending" || isBrowserJournalStatus(status)
}

func loadJournal(cfg config.HelperConfig, requestID string) (journal, error) {
	data, err := os.ReadFile(filepath.Join(cfg.JournalDir, safeName(requestID)+".json"))
	if err != nil {
		return journal{}, err
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil {
		return journal{}, err
	}
	return j, nil
}

func browserResultFromLease(cfg config.HelperConfig, j journal) (browserLoginResult, error) {
	if j.Status != journalStatusActiveBrowser {
		return browserLoginResult{}, errBrowserLoginUnresolved
	}
	tempPassword, err := j.decryptedTempPassword(cfg)
	if err != nil {
		return browserLoginResult{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, j.ExpiresAt)
	if err != nil {
		return browserLoginResult{}, fmt.Errorf("%w: invalid lease expiry", errBrowserLoginUnresolved)
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return browserLoginResult{}, errBrowserLoginInProgress
	}
	ttlSeconds := int((remaining + time.Second - 1) / time.Second)
	return browserLoginResult{
		Username:     j.DSMUsername,
		TempPassword: tempPassword,
		ExpiresAt:    j.ExpiresAt,
		TTLSeconds:   ttlSeconds,
	}, nil
}

func shadowLine(path, username string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	prefix := username + ":"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line, nil
		}
	}
	return "", errors.New("DSM user not found")
}

func restoreIfCurrentMatches(path, username, originalLine, expectedCurrentLine string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hasTrailingNewline := strings.HasSuffix(string(data), "\n")
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	prefix := username + ":"
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			if line != expectedCurrentLine {
				return errors.New("shadow line changed by another process")
			}
			lines[i] = originalLine
			replaced = true
			break
		}
	}
	if !replaced {
		return errors.New("DSM user not found during restore")
	}
	updated := strings.Join(lines, "\n")
	if hasTrailingNewline {
		updated += "\n"
	}
	return rewriteShadowInPlace(path, []byte(updated))
}

func dsmLogin(cfg config.HelperConfig, requestID, username, password string) (relayLoginResult, error) {
	values := url.Values{}
	values.Set("api", "SYNO.API.Auth")
	values.Set("method", "login")
	values.Set("version", "7")
	values.Set("account", username)
	values.Set("passwd", password)
	values.Set("session", cfg.DSMSession)
	if cfg.DSMFormat != "" {
		values.Set("format", cfg.DSMFormat)
	}
	if cfg.DSMOTPCode != "" {
		values.Set("otp_code", cfg.DSMOTPCode)
	}
	if cfg.DSMEnableDeviceToken != "" {
		values.Set("enable_device_token", cfg.DSMEnableDeviceToken)
	}
	if cfg.DSMDeviceName != "" {
		values.Set("device_name", cfg.DSMDeviceName)
	}
	if cfg.DSMDeviceID != "" {
		values.Set("device_id", cfg.DSMDeviceID)
	}
	sep := "?"
	if strings.Contains(cfg.DSMLoginAPI, "?") {
		sep = "&"
	}
	fullURL := cfg.DSMLoginAPI + sep + values.Encode()
	diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.request", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"dsm_login_api":       cfg.DSMLoginAPI,
		"login_url_redacted":  redactedURL(fullURL, "passwd", "otp_code", "device_id"),
		"account":             username,
		"session":             cfg.DSMSession,
		"format":              cfg.DSMFormat,
		"enable_device_token": cfg.DSMEnableDeviceToken,
		"device_name":         cfg.DSMDeviceName,
	})
	client := dsmHTTPClient(cfg)
	start := time.Now()
	response, err := client.Get(fullURL)
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.http_error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
		return relayLoginResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.read_error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
		return relayLoginResult{}, err
	}
	diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.response", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"http_status":      response.StatusCode,
		"header_names":     headerNames(response.Header),
		"set_cookie_count": len(response.Header.Values("Set-Cookie")),
		"body_bytes":       len(body),
		"duration_ms":      time.Since(start).Milliseconds(),
	})
	var parsed struct {
		Success bool `json:"success"`
		Data    struct {
			SID string `json:"sid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return relayLoginResult{}, err
	}
	if !parsed.Success || parsed.Data.SID == "" {
		diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.parsed_failure", cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"success":     parsed.Success,
			"sid_present": parsed.Data.SID != "",
			"body_bytes":  len(body),
		})
		return relayLoginResult{}, errors.New("DSM login failed")
	}
	cookies := relayCookiesFromHTTP(response.Cookies())
	diaglog.Append(cfg.DataDir, requestID, "helper.dsm_login.parsed_success", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"sid":     parsed.Data.SID,
		"cookies": cookies,
	})
	return relayLoginResult{SID: parsed.Data.SID, Cookies: cookies}, nil
}

func relayCookiesFromHTTP(httpCookies []*http.Cookie) []relayCookie {
	cookies := make([]relayCookie, 0, len(httpCookies))
	for _, cookie := range httpCookies {
		cookies = append(cookies, relayCookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			MaxAge:   cookie.MaxAge,
			HTTPOnly: cookie.HttpOnly,
		})
	}
	return cookies
}

func redactedURL(raw string, sensitiveKeys ...string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[invalid-url]"
	}
	sensitive := map[string]bool{}
	for _, key := range sensitiveKeys {
		sensitive[strings.ToLower(key)] = true
	}
	values := parsed.Query()
	for key := range values {
		if sensitive[strings.ToLower(key)] {
			values.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func headerNames(headers http.Header) []string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	return names
}

func validateDSMDesktopSession(cfg config.HelperConfig, requestID string, result relayLoginResult, phase string) {
	parsed, err := url.Parse(cfg.DSMLoginAPI)
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.dsm_sessiondata.validate.skip", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "dsm_login_api": cfg.DSMLoginAPI, "phase": phase})
		return
	}
	parsed.Path = "/webapi/entry.cgi"
	values := url.Values{}
	values.Set("api", "SYNO.Core.Desktop.SessionData")
	values.Set("version", "1")
	values.Set("method", "getjs")
	values.Set("SynoToken", "")
	parsed.RawQuery = values.Encode()
	parsed.Fragment = ""
	validationURL := parsed.String()
	request, err := http.NewRequest(http.MethodGet, validationURL, nil)
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.dsm_sessiondata.validate.request_error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "validation_url": validationURL, "phase": phase})
		return
	}
	hasID := false
	for _, cookie := range result.Cookies {
		if cookie.Name == "" || cookie.Value == "" {
			continue
		}
		if cookie.Name == "id" {
			hasID = true
		}
		request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value, Path: "/"})
	}
	if !hasID && result.SID != "" {
		request.AddCookie(&http.Cookie{Name: "id", Value: result.SID, Path: "/"})
	}
	start := time.Now()
	client := dsmHTTPClient(cfg)
	response, err := client.Do(request)
	if err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.dsm_sessiondata.validate.http_error", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "validation_url": validationURL, "phase": phase})
		return
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
	bodyText := string(body)
	diaglog.Append(cfg.DataDir, requestID, "helper.dsm_sessiondata.validate.response", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"validation_url":   validationURL,
		"cookies":          result.Cookies,
		"sid":              result.SID,
		"http_status":      response.StatusCode,
		"header_names":     headerNames(response.Header),
		"set_cookie_count": len(response.Header.Values("Set-Cookie")),
		"location":         response.Header.Get("Location"),
		"is_logined":       strings.Contains(bodyText, `"isLogined" : true`),
		"body_bytes":       len(body),
		"read_error":       errorString(readErr),
		"duration_ms":      time.Since(start).Milliseconds(),
		"phase":            phase,
	})
}

func runWithDiag(cfg config.HelperConfig, requestID, stage, name string, args ...string) error {
	diaglog.Append(cfg.DataDir, requestID, stage+".start", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"command": name,
		"args":    redactedCommandArgs(args),
	})
	start := time.Now()
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	fields := diaglog.Event{
		"command":     name,
		"args":        redactedCommandArgs(args),
		"output":      string(output),
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if err != nil {
		fields["error"] = err.Error()
		diaglog.Append(cfg.DataDir, requestID, stage+".error", cfg.LoginDiagnosticsEnabled, fields)
		return errors.New(strings.TrimSpace(string(output)) + ": " + err.Error())
	}
	diaglog.Append(cfg.DataDir, requestID, stage+".success", cfg.LoginDiagnosticsEnabled, fields)
	return nil
}

func redactedCommandArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	for i, arg := range redacted {
		if arg == "--setpw" && i+2 < len(redacted) {
			redacted[i+2] = "[REDACTED]"
		}
	}
	return redacted
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func dsmHTTPClient(cfg config.HelperConfig) http.Client {
	client := http.Client{Timeout: time.Duration(cfg.DSMTimeoutSeconds) * time.Second}
	parsed, err := url.Parse(cfg.DSMLoginAPI)
	if err != nil {
		return client
	}
	host := parsed.Hostname()
	if cfg.DSMTLSSkipVerify || host == "localhost" || net.ParseIP(host).IsLoopback() {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - explicit test/local DSM compatibility option.
		}
	}
	return client
}

func withFileLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

func lockPath(dir, username string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return r
		}
		return '_'
	}, username)
	return filepath.Join(dir, "user-"+safe+".lock")
}

func saveJournal(cfg config.HelperConfig, j journal) error {
	if err := j.encryptOriginalLine(cfg); err != nil {
		return err
	}
	if err := j.encryptTempPassword(cfg); err != nil {
		return err
	}
	dir := cfg.JournalDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	j.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, safeName(j.RequestID)+".json")
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func (j *journal) encryptOriginalLine(cfg config.HelperConfig) error {
	if j.OriginalLine == "" {
		return nil
	}
	nonce, ciphertext, err := encryptJournalValue(cfg, journalAAD(*j), j.OriginalLine)
	if err != nil {
		return err
	}
	j.OriginalLineNonce = nonce
	j.OriginalLineEncrypted = ciphertext
	j.OriginalLine = ""
	return nil
}

func (j journal) decryptedOriginalLine(cfg config.HelperConfig) (string, error) {
	if j.OriginalLineEncrypted == "" {
		if j.OriginalLine == "" {
			return "", errors.New("journal missing original line")
		}
		return j.OriginalLine, nil
	}
	return decryptJournalValue(cfg, journalAAD(j), j.OriginalLineNonce, j.OriginalLineEncrypted)
}

func (j *journal) encryptTempPassword(cfg config.HelperConfig) error {
	if j.TempPassword == "" {
		return nil
	}
	nonce, ciphertext, err := encryptJournalValue(cfg, tempPasswordAAD(*j), j.TempPassword)
	if err != nil {
		return err
	}
	j.TempPasswordNonce = nonce
	j.TempPasswordEncrypted = ciphertext
	j.TempPassword = ""
	return nil
}

func (j journal) decryptedTempPassword(cfg config.HelperConfig) (string, error) {
	if j.TempPasswordEncrypted == "" {
		if j.TempPassword == "" {
			return "", errors.New("journal missing temporary password")
		}
		return j.TempPassword, nil
	}
	return decryptJournalValue(cfg, tempPasswordAAD(j), j.TempPasswordNonce, j.TempPasswordEncrypted)
}

func (j *journal) clearTempPassword() {
	j.TempPassword = ""
	j.TempPasswordEncrypted = ""
	j.TempPasswordNonce = ""
}

func encryptJournalValue(cfg config.HelperConfig, aad []byte, plaintext string) (string, string, error) {
	gcm, err := journalCipher(cfg)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), aad)
	return base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decryptJournalValue(cfg config.HelperConfig, aad []byte, nonceText, ciphertextText string) (string, error) {
	gcm, err := journalCipher(cfg)
	if err != nil {
		return "", err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceText)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextText)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func journalCipher(cfg config.HelperConfig) (cipher.AEAD, error) {
	if cfg.HMACSecret == "" {
		return nil, errors.New("helper hmac secret is required for journal encryption")
	}
	key := sha256.Sum256([]byte("dsmpass journal v1\x00" + cfg.HMACSecret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func journalAAD(j journal) []byte {
	return []byte(j.RequestID + "\x00" + j.DSMUsername + "\x00" + j.OriginalLineHash)
}

func tempPasswordAAD(j journal) []byte {
	return append(journalAAD(j), []byte("\x00temp_password")...)
}

func rewriteShadowInPlace(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func safeName(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r == '_' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "request"
	}
	return b.String()
}

func lineHash(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

func randomPassword(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		length = 64
	}
	bytes := make([]byte, length)
	_, _ = rand.Read(bytes)
	for i := range bytes {
		bytes[i] = alphabet[int(bytes[i])%len(alphabet)]
	}
	return string(bytes)
}
