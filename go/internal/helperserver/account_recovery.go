package helperserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func ensureNewLoginJournal(cfg config.HelperConfig, requestID, username string) error {
	if requestID == "" || safeName(requestID) != requestID {
		return errors.New("invalid login request ID")
	}
	if _, err := loadJournal(cfg, requestID); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return errors.New("login request ID has already been used")
	}
	return checkPasswordResetPending(cfg, username)
}

func accountUID(cfg config.HelperConfig, username string) (string, error) {
	path := filepath.Join(filepath.Dir(cfg.ShadowPath), "passwd")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) && filepath.Clean(cfg.ShadowPath) != "/etc/shadow" {
		return "", nil // isolated unit-test shadow files have no passwd database
	}
	if err != nil {
		return "", err
	}
	var uid string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 || fields[0] != username {
			continue
		}
		if len(fields) != 7 || uid != "" {
			return "", errors.New("ambiguous or invalid account identity")
		}
		if _, err := strconv.ParseUint(fields[2], 10, 32); err != nil {
			return "", errors.New("invalid account UID")
		}
		uid = fields[2]
	}
	if uid == "" {
		return "", errors.New("account identity no longer exists")
	}
	return uid, nil
}

func shadowFields(username, line string) ([]string, error) {
	fields := strings.Split(line, ":")
	if len(fields) != 9 || fields[0] != username || strings.ContainsAny(line, "\r\n\x00") {
		return nil, errors.New("invalid shadow account record")
	}
	return fields, nil
}

func restoreJournalUnderAccountLock(cfg config.HelperConfig, j journal, reason string) error {
	if j.Status == "restored" || j.Status == journalStatusSuperseded {
		return nil
	}
	if !journalNeedsRecovery(j.Status) {
		return errBrowserLoginUnresolved
	}
	if isBrowserJournalStatus(j.Status) && j.Status != journalStatusRestoringBrowser {
		j.Status = journalStatusRestoringBrowser
		if err := saveJournal(cfg, j); err != nil {
			return err
		}
	}
	// Old releases could crash before saving the temporary fingerprint. Keep
	// their verification path, but never hold a global/system lock during HTTP.
	if j.TempLineHash == "" && j.TempPasswordHash == "" {
		var candidate string
		err := withShadowWrite(cfg, func() error {
			var err error
			candidate, err = shadowLine(cfg.ShadowPath, j.DSMUsername)
			return err
		})
		if err != nil {
			return err
		}
		original, err := j.decryptedOriginalLine(cfg)
		if err != nil {
			return err
		}
		currentFields, err := shadowFields(j.DSMUsername, candidate)
		if err != nil {
			return err
		}
		originalFields, err := shadowFields(j.DSMUsername, original)
		if err != nil {
			return err
		}
		if currentFields[1] != originalFields[1] {
			password, err := j.decryptedTempPassword(cfg)
			if err == nil {
				_, err = dsmLogin(cfg, j.RequestID+"_recovery_verify", j.DSMUsername, password)
			}
			if err != nil {
				j.Status = journalStatusUnresolvedBrowser
				return errors.Join(errBrowserLoginUnresolved, err, saveJournal(cfg, j))
			}
			j.TempPasswordHash = lineHash(currentFields[1])
			if err := saveJournal(cfg, j); err != nil {
				return err
			}
		}
	}
	return withShadowWrite(cfg, func() error {
		return restoreJournalPasswordLocked(cfg, j, reason)
	})
}

// Both the account lock and the project/system writer locks must be held.
func restoreJournalPasswordLocked(cfg config.HelperConfig, j journal, reason string) error {
	if j.AccountUID != "" {
		uid, err := accountUID(cfg, j.DSMUsername)
		if err != nil || uid != j.AccountUID {
			return errors.Join(errBrowserLoginUnresolved, errors.New("account identity changed; refusing password recovery"), err)
		}
	}
	current, err := shadowLine(cfg.ShadowPath, j.DSMUsername)
	if err != nil {
		return err
	}
	original, err := j.decryptedOriginalLine(cfg)
	if err != nil {
		return err
	}
	fields, err := shadowFields(j.DSMUsername, current)
	if err != nil {
		return err
	}
	old, err := shadowFields(j.DSMUsername, original)
	if err != nil {
		return err
	}
	base := strings.TrimLeft(fields[1], "!")
	prefix := strings.TrimSuffix(fields[1], base)
	if base == strings.TrimLeft(old[1], "!") {
		return finishJournal(cfg, j, "restored", j.RequestID, reason)
	}
	if base == "" || strings.HasPrefix(base, "*") {
		return fmt.Errorf("%w: current locked password cannot be identified", errBrowserLoginUnresolved)
	}
	if j.TempPasswordHash != "" {
		if lineHash(base) != j.TempPasswordHash {
			return finishJournal(cfg, j, journalStatusSuperseded, j.RequestID, reason)
		}
	} else {
		// Older journals identify the whole temporary row. Reconstruct that row
		// with its original metadata to recognize expiry/lock-only changes.
		candidate := append([]string(nil), old...)
		candidate[1] = base
		if lineHash(current) != j.TempLineHash && lineHash(strings.Join(candidate, ":")) != j.TempLineHash {
			if strings.Join(fields[2:], ":") != strings.Join(old[2:], ":") {
				return fmt.Errorf("%w: legacy temporary fingerprint is ambiguous", errBrowserLoginUnresolved)
			}
			return finishJournal(cfg, j, journalStatusSuperseded, j.RequestID, reason)
		}
	}
	if prefix == "" && strings.HasPrefix(old[1], "!") {
		prefix = "!"
	}
	fields[1] = prefix + strings.TrimLeft(old[1], "!")
	if err := replaceShadowLineIfCurrentMatches(cfg.ShadowPath, j.DSMUsername, strings.Join(fields, ":"), current); err != nil {
		return err
	}
	return finishJournal(cfg, j, "restored", j.RequestID, reason)
}

func recordRecoveryFailure(cfg config.HelperConfig, requestID string) error {
	j, err := loadJournal(cfg, requestID)
	if err != nil || !journalNeedsRecovery(j.Status) {
		return err
	}
	j.RecoveryAttempts++
	delay := 2 * time.Second
	for n := 1; n < j.RecoveryAttempts && delay < time.Minute; n++ {
		delay *= 2
	}
	if delay > time.Minute {
		delay = time.Minute
	}
	j.NextRecoveryAt = time.Now().Add(delay).UTC().Format(time.RFC3339Nano)
	return saveJournal(cfg, j)
}

func runRecoveryLoop(ctx context.Context, cfg config.HelperConfig) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := recoverJournals(cfg, false); err != nil {
				log.Printf("DSM Pass helper password recovery pending: %v", err)
			}
		}
	}
}
