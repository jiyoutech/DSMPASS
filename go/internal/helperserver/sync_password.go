package helperserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) resetSyncedUserPassword(cfg config.HelperConfig, payload map[string]any) error {
	values := make(map[string]string)
	for _, key := range []string{"request_id", "source_slug", "account_id", "dsm_username", "password"} {
		value, err := requiredString(payload, key)
		if err != nil {
			return err
		}
		values[key] = value
	}
	username, password := values["dsm_username"], values["password"]
	if err := assertAllowed(cfg, username); err != nil {
		return err
	}
	if strings.ContainsAny(username, "\r\n\x00") || len(password) > 127 || strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("invalid synced account password request")
	}
	return withFileLock(lockPath(cfg.LockDir, username), func() error {
		if s.store == nil {
			return errors.New("cannot verify synced account without database")
		}
		eligible, err := db.SyncedPasswordResetAllowed(context.Background(), s.store, values["source_slug"], values["account_id"], username)
		if err != nil {
			return fmt.Errorf("verify synced account: %w", err)
		}
		if !eligible {
			return errors.New("account is not an active synced account of this identity source")
		}
		if _, found, err := browserLeaseForUser(cfg, username); err != nil {
			return err
		} else if found {
			return errBrowserLoginInProgress
		}
		return withFileLock(cfg.ShadowLockPath, func() error {
			return applyPermanentPassword(cfg, values)
		})
	})
}
