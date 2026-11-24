package helperserver

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

func passwordResetValues(payload map[string]any) (map[string]string, error) {
	values := make(map[string]string)
	for _, key := range []string{"request_id", "source_slug", "account_id", "dsm_username", "password"} {
		value, err := requiredString(payload, key)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	password := values["password"]
	if len(password) > 127 || strings.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("invalid synced account password request")
	}
	return values, nil
}

func (s *Server) resetSyncedUserPassword(cfg config.HelperConfig, payload map[string]any) error {
	values, err := passwordResetValues(payload)
	if err != nil {
		return err
	}
	if err := assertAllowed(cfg, values["dsm_username"]); err != nil {
		return err
	}
	return withFileLock(lockPath(cfg.LockDir, values["dsm_username"]), func() error {
		return withFileLock(cfg.ShadowLockPath, func() error { return s.resetPasswordUnderLocks(cfg, values) })
	})
}

// Both the account lock and the project writer lock are held on every path.
func (s *Server) resetPasswordUnderLocks(cfg config.HelperConfig, values map[string]string) error {
	name := values["dsm_username"]
	if _, busy, err := browserLeaseForUser(cfg, name); err != nil {
		return err
	} else if busy {
		return errBrowserLoginInProgress
	}
	if err := requireManagedUser(cfg, name); err != nil {
		return err
	}
	if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "password_reset", Username: name, SourceSlug: values["source_slug"], AccountID: values["account_id"]}); err != nil {
		return err
	}
	return applyPermanentPassword(cfg, values)
}

func (s *Server) resetSyncedPasswordBatch(ctx context.Context, cfg config.HelperConfig, payload map[string]any) map[string]any {
	raw, ok := payload["dsm_users"].([]any)
	requestID, err := requiredString(payload, "request_id")
	if !ok || len(raw) == 0 || len(raw) > helperclient.PasswordResetBatchSize || err != nil {
		return errorResponse("BAD_REQUEST", "invalid password reset batch")
	}
	byLock := map[string][]int{}
	names, ids := map[string]bool{}, map[string]bool{}
	values := make([]map[string]string, len(raw))
	failures := make([]error, len(raw))
	for i, item := range raw {
		row, ok := item.(map[string]any)
		if !ok {
			return errorResponse("BAD_REQUEST", "invalid password reset user")
		}
		v, err := passwordResetValues(map[string]any{
			"request_id": fmt.Sprintf("%s:%d", requestID, i), "source_slug": payload["source_slug"], "password": payload["password"],
			"account_id": row["account_id"], "dsm_username": row["dsm_username"],
		})
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		name, id := strings.ToLower(v["dsm_username"]), v["account_id"]
		if names[name] || ids[id] {
			return errorResponse("BAD_REQUEST", "duplicate password reset target")
		}
		names[name], ids[id] = true, true
		values[i] = v
		if err := assertAllowed(cfg, v["dsm_username"]); err != nil {
			failures[i] = err
			continue
		}
		path := lockPath(cfg.LockDir, v["dsm_username"])
		byLock[path] = append(byLock[path], i)
	}

	// Lock accounts in a stable order. A busy account must not block other rows.
	// Names sharing a normalized lock path run sequentially underneath that lock.
	paths := slices.Sorted(maps.Keys(byLock))
	var hold func(int)
	hold = func(i int) {
		if i < len(paths) {
			path := paths[i]
			if err := withFileLock(path, func() error { hold(i + 1); return nil }); err != nil {
				for _, index := range byLock[path] {
					failures[index] = err
				}
				hold(i + 1)
			}
			return
		}
		err := withFileLock(cfg.ShadowLockPath, func() error {
			var workers sync.WaitGroup
			for _, indexes := range byLock {
				if failures[indexes[0]] != nil {
					continue
				}
				workers.Go(func() {
					for _, index := range indexes {
						if err := ctx.Err(); err != nil {
							failures[index] = err
							continue
						}
						failures[index] = s.resetPasswordUnderLocks(cfg, values[index])
					}
				})
			}
			workers.Wait()
			return nil
		})
		if err != nil {
			for i := range failures {
				if failures[i] == nil {
					failures[i] = err
				}
			}
		}
	}
	hold(0)
	results := make([]map[string]any, len(values))
	for i, v := range values {
		row := map[string]any{"account_id": v["account_id"], "dsm_username": v["dsm_username"], "success": failures[i] == nil}
		if errors.Is(failures[i], errDingTalkMembershipOnly) {
			row["error_code"] = "DINGTALK_MEMBERSHIP_ONLY"
		} else if errors.Is(failures[i], errDirectoryMembershipOnly) {
			row["error_code"] = "DIRECTORY_MEMBERSHIP_ONLY"
		} else if failures[i] != nil {
			row["error_code"] = "SYNC_PASSWORD_RESET_FAILED"
			row["error"] = failures[i].Error()
		}
		results[i] = row
	}
	return map[string]any{"success": true, "user_results": results}
}
