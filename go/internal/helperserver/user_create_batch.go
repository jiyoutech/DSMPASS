package helperserver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

// Limit concurrent native creates while retaining the Helper's writer lock.
// Each process creates exactly one new account and returns its own outcome.
const maxConcurrentUserCreates = 4

type newDSMUser struct {
	name, display, email string
}

func withUserCreateLocks(paths []string, fn func() error) error {
	if len(paths) == 0 {
		return fn()
	}
	return withFileLock(paths[0], func() error { return withUserCreateLocks(paths[1:], fn) })
}

func userCreateLockPaths(dir string, users []newDSMUser) []string {
	paths := make([]string, len(users))
	for i, u := range users {
		paths[i] = lockPath(dir, u.name)
	}
	// Several Unicode usernames may normalize to the same lock pathname.
	slices.Sort(paths)
	return slices.Compact(paths)
}

func dsmUserNotFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && bytes.Contains(bytes.ToLower(exitErr.Stderr), []byte("synoerr=[0x1d00]"))
}

func (s *Server) createMissingUsers(ctx context.Context, cfg config.HelperConfig, rows []map[string]any, password string) map[string]map[string]any {
	if len(rows) < 2 || password == "" || cfg.AccountPolicyPath == "" || cfg.PasswdPath == "" || cfg.GroupPath == "" || cfg.JournalDir == "" || cfg.SynoUserPath == "" {
		return nil
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return nil
	}
	var missing []newDSMUser
	for _, row := range rows {
		name := row["dsm_username"].(string)
		if _, exists := users[name]; !exists && assertAllowed(cfg, name) == nil {
			missing = append(missing, newDSMUser{name: name, display: row["display_name"].(string), email: row["email"].(string)})
		}
	}
	results := map[string]map[string]any{}
	for group := range slices.Chunk(missing, maxConcurrentUserCreates) {
		if len(group) < 2 || ctx.Err() != nil {
			break
		}
		err := withUserCreateLocks(userCreateLockPaths(cfg.LockDir, group), func() error {
			var absent []newDSMUser
			for _, u := range group {
				if _, err := getSynoUser(cfg.SynoUserPath, u.name); dsmUserNotFound(err) {
					absent = append(absent, u)
				}
			}
			if len(absent) < 2 {
				return nil
			}
			return withFileLock(cfg.ShadowLockPath, func() error {
				return s.createUsersUnderWriter(ctx, cfg, absent, password, results)
			})
		})
		if err != nil {
			// Attempted rows already have individual outcomes. Return to the
			// normal single-account path for all rows not yet submitted.
			break
		}
	}
	return results
}

func (s *Server) createUsersUnderWriter(ctx context.Context, cfg config.HelperConfig, users []newDSMUser, password string, results map[string]map[string]any) error {
	local, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return err
	}
	policy, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	var eligible []newDSMUser
	var names []string
	for _, u := range users {
		if _, found := local[u.name]; found {
			continue
		}
		if err := verifyNewAccountPolicy(policy, u.name); err != nil {
			continue
		}
		target := creationTarget{cfg: cfg, name: u.name}
		if _, err := os.Lstat(target.path()); !os.IsNotExist(err) {
			continue
		}
		if _, busy, err := browserLeaseForUser(cfg, u.name); err != nil || busy {
			continue
		}
		eligible = append(eligible, u)
		names = append(names, u.name)
	}
	if len(eligible) < 2 {
		return nil
	}
	allowed, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "provision_users", Usernames: names})
	if err != nil || !allowed {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	errs := make([]error, len(eligible))
	var workers sync.WaitGroup
	for i, u := range eligible {
		target := creationTarget{cfg: cfg, name: u.name}
		if errs[i] = target.begin(); errs[i] != nil {
			continue
		}
		workers.Go(func() {
			// Settle an already started native operation even if the socket closes.
			cmdCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			errs[i] = runAccountCommand(cmdCtx, cfg.SynoUserPath, synouserAddArgs(u.name, password, u.display, u.email)...)
		})
	}
	workers.Wait()
	var firstErr error
	for i, u := range eligible {
		if errs[i] == nil {
			// Only this goroutine updates the shared policy. confirm binds the
			// actual ordinary UID and rejects missing, privileged or duplicate UIDs.
			errs[i] = (creationTarget{cfg: cfg, name: u.name}).confirm()
		}
		if errs[i] == nil {
			info, err := getSynoUser(cfg.SynoUserPath, u.name)
			if err != nil || info.Expired || (u.display != "" && info.FullName != u.display) || (u.email != "" && info.Mail != u.email) {
				errs[i] = errors.New("DSM did not confirm the new account profile")
			}
		}
		if errs[i] != nil {
			results[u.name] = errorResponse("SYNOUSER_FAILED", errs[i].Error())
			if firstErr == nil {
				firstErr = errs[i]
			}
			continue
		}
		results[u.name] = map[string]any{"success": true, "created": true, "initial_password_applied": checkPasswordResetPending(cfg, u.name) == nil}
	}
	return firstErr
}
