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
	// Case variants share an account lock. Acquire each distinct lock in order.
	slices.Sort(paths)
	return slices.Compact(paths)
}

func dsmUserNotFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && bytes.Contains(bytes.ToLower(exitErr.Stderr), []byte("synoerr=[0x1d00]"))
}

func (s *Server) createMissingUsers(ctx context.Context, cfg config.HelperConfig, rows []map[string]any, password string) (map[string]map[string]any, error) {
	if len(rows) < 2 || password == "" || cfg.AccountPolicyPath == "" || cfg.PasswdPath == "" || cfg.GroupPath == "" || cfg.JournalDir == "" || cfg.SynoUserPath == "" {
		return nil, nil
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return nil, err
	}
	var missing []newDSMUser
	for _, row := range rows {
		name := row["dsm_username"].(string)
		if _, exists := users[name]; !exists && assertAllowed(cfg, name) == nil {
			missing = append(missing, newDSMUser{name: name, display: row["display_name"].(string), email: row["email"].(string)})
		}
	}
	results := map[string]map[string]any{}
	if len(missing) < 2 {
		return results, nil
	}
	createdIDs := map[string]int{}
	// Release account locks as soon as this wave's successful UIDs are pinned.
	// Final readback checks those same UIDs and the current enrollment under the writer lock.
	for group := range slices.Chunk(missing, maxConcurrentUserCreates) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(group) < 2 {
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
				return s.createUsersUnderWriter(ctx, cfg, absent, password, results, createdIDs)
			})
		})
		if err != nil {
			return nil, err
		}
	}
	if len(createdIDs) == 0 {
		return results, nil
	}
	err = withFileLock(cfg.ShadowLockPath, func() error {
		local, err := systemAccounts(cfg.PasswdPath, false)
		if err != nil {
			return err
		}
		groups, err := systemAccounts(cfg.GroupPath, true)
		if err != nil {
			return err
		}
		policy, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		profiles, err := completeDSMProfiles(ctx, cfg.SynoWebAPIPath, local)
		if err != nil {
			return err
		}
		for _, row := range rows {
			name := row["dsm_username"].(string)
			id, created := createdIDs[name]
			if !created {
				continue
			}
			user := local[name]
			p, ok := profiles[name]
			grant, err := enrolledLocalUser(policy, name, local, groups)
			if err != nil || grant != nil || !ok || user.id != id || !p.matches(user, row) {
				results[name] = errorResponse("DSM_PROFILE_UNCONFIRMED", "DSM did not confirm the new account UID and profile")
				continue
			}
			// A password reset may have completed since this wave released its locks.
			reset, err := loadPasswordReset(cfg, name)
			initial := os.IsNotExist(err) || (err == nil && reset.Status == "completed" && reset.PasswordDigest == lineHash(password))
			results[name] = map[string]any{"success": true, "created": true, "initial_password_applied": initial}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

func (s *Server) createUsersUnderWriter(ctx context.Context, cfg config.HelperConfig, users []newDSMUser, password string, results map[string]map[string]any, createdIDs map[string]int) error {
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
			errs[i] = createNativeUser(cfg, u, password)
		})
	}
	workers.Wait()
	for i, u := range eligible {
		errs[i] = s.retryAbsentCreate(ctx, cfg, u, password, errs[i])
		if errs[i] == nil {
			// Only this goroutine updates the shared policy. confirm binds the
			// actual ordinary UID and rejects missing, privileged or duplicate UIDs.
			var id int
			id, errs[i] = (creationTarget{cfg: cfg, name: u.name}).confirmID()
			if errs[i] == nil && cfg.SynoWebAPIPath != "" {
				createdIDs[u.name] = id
				continue
			}
		}
		if errs[i] == nil {
			info, err := getSynoUser(cfg.SynoUserPath, u.name)
			if err != nil || info.Expired || (u.display != "" && info.FullName != u.display) || (u.email != "" && info.Mail != u.email) {
				errs[i] = errors.New("DSM did not confirm the new account profile")
			}
		}
		if errs[i] != nil {
			results[u.name] = errorResponse("SYNOUSER_FAILED", errs[i].Error())
			continue
		}
		results[u.name] = map[string]any{"success": true, "created": true, "initial_password_applied": checkPasswordResetPending(cfg, u.name) == nil}
	}
	return nil
}

func createNativeUser(cfg config.HelperConfig, u newDSMUser, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return runAccountCommand(ctx, cfg.SynoUserPath, synouserAddArgs(u.name, password, u.display, u.email)...)
}

// Synology also returns 255 for permanent failures. The exit code alone never
// authorizes a retry. Inconclusive queries and partially created accounts retain
// the pending ownership receipt.
func commandExited255(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 255
}

// Called under the account and writer locks, after all native jobs in this wave have exited.
func (s *Server) retryAbsentCreate(ctx context.Context, cfg config.HelperConfig, user newDSMUser, password string, err error) error {
	if !commandExited255(err) || ctx.Err() != nil || !s.canRetryAbsentCreate(cfg, user.name) {
		return err
	}
	err = createNativeUser(cfg, user, password)
	if commandExited255(err) && s.canRetryAbsentCreate(cfg, user.name) {
		return errors.Join(err, (creationTarget{cfg: cfg, name: user.name}).clear())
	}
	return err
}

func (s *Server) canRetryAbsentCreate(cfg config.HelperConfig, name string) bool {
	if _, err := getSynoUser(cfg.SynoUserPath, name); !dsmUserNotFound(err) {
		return false
	}
	if err := verifyAccountAbsent(cfg, name); err != nil {
		return false
	}
	return s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "provision", Username: name}) == nil
}
