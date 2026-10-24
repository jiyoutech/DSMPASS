package helperserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

// This authority is independent of the package database and HMAC secret.
// Existing DSM accounts are enrolled by the root install migration or an
// explicit root action; package RPCs cannot extend this authority.
type accountPolicy struct {
	Users                   map[string]int `json:"users"`
	Groups                  map[string]int `json:"groups"`
	LegacyMigrationComplete bool           `json:"legacy_migration_complete,omitempty"`
}

type systemAccount struct {
	name    string
	id, gid int
	members []string
}

func systemAccounts(path string, group bool) (map[string]systemAccount, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]systemAccount{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Split(line, ":")
		count := 7
		if group {
			count = 4
		}
		if len(fields) != count || fields[0] == "" {
			return nil, errors.New("invalid system account database")
		}
		id, err := strconv.Atoi(fields[2])
		if err != nil || id < 0 {
			return nil, errors.New("invalid system account ID")
		}
		if _, ok := result[fields[0]]; ok {
			return nil, errors.New("duplicate system account name")
		}
		a := systemAccount{name: fields[0], id: id}
		if group {
			a.members = strings.Split(fields[3], ",")
		} else {
			a.gid, err = strconv.Atoi(fields[3])
			if err != nil || a.gid < 0 {
				return nil, errors.New("invalid system account group")
			}
		}
		result[a.name] = a
	}
	return result, nil
}

func normalUser(cfg config.HelperConfig, username string) (systemAccount, error) {
	if err := assertAllowed(cfg, username); err != nil {
		return systemAccount{}, err
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return systemAccount{}, err
	}
	a, ok := users[username]
	if !ok {
		return a, os.ErrNotExist
	}
	if a.id < 1024 || a.gid == 0 {
		return a, errors.New("system or privileged account is forbidden")
	}
	for name, other := range users {
		if name != username && other.id == a.id {
			return a, errors.New("ambiguous target account UID")
		}
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return a, err
	}
	admins, ok := groups["administrators"]
	if !ok {
		return a, errors.New("cannot determine DSM administrator membership")
	}
	if a.gid == admins.id {
		return a, errors.New("DSM administrator account is forbidden")
	}
	for _, group := range groups {
		if group.id != 0 && group.id != admins.id {
			continue
		}
		for _, member := range group.members {
			if member == username {
				return a, errors.New("DSM administrator account is forbidden")
			}
		}
	}
	return a, nil
}

func normalGroup(cfg config.HelperConfig, name string) (systemAccount, error) {
	if err := assertAllowedGroup(name); err != nil {
		return systemAccount{}, err
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return systemAccount{}, err
	}
	a, ok := groups[name]
	if !ok {
		return a, os.ErrNotExist
	}
	if a.id < 1024 {
		return a, errors.New("system group is forbidden")
	}
	for otherName, other := range groups {
		if otherName != name && other.id == a.id {
			return a, errors.New("ambiguous target group GID")
		}
	}
	return a, nil
}

func readAccountPolicy(cfg config.HelperConfig) (accountPolicy, error) {
	policy := accountPolicy{Users: map[string]int{}, Groups: map[string]int{}}
	if cfg.Privileged {
		if err := securefs.CheckRootPath(filepath.Dir(cfg.AccountPolicyPath)); err != nil {
			return policy, err
		}
	}
	info, err := os.Lstat(cfg.AccountPolicyPath)
	if os.IsNotExist(err) {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return policy, errors.New("account policy must be a private regular file")
	}
	if cfg.Privileged {
		if err := securefs.CheckRootPath(cfg.AccountPolicyPath); err != nil {
			return policy, err
		}
	}
	data, err := os.ReadFile(cfg.AccountPolicyPath)
	if err != nil {
		return policy, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&policy); err != nil {
		return policy, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return policy, errors.New("invalid trailing policy data")
	}
	if policy.Users == nil || policy.Groups == nil {
		return policy, errors.New("invalid account policy")
	}
	return policy, nil
}

func requireManagedUser(cfg config.HelperConfig, username string) error {
	if cfg.AccountPolicyPath == "" && !cfg.Privileged {
		return nil
	} // Isolated legacy tests only; production configuration always sets a policy.
	a, err := normalUser(cfg, username)
	if err != nil {
		return err
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	if id, ok := p.Users[username]; !ok || id != a.id {
		return errors.New("DSM account requires root authorization or its UID has changed")
	}
	return nil
}

func requireManagedGroup(cfg config.HelperConfig, name string) error {
	if cfg.AccountPolicyPath == "" && !cfg.Privileged {
		return nil
	}
	a, err := normalGroup(cfg, name)
	if err != nil {
		return err
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	if id, ok := p.Groups[name]; !ok || id != a.id {
		return errors.New("DSM group requires root authorization or its GID has changed")
	}
	return nil
}

// Call with the project writer lock held. Atomic replacement permits concurrent
// readers without granting the package account any write access to this policy.
func updateAccountPolicy(cfg config.HelperConfig, name string, group, revoke bool) error {
	if cfg.AccountPolicyPath == "" && !cfg.Privileged {
		return nil
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	entries := p.Users
	if group {
		entries = p.Groups
	}
	if revoke {
		delete(entries, name)
	} else {
		var a systemAccount
		if group {
			a, err = normalGroup(cfg, name)
		} else {
			a, err = normalUser(cfg, name)
		}
		if err != nil {
			return err
		}
		entries[name] = a.id
	}
	return saveAccountPolicy(cfg, p)
}

func saveAccountPolicy(cfg config.HelperConfig, p accountPolicy) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if cfg.Privileged {
		return securefs.WriteRootFile(cfg.AccountPolicyPath, data, 0600)
	}
	return os.WriteFile(cfg.AccountPolicyPath, data, 0600)
}

// ManageAccountPolicy is intentionally unavailable over the socket or sudo
// controller. Revoking a user also restores any outstanding temporary password.
func ManageAccountPolicy(cfg config.HelperConfig, action, name string) error {
	if os.Geteuid() != 0 || !cfg.Privileged {
		return errors.New("account enrollment requires a root administrator")
	}
	group := action == "authorize-group" || action == "revoke-group"
	revoke := action == "revoke-user" || action == "revoke-group"
	if action != "authorize-user" && action != "authorize-group" && !revoke {
		return errors.New("unsupported policy command")
	}
	if group {
		if err := assertAllowedGroup(name); err != nil {
			return err
		}
	} else if err := assertAllowed(cfg, name); err != nil {
		return err
	}
	apply := func() error {
		return withFileLock(cfg.ShadowLockPath, func() error { return updateAccountPolicy(cfg, name, group, revoke) })
	}
	if group {
		return apply()
	}
	return withFileLock(lockPath(cfg.LockDir, name), func() error {
		if err := apply(); err != nil {
			return err
		}
		if revoke {
			j, found, err := browserLeaseForUser(cfg, name)
			if err != nil {
				return err
			}
			if found {
				return restoreJournalUnderAccountLock(cfg, j, "authorization_revoked")
			}
		}
		return nil
	})
}

func verifyAccountAbsent(cfg config.HelperConfig, name string) error {
	if cfg.AccountPolicyPath == "" && !cfg.Privileged {
		return nil
	}
	accounts, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return err
	}
	if _, exists := accounts[name]; exists {
		return fmt.Errorf("existing DSM account %q cannot be adopted automatically", name)
	}
	return nil
}
