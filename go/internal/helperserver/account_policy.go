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
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

// This authority is independent of the package database and HMAC secret.
// Existing DSM accounts are enrolled by the root install migration or an
// explicit root action. The installer can also pin local groups for directory reuse.
type directoryUserGrant struct {
	DingTalk *db.DingTalkUserBinding `json:"dingtalk,omitempty"`
	UID      int                     `json:"uid"`
	Groups   map[string]int          `json:"groups,omitempty"`
}

type dingTalkDirectoryScope struct {
	Sources []string       `json:"sources"`
	Users   map[string]int `json:"users"`
}

type accountPolicy struct {
	DingTalkScope           *dingTalkDirectoryScope       `json:"dingtalk_scope,omitempty"`
	DirectoryUsers          map[string]directoryUserGrant `json:"directory_users,omitempty"`
	Users                   map[string]int                `json:"users"`
	Groups                  map[string]int                `json:"groups"`
	ReusableGroups          map[string]int                `json:"reusable_groups,omitzero"`
	WebApprovals            map[string]groupWebApproval   `json:"pending_web_group_approvals,omitempty"`
	LegacyMigrationComplete bool                          `json:"legacy_migration_complete,omitempty"`
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
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return systemAccount{}, err
	}
	return normalLocalUser(username, users, groups)
}

func normalLocalUser(username string, users, groups map[string]systemAccount) (systemAccount, error) {
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

// System UIDs are nonnegative. Older Helpers also deny this binding.
const revokedUserID = -1

var errUserNotEnrolled = errors.New("尚未登记")

var errDingTalkMembershipOnly = errors.New("钉钉同名用户仅获通讯录同步授权，保留 DSM/SMB 密码和账号状态")

func requireManagedUser(cfg config.HelperConfig, username string) error {
	grant, err := userEnrollment(cfg, username)
	if err == nil && grant != nil {
		if grant.DingTalk != nil {
			return fmt.Errorf("DSM 用户 %q: %w", username, errDingTalkMembershipOnly)
		}
		return fmt.Errorf("DSM 用户 %q 已获通讯录同步授权，登录、改密和停用需独立核实账号归属", username)
	}
	return err
}

func userEnrollment(cfg config.HelperConfig, username string) (*directoryUserGrant, error) {
	if cfg.AccountPolicyPath == "" && !cfg.Privileged {
		return nil, nil
	} // Isolated legacy tests only; production configuration always sets a policy.
	a, err := normalUser(cfg, username)
	if err != nil {
		return nil, err
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return nil, err
	}
	id, ok := p.Users[username]
	if !ok {
		if grant, found := p.DirectoryUsers[username]; found {
			if grant.UID != a.id {
				return nil, fmt.Errorf("DSM 用户 %q 的 UID 已从 %d 变为 %d", username, grant.UID, a.id)
			}
			if grant.DingTalk != nil {
				groups, err := systemAccounts(cfg.GroupPath, true)
				if err != nil {
					return nil, err
				}
				if !ordinaryInstallUser(a, groups) {
					return nil, errors.New("仅普通本地用户可按钉钉姓名关联")
				}
			}
			return &grant, nil
		}
		return nil, fmt.Errorf("DSM 用户 %q %w（当前 UID %d），请管理员运行 setup-helper-sudo.sh 批量核对当前映射", username, errUserNotEnrolled, a.id)
	}
	if id == revokedUserID {
		return nil, fmt.Errorf("DSM 用户 %q 的授权已撤销", username)
	}
	if id != a.id {
		return nil, fmt.Errorf("DSM 用户 %q 的 UID 已从 %d 变为 %d，请管理员核实是否为同一账号", username, id, a.id)
	}
	return nil, nil
}

func requireManagedGroup(cfg config.HelperConfig, name string) error {
	return checkGroupEnrollment(cfg, name, nil)
}

// A mapping lookup is supplied only for provisioning under the writer lock.
// Membership changes alone cannot claim a pre-existing group.
func checkGroupEnrollment(cfg config.HelperConfig, name string, mapped func() (bool, error)) error {
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
	id, enrolled := p.Groups[name]
	if _, pending := p.WebApprovals[name]; pending && mapped != nil && (!enrolled || id != a.id) {
		ok, err := mapped()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("DSM 群组 %q 没有有效的通讯录部门映射", name)
		}
		return acceptDSMGroupApproval(cfg, p, a)
	}
	if !enrolled {
		var captured bool
		id, captured = p.ReusableGroups[name]
		if !captured || mapped == nil {
			if mapped != nil && p.LegacyMigrationComplete && p.ReusableGroups == nil && isLocalDirectoryGroup(name, a.id) {
				return fmt.Errorf("DSM 群组 %q 未登记为可同步群组。旧安装尚未确认自动复用范围，请管理员运行 setup-helper-sudo.sh 自动登记，或在部门群组页面授权此组", name)
			}
			return fmt.Errorf("DSM 群组 %q 未登记为可同步群组，可到部门群组页面办理网页授权", name)
		}
	}
	if id != a.id {
		return fmt.Errorf("DSM 群组 %q 的编号已从 %d 变为 %d，请核对群组后在部门群组页面办理网页授权", name, id, a.id)
	}
	if enrolled {
		return nil
	}
	ok, err := mapped()
	if err != nil {
		return fmt.Errorf("核对 DSM 群组 %q 的部门映射失败: %w", name, err)
	}
	if !ok {
		return fmt.Errorf("DSM 群组 %q 没有有效的通讯录部门映射", name)
	}
	// DSM administrators can change local groups outside the Helper lock.
	current, err := normalGroup(cfg, name)
	if err != nil {
		return err
	}
	if current.id != id {
		return fmt.Errorf("DSM 群组 %q 的编号已从 %d 变为 %d，请核对群组后在部门群组页面办理网页授权", name, id, current.id)
	}
	p.Groups[name] = id
	delete(p.ReusableGroups, name)
	return saveAccountPolicy(cfg, p)
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
		delete(p.ReusableGroups, name)
		delete(p.WebApprovals, name)
	} else {
		delete(p.DirectoryUsers, name)
	}
	if err := (creationTarget{cfg: cfg, name: name, group: group}).clear(); err != nil {
		return err
	}
	if revoke {
		if group {
			delete(entries, name)
		} else {
			entries[name] = revokedUserID
		}
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
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	_, limited := p.DirectoryUsers[name]
	captured := false
	if p.DingTalkScope != nil {
		_, captured = p.DingTalkScope.Users[name]
	}
	if _, bound := p.Users[name]; bound || limited || captured {
		return fmt.Errorf("DSM 用户 %q 已有授权或撤销记录，请管理员核实后再重建", name)
	}
	return nil
}
