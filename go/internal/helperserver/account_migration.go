package helperserver

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

// LegacyGroupReview selects which existing name/GID bindings may be reused.
// A nil result defers the decision; a non-nil empty map confirms an empty scope.
type LegacyGroupReview func(map[string]int) (map[string]int, error)

type enrollmentMigrationResult struct {
	Users, DirectoryUsers, UpdatedDirectoryUsers, Groups, Skipped int
	AlreadyComplete                                               bool
	ReviewedGroupCount                                            *int
}

// Called only by the root installer while the Helper instance lock is held.
// Neither normal startup nor an authenticated socket request can run migration.
func migrateInstalledAccounts(cfg config.HelperConfig, review LegacyGroupReview) (enrollmentMigrationResult, error) {
	if os.Geteuid() != 0 || !cfg.Privileged {
		return enrollmentMigrationResult{}, errors.New("account migration requires the root installer")
	}
	return migrateAccountPolicy(cfg, review, func() (*db.HelperEnrollmentSnapshot, error) {
		result, err := queryHelperAsPackage(cfg, db.HelperAuthorizationQuery{
			Action: "enrollment_snapshot", DatabasePath: strings.TrimPrefix(cfg.DatabaseURL, "sqlite://"),
		})
		return result.Enrollment, err
	})
}

func migrateAccountPolicy(cfg config.HelperConfig, review LegacyGroupReview, candidates func() (*db.HelperEnrollmentSnapshot, error)) (enrollmentMigrationResult, error) {
	var result enrollmentMigrationResult
	err := withFileLock(cfg.ShadowLockPath, func() error {
		policy, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		result.AlreadyComplete = policy.LegacyMigrationComplete
		groups, err := systemAccounts(cfg.GroupPath, true)
		if err != nil {
			return err
		}
		if _, ok := groups["administrators"]; !ok {
			return errors.New("cannot determine DSM administrator membership")
		}
		if policy.ReusableGroups == nil {
			eligible := reusableLocalGroups(groups, policy.Groups)
			_, err := os.Lstat(cfg.AccountPolicyPath)
			switch {
			case os.IsNotExist(err):
				policy.ReusableGroups = eligible
			case err != nil:
				return err
			case review != nil:
				approved, err := review(maps.Clone(eligible))
				if err != nil {
					return err
				}
				for name, gid := range approved {
					if expected, ok := eligible[name]; !ok || expected != gid {
						return errors.New("reviewed group is outside the eligible migration scope")
					}
					delete(policy.WebApprovals, name)
				}
				if approved != nil {
					count := len(approved)
					result.ReviewedGroupCount = &count
				}
				policy.ReusableGroups = approved
			}
		}
		snapshot, err := candidates()
		if err != nil {
			return err
		}
		if snapshot == nil || snapshot.Users == nil || snapshot.Groups == nil || len(snapshot.Users)+len(snapshot.RetryUsers)+len(snapshot.Groups) > 10000 {
			return errors.New("invalid enrollment snapshot")
		}
		users, err := systemAccounts(cfg.PasswdPath, false)
		if err != nil {
			return err
		}
		if policy.DirectoryUsers == nil {
			policy.DirectoryUsers = make(map[string]directoryUserGrant)
		}
		verifiedChanged := captureVerifiedDirectory(cfg, &policy, snapshot.VerifiedEmails, users, groups)
		// Only this explicit root action may add existing users. Keep the UID
		// from the system snapshot so a concurrent replacement cannot inherit it.
		for _, name := range snapshot.Users {
			enrollMappedUser(cfg, policy, users, groups, name, "", false, snapshot, &result)
		}
		for name, email := range snapshot.RetryUsers {
			enrollMappedUser(cfg, policy, users, groups, name, email, true, snapshot, &result)
		}
		// Accounts enrolled by this trusted installation already passed the legacy
		// ownership checks. Keep their verified source and subject for later operations.
		for name, candidate := range policy.CredentialCandidates {
			if id, ok := policy.Users[name]; ok && id == candidate.UID {
				if policy.CredentialOwners == nil {
					policy.CredentialOwners = map[string]db.CredentialIdentity{}
				}
				policy.CredentialOwners[name] = candidate.Owner
				delete(policy.CredentialCandidates, name)
				verifiedChanged = true
			}
		}
		for name, binding := range snapshot.DingTalkUsers {
			grant, exists := policy.DirectoryUsers[name]
			if !exists || grant.DingTalk != nil || grant.UID != users[name].id {
				continue
			}
			grant.DingTalk = &binding
			policy.DirectoryUsers[name] = grant
			result.UpdatedDirectoryUsers++
		}
		scopeChanged := captureDingTalkDirectory(cfg, &policy, snapshot.DingTalkSources, users, groups)

		if policy.LegacyMigrationComplete {
			if !verifiedChanged && result.Users == 0 && result.DirectoryUsers == 0 && result.UpdatedDirectoryUsers == 0 && result.ReviewedGroupCount == nil && !scopeChanged {
				return nil
			}
			return saveAccountPolicy(cfg, policy)
		}
		for _, name := range snapshot.Groups {
			if _, exists := policy.Groups[name]; exists {
				continue
			}
			gid, ok := policy.ReusableGroups[name]
			if !ok {
				log.Printf("automatic enrollment skipped group %q outside eligible local groups", name)
				result.Skipped++
				continue
			}
			policy.Groups[name] = gid
			delete(policy.ReusableGroups, name)
			result.Groups++
		}
		// Grants and the completion marker share one atomic replacement. A
		// failed query/write cannot leave a partially applied migration.
		policy.LegacyMigrationComplete = true
		return saveAccountPolicy(cfg, policy)
	})
	if err != nil {
		return enrollmentMigrationResult{}, err
	}
	return result, nil
}

func enrollMappedUser(cfg config.HelperConfig, policy accountPolicy, users, groups map[string]systemAccount, name, email string, retry bool, snapshot *db.HelperEnrollmentSnapshot, result *enrollmentMigrationResult) {
	skip := func(reason error) {
		log.Printf("跳过 DSM 用户 %q：%v", name, reason)
		result.Skipped++
	}
	if err := assertAllowed(cfg, name); err != nil {
		skip(err)
		return
	}
	account, err := normalLocalUser(name, users, groups)
	if err != nil {
		skip(err)
		return
	}
	if id, bound := policy.Users[name]; bound {
		switch {
		case id == revokedUserID:
			skip(errors.New("授权已撤销"))
		case id != account.id:
			skip(fmt.Errorf("原 UID %d，当前 UID %d", id, account.id))
		}
		return
	}
	if policy.DingTalkScope != nil {
		if pinned, found := policy.DingTalkScope.Users[name]; found && pinned != account.id {
			skip(fmt.Errorf("原 UID %d，当前 UID %d", pinned, account.id))
			return
		}
	}
	if !ordinaryInstallUser(account, groups) {
		skip(errors.New("不属于可自动登记的普通本地用户"))
		return
	}
	// A successful directory-only reconciliation also produces a success log.
	// That log can never promote an existing directory grant to password access.
	if grant, exists := policy.DirectoryUsers[name]; exists {
		if grant.UID != account.id {
			skip(fmt.Errorf("原 UID %d，当前 UID %d", grant.UID, account.id))
			return
		}
		if pinDirectoryDepartments(&grant, policy, groups, snapshot.Departments[name]) {
			policy.DirectoryUsers[name] = grant
			result.UpdatedDirectoryUsers++
		}
		return
	}
	if candidate, ok := policy.CredentialCandidates[name]; ok {
		if candidate.UID != account.id || snapshot.VerifiedEmails[candidate.Email] != candidate.Owner {
			skip(errors.New("原有 DSM UID 或已核实的来源身份已变化"))
			return
		}
		// A previous success may have confirmed membership only. Check native mail
		// before activating a credential binding for an existing account.
		retry, email = true, candidate.Email
	}
	target := creationTarget{cfg: cfg, name: name}
	id, found, err := target.receiptID()
	switch {
	case err != nil:
		skip(err)
		return
	case found && id != account.id:
		skip(fmt.Errorf("创建凭据 UID %d 与当前 UID %d 不符", id, account.id))
		return
	case retry && !found:
		info, err := getSynoUser(cfg.SynoUserPath, name)
		if err != nil {
			skip(fmt.Errorf("读取 DSM 账号资料失败: %w", err))
			return
		}
		mail := strings.TrimSpace(info.Mail)
		if info.Expired || (mail != "" && email != "" && !strings.EqualFold(mail, email)) {
			skip(errors.New("DSM 账号已停用或邮箱与通讯录不匹配"))
			return
		}
		if mail == "" || email == "" {
			grant := directoryUserGrant{UID: account.id}
			pinDirectoryDepartments(&grant, policy, groups, snapshot.Departments[name])
			policy.DirectoryUsers[name] = grant
			result.DirectoryUsers++
			return
		}
	}
	policy.Users[name] = account.id
	result.Users++
}

func pinDirectoryDepartments(grant *directoryUserGrant, policy accountPolicy, groups map[string]systemAccount, departments []string) bool {
	changed := false
	for _, name := range departments {
		if _, fixed := grant.Groups[name]; fixed {
			continue
		}
		group, exists := groups[name]
		if !exists || !isLocalDirectoryGroup(name, group.id) || (policy.Groups[name] != group.id && policy.ReusableGroups[name] != group.id) {
			continue
		}
		if grant.Groups == nil {
			grant.Groups = make(map[string]int)
		}
		grant.Groups[name] = group.id
		changed = true
	}
	return changed
}

func ordinaryInstallUser(account systemAccount, groups map[string]systemAccount) bool {
	switch strings.ToLower(account.name) {
	case "guest", "nobody", "dsmpass":
		return false
	}
	local, ok := groups["users"]
	if !ok || account.gid != local.id || account.id >= 65536 {
		return false
	}
	for _, name := range []string{"docker", "lxd", "incus-admin", "sudo", "wheel", "disk", "libvirt"} {
		privileged, exists := groups[name]
		if !exists {
			continue
		}
		for _, group := range groups {
			if group.id == privileged.id && (group.id == account.gid || slices.Contains(group.members, account.name)) {
				return false
			}
		}
	}
	return true
}

// Only the root installer captures these names and GIDs. Runtime requests cannot
// add candidates. DSM reserves this range for locally created groups.
func reusableLocalGroups(groups map[string]systemAccount, enrolled map[string]int) map[string]int {
	counts := make(map[int]int, len(groups))
	for _, group := range groups {
		counts[group.id]++
	}
	reusable := make(map[string]int)
	for name, group := range groups {
		if counts[group.id] != 1 || !isLocalDirectoryGroup(name, group.id) {
			continue
		}
		if _, exists := enrolled[name]; exists {
			continue
		}
		reusable[name] = group.id
	}
	return reusable
}

func isLocalDirectoryGroup(name string, gid int) bool {
	if gid < 65536 || gid > 95536 || assertAllowedGroup(name) != nil {
		return false
	}
	switch strings.ToLower(name) {
	case "users", "http", "docker", "lxd", "incus-admin", "sudo", "wheel", "disk", "libvirt":
		return false
	}
	return true
}
