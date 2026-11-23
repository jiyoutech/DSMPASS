package helperserver

import (
	"errors"
	"log"
	"maps"
	"os"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

// LegacyGroupReview selects which existing name/GID bindings may be reused.
// A nil result defers the decision; a non-nil empty map confirms an empty scope.
type LegacyGroupReview func(map[string]int) (map[string]int, error)

type enrollmentMigrationResult struct {
	Users, Groups, Skipped int
	AlreadyComplete        bool
	ReviewedGroupCount     *int
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
		if policy.LegacyMigrationComplete && (review == nil || policy.ReusableGroups != nil) {
			return nil
		}
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
		if policy.LegacyMigrationComplete {
			if policy.ReusableGroups == nil {
				return nil
			}
			return saveAccountPolicy(cfg, policy)
		}
		snapshot, err := candidates()
		if err != nil {
			return err
		}
		if snapshot == nil || snapshot.Users == nil || snapshot.Groups == nil || len(snapshot.Users)+len(snapshot.Groups) > 10000 {
			return errors.New("invalid enrollment snapshot")
		}
		if _, err := systemAccounts(cfg.PasswdPath, false); err != nil {
			return err
		}
		for _, name := range snapshot.Users {
			if _, exists := policy.Users[name]; exists {
				// Preserve prior UID bindings, including a now-stale binding that
				// intentionally blocks a deleted/recreated account.
				continue
			}
			account, err := normalUser(cfg, name)
			if err != nil {
				log.Printf("automatic enrollment skipped user %q: %v", name, err)
				result.Skipped++
				continue
			}
			policy.Users[name] = account.id
			result.Users++
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
		// failed query/write cannot leave a partially applied migration. Later
		// reinstalls cannot re-enroll revoked accounts or new database mappings.
		policy.LegacyMigrationComplete = true
		return saveAccountPolicy(cfg, policy)
	})
	if err != nil {
		return enrollmentMigrationResult{}, err
	}
	return result, nil
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
