package helperserver

import (
	"errors"
	"log"
	"os"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

type enrollmentMigrationResult struct {
	Users, Groups, Skipped int
	AlreadyComplete        bool
}

// Called only by the root installer while the Helper instance lock is held.
// Neither normal startup nor an authenticated socket request can run migration.
func migrateInstalledAccounts(cfg config.HelperConfig, reuseExisting bool) (enrollmentMigrationResult, error) {
	if os.Geteuid() != 0 || !cfg.Privileged {
		return enrollmentMigrationResult{}, errors.New("account migration requires the root installer")
	}
	return migrateAccountPolicy(cfg, reuseExisting, func() (*db.HelperEnrollmentSnapshot, error) {
		result, err := queryHelperAsPackage(cfg, db.HelperAuthorizationQuery{
			Action: "enrollment_snapshot", DatabasePath: strings.TrimPrefix(cfg.DatabaseURL, "sqlite://"),
		})
		return result.Enrollment, err
	})
}

func migrateAccountPolicy(cfg config.HelperConfig, reuseExisting bool, candidates func() (*db.HelperEnrollmentSnapshot, error)) (enrollmentMigrationResult, error) {
	var result enrollmentMigrationResult
	err := withFileLock(cfg.ShadowLockPath, func() error {
		policy, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		result.AlreadyComplete = policy.LegacyMigrationComplete
		if policy.LegacyMigrationComplete && (!reuseExisting || policy.ReusableGroups != nil) {
			return nil
		}
		groups, err := systemAccounts(cfg.GroupPath, true)
		if err != nil {
			return err
		}
		if _, ok := groups["administrators"]; !ok {
			return errors.New("cannot determine DSM administrator membership")
		}
		policy.ReusableGroups = reusableLocalGroups(groups, policy.Groups)
		if policy.LegacyMigrationComplete {
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
		if group.id < 65536 || group.id > 95536 || counts[group.id] != 1 || assertAllowedGroup(name) != nil {
			continue
		}
		if _, exists := enrolled[name]; exists {
			continue
		}
		switch strings.ToLower(name) {
		case "users", "http", "docker", "lxd", "incus-admin", "sudo", "wheel", "disk", "libvirt":
			continue
		}
		reusable[name] = group.id
	}
	return reusable
}
