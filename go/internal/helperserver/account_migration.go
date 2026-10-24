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
func migrateInstalledAccounts(cfg config.HelperConfig) (enrollmentMigrationResult, error) {
	if os.Geteuid() != 0 || !cfg.Privileged {
		return enrollmentMigrationResult{}, errors.New("account migration requires the root installer")
	}
	return migrateAccountPolicy(cfg, func() (*db.HelperEnrollmentSnapshot, error) {
		result, err := queryHelperAsPackage(cfg, db.HelperAuthorizationQuery{
			Action: "enrollment_snapshot", DatabasePath: strings.TrimPrefix(cfg.DatabaseURL, "sqlite://"),
		})
		return result.Enrollment, err
	})
}

func migrateAccountPolicy(cfg config.HelperConfig, candidates func() (*db.HelperEnrollmentSnapshot, error)) (enrollmentMigrationResult, error) {
	var result enrollmentMigrationResult
	err := withFileLock(cfg.ShadowLockPath, func() error {
		policy, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		if policy.LegacyMigrationComplete {
			result.AlreadyComplete = true
			return nil
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
		groups, err := systemAccounts(cfg.GroupPath, true)
		if err != nil {
			return err
		}
		if _, ok := groups["administrators"]; !ok {
			return errors.New("cannot determine DSM administrator membership")
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
			group, err := normalGroup(cfg, name)
			if err != nil {
				log.Printf("automatic enrollment skipped group %q: %v", name, err)
				result.Skipped++
				continue
			}
			policy.Groups[name] = group.id
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
