package helperserver

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestEnrollmentSnapshotOnlyIncludesActiveExistingMappings(t *testing.T) {
	for _, tc := range []struct {
		name, change  string
		users, groups bool
	}{
		{"normal", "", true, true},
		{"manually_named", "UPDATE dsm_accounts SET managed=0; UPDATE dsm_groups SET managed=0", true, true},
		{"created", "UPDATE dsm_accounts SET provision_status='created'", true, true},
		{"pending_user", "UPDATE dsm_accounts SET provision_status='pending'", false, true},
		{"conflicted_user", "UPDATE dsm_accounts SET provision_status='conflict'", false, true},
		{"inactive_identity", "UPDATE app_identities SET status='disabled'", false, true},
		{"inactive_external", "UPDATE external_accounts SET active=0", false, true},
		{"wrong_identity", "UPDATE external_accounts SET app_identity_id='other'", false, true},
		{"wrong_source", "UPDATE external_accounts SET provider_slug='other'", false, true},
		{"missing_mapping", "DELETE FROM dsm_mapping_entries", false, false},
		{"inactive_mapping", "UPDATE dsm_mapping_entries SET active=0", false, false},
		{"source_disabled", "UPDATE identity_sources SET enabled=0", false, false},
		{"source_inactive", "UPDATE identity_sources SET directory_sync_enabled=0,login_enabled=0", false, false},
		{"login_only", "UPDATE identity_sources SET directory_sync_enabled=0", true, false},
		{"sync_only", "UPDATE identity_sources SET login_enabled=0", true, true},
		{"login_denied_keeps_sync_scope", "UPDATE dsm_accounts SET allow_login=0", true, true},
		{"inactive_department", "UPDATE provider_groups SET active=0", true, false},
		{"wrong_department_source", "UPDATE provider_groups SET provider_slug='other'", true, false},
		{"pending_group", "UPDATE dsm_groups SET provision_status='pending'", true, false},
		{"empty", "DELETE FROM dsm_accounts; DELETE FROM dsm_groups", false, false},
		{"duplicate_mapping", `INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id) VALUES ('second','source','second','second','user','identity');
INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,dsm_account_id) VALUES ('second','user','source','second','account')`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := syncedPasswordTestStore(t, "alice")
			if _, err := q.DBTX().ExecContext(context.Background(), `
INSERT INTO provider_groups(id,provider_slug,subject,subject_norm,name) VALUES ('department','source','department','department','Engineering');
INSERT INTO dsm_groups(id,dsm_groupname,dsm_groupname_norm,provision_status) VALUES ('group','engineering','engineering','created');
INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,provider_group_id,dsm_group_id) VALUES ('group','group','source','department','group');`); err != nil {
				t.Fatal(err)
			}
			if tc.change != "" {
				if _, err := q.DBTX().ExecContext(context.Background(), tc.change); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := db.HelperEnrollmentCandidates(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			want := &db.HelperEnrollmentSnapshot{Users: []string{}, Groups: []string{}}
			if tc.users {
				want.Users = []string{"alice"}
			}
			if tc.groups {
				want.Groups = []string{"engineering"}
			}
			if !reflect.DeepEqual(snapshot, want) {
				t.Fatalf("got %+v want %+v", snapshot, want)
			}
		})
	}
	if _, err := db.HelperEnrollmentCandidates(context.Background(), nil); err == nil {
		t.Fatal("nil database accepted")
	}
}

func TestAccountMigrationPreservesPasswordsAndRejectsPrivilegedTargets(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		cfg := policyTestConfig(t)
		cfg.ShadowPath = cfg.PasswdPath + ".shadow"
		writeFile(t, cfg.ShadowPath, "unchanged password fixture")
		users := []string{"bob", "alice", "alice", "operator", "root", "service", "missing", "-invalid"}
		if reverse {
			for i, j := 0, len(users)-1; i < j; i, j = i+1, j-1 {
				users[i], users[j] = users[j], users[i]
			}
		}
		result, err := migrateAccountPolicy(cfg, func() (*db.HelperEnrollmentSnapshot, error) {
			return &db.HelperEnrollmentSnapshot{Users: users, Groups: []string{"engineering", "engineering", "administrators", "users"}}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Users != 2 || result.Groups != 1 || result.Skipped != 7 {
			t.Fatalf("unexpected migration: %+v", result)
		}
		p, err := readAccountPolicy(cfg)
		if err != nil || !p.LegacyMigrationComplete || !reflect.DeepEqual(p.Users, map[string]int{"alice": 1026, "bob": 1027}) || !reflect.DeepEqual(p.Groups, map[string]int{"engineering": 65536}) {
			t.Fatalf("unexpected policy: %+v %v", p, err)
		}
		data, err := os.ReadFile(cfg.ShadowPath)
		if err != nil || string(data) != "unchanged password fixture" {
			t.Fatal("migration changed password state")
		}
	}
}

func TestAccountMigrationNeverRepeatsAfterRevocationOrNewMappings(t *testing.T) {
	cfg := policyTestConfig(t)
	first := func() (*db.HelperEnrollmentSnapshot, error) {
		return &db.HelperEnrollmentSnapshot{Users: []string{"alice"}, Groups: []string{"engineering"}}, nil
	}
	if _, err := migrateAccountPolicy(cfg, first); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "engineering", true, true); err != nil {
		t.Fatal(err)
	}
	result, err := migrateAccountPolicy(cfg, func() (*db.HelperEnrollmentSnapshot, error) {
		t.Fatal("completed migration queried mutable database again")
		return nil, nil
	})
	if err != nil || !result.AlreadyComplete {
		t.Fatalf("migration repeated: %+v %v", result, err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := requireManagedUser(cfg, name); err == nil {
			t.Fatalf("unapproved user %s granted", name)
		}
	}
	if err := requireManagedGroup(cfg, "engineering"); err == nil {
		t.Fatal("revoked group restored")
	}
}

func TestAccountMigrationKeepsExistingUIDBindings(t *testing.T) {
	cfg := policyTestConfig(t)
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, strings.Replace(string(data), "alice:x:1026:", "alice:x:1030:", 1))
	_, err = migrateAccountPolicy(cfg, func() (*db.HelperEnrollmentSnapshot, error) {
		return &db.HelperEnrollmentSnapshot{Users: []string{"alice", "bob"}, Groups: []string{}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireManagedUser(cfg, "alice"); err == nil {
		t.Fatal("migration rebound recreated account")
	}
	if err := requireManagedUser(cfg, "bob"); err != nil {
		t.Fatal(err)
	}
}

func TestAccountMigrationFailureDoesNotPersistPartialGrants(t *testing.T) {
	for _, failure := range []string{"query", "missing_snapshot", "incomplete_snapshot", "bad_passwd", "missing_admins", "oversized_snapshot"} {
		t.Run(failure, func(t *testing.T) {
			cfg := policyTestConfig(t)
			if err := updateAccountPolicy(cfg, "bob", false, false); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(cfg.AccountPolicyPath)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "bad_passwd" {
				writeFile(t, cfg.PasswdPath, "broken")
			}
			if failure == "missing_admins" {
				writeFile(t, cfg.GroupPath, "users:x:100:alice\n")
			}
			_, err = migrateAccountPolicy(cfg, func() (*db.HelperEnrollmentSnapshot, error) {
				switch failure {
				case "query":
					return nil, errors.New("database unavailable")
				case "missing_snapshot":
					return nil, nil
				case "incomplete_snapshot":
					return &db.HelperEnrollmentSnapshot{}, nil
				case "oversized_snapshot":
					return &db.HelperEnrollmentSnapshot{Users: make([]string, 10001), Groups: []string{}}, nil
				}
				return &db.HelperEnrollmentSnapshot{Users: []string{"alice"}, Groups: []string{}}, nil
			})
			if err == nil {
				t.Fatal("invalid migration succeeded")
			}
			after, readErr := os.ReadFile(cfg.AccountPolicyPath)
			if readErr != nil || string(before) != string(after) {
				t.Fatal("failed migration changed policy")
			}
		})
	}
}

func TestAccountMigrationEmptySnapshotAndConcurrentAttempts(t *testing.T) {
	cfg := policyTestConfig(t)
	var queries atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := migrateAccountPolicy(cfg, func() (*db.HelperEnrollmentSnapshot, error) {
				queries.Add(1)
				return &db.HelperEnrollmentSnapshot{Users: []string{}, Groups: []string{}}, nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if queries.Load() != 1 {
		t.Fatalf("migration queried database %d times", queries.Load())
	}
	if _, err := migrateInstalledAccounts(cfg); err == nil {
		t.Fatal("nonprivileged configuration allowed production migration")
	}
}
