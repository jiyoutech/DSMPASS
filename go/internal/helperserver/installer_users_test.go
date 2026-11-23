package helperserver

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestInstallerRetriesExistingMappedUser(t *testing.T) {
	const mail = "UPDATE external_accounts SET email_norm='alice@example.test', email_verified=1;"
	const success = `INSERT INTO sync_runs(id,source_slug,status) VALUES ('run','source','success');
INSERT INTO sync_operation_logs(id,sync_run_id,source_slug,object_type,object_key,dsm_name,action,status,after_state)
VALUES ('log','run','source','user','account','alice','create_or_update','success','linked_existing');`
	for _, tc := range []struct {
		name, sql, receipt, native string
		want                       bool
	}{
		{name: "previously synchronized", sql: success, want: true},
		{name: "dry run is not proof", sql: success + "UPDATE sync_runs SET dry_run=1"},
		{name: "success for other account", sql: success + "UPDATE sync_operation_logs SET object_key='other'"},
		{name: "success before mapping", sql: success + "UPDATE sync_operation_logs SET created_at='2001-01-01'"},
		{name: "root creation receipt", receipt: "1026", want: true},
		{name: "different receipt UID", receipt: "1090", sql: success},
		{name: "incomplete receipt", receipt: "-1", sql: success},
		{name: "matching independent mail", sql: mail, native: "User Mail : [ALICE@example.test]", want: true},
		{name: "pending matching mail", sql: mail + "UPDATE dsm_accounts SET provision_status='pending'", native: "User Mail : [alice@example.test]", want: true},
		{name: "inactive DSM account", sql: mail, native: "User Mail : [alice@example.test]\nExpired : [true]"},
		{name: "different mail", sql: mail, native: "User Mail : [other@example.test]"},
		{name: "unverified mail", sql: mail + "UPDATE external_accounts SET email_verified=0", native: "User Mail : [alice@example.test]"},
		{name: "shared mail", sql: mail + `INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id,email_norm,active) VALUES ('other','source','other','other','user','other','alice@example.test',1)`, native: "User Mail : [alice@example.test]"},
		{name: "no proof"},
		{name: "inactive mapping", sql: success + "UPDATE dsm_mapping_entries SET active=0"},
		{name: "conflicting identity", sql: success + "UPDATE dsm_accounts SET conflict_reason='unresolved'"},
		{name: "inactive source", sql: success + "UPDATE identity_sources SET directory_sync_enabled=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policyTestConfig(t)
			if _, err := migrateAccountPolicy(cfg, nil, emptyDirectorySnapshot); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			_, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_accounts SET provision_status='failed';"+tc.sql)
			if err != nil {
				t.Fatal(err)
			}
			if tc.receipt != "" {
				if err := os.WriteFile((creationTarget{cfg: cfg, name: "alice"}).path(), []byte(tc.receipt), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg.SynoUserPath = cfg.PasswdPath + ".synouser"
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] && [ \"$2\" = alice ] || exit 1\nprintf '%s\\n' '"+tc.native+"'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			candidates := func() (*db.HelperEnrollmentSnapshot, error) {
				return db.HelperEnrollmentCandidates(context.Background(), q)
			}
			for i := 0; i < 2; i++ {
				result, err := migrateAccountPolicy(cfg, nil, candidates)
				if err != nil {
					t.Fatal(err)
				}
				if (result.Users == 1) != (i == 0 && tc.want) {
					t.Fatalf("run %d: %+v", i, result)
				}
				if err := requireManagedUser(cfg, "alice"); (err == nil) != tc.want {
					t.Fatalf("grant: %v", err)
				}
			}
			if tc.want {
				server := NewWithStore(cfg, q)
				if r := server.provisionAccount(cfg, map[string]any{"dsm_username": "alice"}); r["success"] != true {
					t.Fatalf("provision after root setup: %v", r)
				}
			}
		})
	}
}

func TestInstallerKeepsRevocationsAndUIDChanges(t *testing.T) {
	cfg := policyTestConfig(t)
	candidates := func() (*db.HelperEnrollmentSnapshot, error) {
		return &db.HelperEnrollmentSnapshot{Users: []string{"alice", "bob"}, Groups: []string{}}, nil
	}
	if _, err := migrateAccountPolicy(cfg, nil, candidates); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	passwd, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, strings.Replace(string(passwd), "bob:x:1027:", "bob:x:1040:", 1))
	result, err := migrateAccountPolicy(cfg, nil, candidates)
	if err != nil || result.Users != 0 || result.Skipped != 2 {
		t.Fatalf("repeat: %+v %v", result, err)
	}
	for name, reason := range map[string]string{"alice": "撤销", "bob": "1027 1040", "operator": "administrator"} {
		err := requireManagedUser(cfg, name)
		for _, part := range strings.Fields(reason) {
			if err == nil || !strings.Contains(err.Error(), part) {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
}

func TestInstallerExcludesServiceAccountsAndPrivilegedMembership(t *testing.T) {
	cfg := policyTestConfig(t)
	writeFile(t, cfg.PasswdPath, "alice:x:1026:100::/:/bin/sh\nbob:x:1027:100::/:/bin/sh\nguest:x:1025:100::/:/bin/sh\npackage:x:170000:100::/:/bin/false\nservice:x:1030:900::/:/bin/false\n")
	writeFile(t, cfg.GroupPath, "users:x:100:\nadministrators:x:101:\ndocker:x:900:\ndocker-alias:x:900:alice\n")
	result, err := migrateAccountPolicy(cfg, nil, func() (*db.HelperEnrollmentSnapshot, error) {
		return &db.HelperEnrollmentSnapshot{Users: []string{"alice", "bob", "guest", "package", "service"}, Groups: []string{}}, nil
	})
	if err != nil || result.Users != 1 || result.Skipped != 4 {
		t.Fatalf("restricted accounts: %+v, %v", result, err)
	}
	if err := requireManagedUser(cfg, "bob"); err != nil {
		t.Fatal(err)
	}
}

func TestMissingAccountWithPriorGrantCannotBeRecreated(t *testing.T) {
	cfg := policyTestConfig(t)
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "bob", false, true); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, "root:x:0:0:root:/root:/bin/sh\n")
	for _, name := range []string{"alice", "bob"} {
		if err := verifyAccountAbsent(cfg, name); err == nil {
			t.Fatalf("recreated %s across an existing binding", name)
		}
	}
	if err := verifyAccountAbsent(cfg, "newuser"); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryOnlyInstallerSyncWithoutMailOrReceipt(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = cfg.PasswdPath + ".synouser"
	if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] && [ \"$2\" = alice ] || exit 1\necho 'Expired : [false]'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.SynoGroupPath = cfg.GroupPath + ".synogroup"
	if err := os.WriteFile(cfg.SynoGroupPath, []byte("#!/bin/sh\n[ \"$1\" = --memberadd ] && [ \"$2\" = engineering ] && [ \"$3\" = alice ]\n"), 0700); err != nil {
		t.Fatal(err)
	}
	q := syncedPasswordTestStore(t, "alice")
	addEngineeringMapping(t, q)
	execSQL := func(sql string) {
		t.Helper()
		if _, err := q.DBTX().ExecContext(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	execSQL(`UPDATE dsm_accounts SET provision_status='failed';
INSERT INTO group_members(id,dsm_group_id,dsm_account_id) VALUES('membership','group','account');
INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id,dsm_group_id)
VALUES('membership','member','source','external','department','account','group');`)
	snapshot := func() (*db.HelperEnrollmentSnapshot, error) {
		return db.HelperEnrollmentCandidates(context.Background(), q)
	}
	// Simulate an older, already-migrated root installation.
	if _, err := migrateAccountPolicy(cfg, nil, emptyDirectorySnapshot); err != nil {
		t.Fatal(err)
	}
	result, err := migrateAccountPolicy(cfg, nil, snapshot)
	if err != nil || result.DirectoryUsers != 1 || result.Users != 0 {
		t.Fatalf("install: %+v, %v", result, err)
	}
	server := NewWithStore(cfg, q)
	user := map[string]any{"dsm_username": "alice", "display_name": "directory name", "email": "new@example.test"}
	if r := server.provisionAccount(cfg, user); r["success"] != true || r["created"] != false {
		t.Fatalf("incremental link: %v", r)
	}
	payload := map[string]any{"dsm_username": "alice", "dsm_groupname": "engineering"}
	if r := server.mutateGroup(cfg, "scoped_provision_group", payload); r["success"] != true {
		t.Fatal(r)
	}
	if r := server.mutateGroup(cfg, "scoped_add_group_member", payload); r["success"] != true {
		t.Fatal(r)
	}
	execSQL("UPDATE dsm_accounts SET provision_status='linked_existing'")
	if result, err = migrateAccountPolicy(cfg, nil, snapshot); err != nil || result.Users != 0 || result.DirectoryUsers != 0 {
		t.Fatalf("reinstall: %+v, %v", result, err)
	}
	if err := server.authorizeLogin(cfg, map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}); err == nil {
		t.Fatal("directory grant allowed SSO")
	}
	if err := server.resetSyncedUserPassword(cfg, syncedPasswordPayload("alice", "test-value")); err == nil || !strings.Contains(err.Error(), "通讯录同步授权") {
		t.Fatalf("password restriction: %v", err)
	}
	if r := server.disableAccount(cfg, user); r["success"] == true {
		t.Fatal("directory grant allowed disabling local account")
	}
	if err := server.requireMemberEnrollment(cfg, "scoped_add_group_member", "alice", "finance"); err == nil {
		t.Fatal("unapproved department allowed")
	}
	if err := server.requireMemberEnrollment(cfg, "scoped_remove_group_member", "alice", "engineering"); err == nil {
		t.Fatal("removed an active directory membership")
	}
	execSQL("UPDATE dsm_mapping_entries SET active=0 WHERE mapping_type='member'")
	if err := server.requireMemberEnrollment(cfg, "scoped_add_group_member", "alice", "engineering"); err == nil {
		t.Fatal("inactive membership allowed")
	}
	if err := server.requireMemberEnrollment(cfg, "scoped_remove_group_member", "alice", "engineering"); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := userEnrollment(cfg, "alice"); err == nil {
		t.Fatal("reinstalled revoked user")
	}
}
