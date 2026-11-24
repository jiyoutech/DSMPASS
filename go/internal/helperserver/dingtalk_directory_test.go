package helperserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/identity"
)

func TestDingTalkDirectoryMatchesAndFollowsNewMembership(t *testing.T) {
	ctx := context.Background()
	for _, when := range []string{"mapped_at_setup", "previously_linked", "mapped_after_setup", "old_directory_grant"} {
		t.Run(when, func(t *testing.T) {
			cfg := policyTestConfig(t)
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			// A successful read of a local account with no email. No other user operation is allowed.
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] && [ \"$2\" = alice ]\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cfg.SynoGroupPath = filepath.Join(t.TempDir(), "synogroup")
			marker := cfg.SynoGroupPath + ".members"
			if err := os.WriteFile(cfg.SynoGroupPath, []byte("#!/bin/sh\n[ \"$1\" = --memberadd ] && [ \"$2\" = engineering ] && [ \"$3\" = alice ] || exit 1\necho added >> '"+marker+"'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			change := func(sql string) {
				t.Helper()
				if _, err := q.DBTX().ExecContext(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			change("UPDATE identity_sources SET provider_type='dingtalk'; UPDATE external_accounts SET display_name='alice'; UPDATE dsm_accounts SET provision_status='failed'")
			if when == "previously_linked" {
				change("UPDATE dsm_accounts SET provision_status='linked_existing'")
			}
			if when == "mapped_after_setup" {
				change("UPDATE external_accounts SET active=0")
			}
			if when == "old_directory_grant" {
				p, err := readAccountPolicy(cfg)
				if err != nil {
					t.Fatal(err)
				}
				p.DirectoryUsers = map[string]directoryUserGrant{"alice": {UID: 1026}}
				p.LegacyMigrationComplete = true
				p.ReusableGroups = map[string]int{"engineering": 65536}
				if err := saveAccountPolicy(cfg, p); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() (*db.HelperEnrollmentSnapshot, error) { return db.HelperEnrollmentCandidates(ctx, q) }
			if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
				t.Fatal(err)
			}
			change("UPDATE external_accounts SET active=1")
			server := NewWithStore(cfg, q)
			member := map[string]any{"dsm_username": "alice", "dsm_groupname": "engineering"}
			if r := server.provisionAccount(context.Background(), cfg, member); r["success"] != true || r["created"] != false {
				t.Fatal(r)
			}
			grant, err := userEnrollment(cfg, "alice")
			if err != nil || grant == nil || grant.DingTalk == nil || grant.DingTalk.Subject != "subject" {
				t.Fatalf("binding: %+v, %v", grant, err)
			}
			if len(grant.Groups) != 0 {
				t.Fatal("test requires a newly assigned department")
			}
			addEngineeringMapping(t, q)
			change("UPDATE provider_groups SET subject='dept-42',subject_norm='dept-42'")
			service := identity.NewService(config.BackendConfig{}, q)
			if err := service.EnsureDSMMemberMapping(ctx, "source", "dept-42", "subject", "group", "account"); err != nil {
				t.Fatal(err)
			}
			if _, err := service.EnsureGroupMember(ctx, "group", "account"); err != nil {
				t.Fatal(err)
			}
			// Membership cannot self-authorize the group. Normal department provisioning must succeed first.
			if r := server.mutateGroup(cfg, "scoped_add_group_member", member); r["success"] == true {
				t.Fatal("claimed an unregistered group")
			}
			if r := server.mutateGroup(cfg, "scoped_provision_group", member); r["success"] != true {
				t.Fatal(r)
			}
			if r := server.mutateGroup(cfg, "scoped_add_group_member", member); r["success"] != true {
				t.Fatal(r)
			}
			active, err := snapshot()
			if err != nil || len(active.Departments["alice"]) != 1 {
				t.Fatalf("native subject not resolved: %+v, %v", active, err)
			}
			pair, err := os.ReadFile(marker)
			if err != nil || string(pair) != "added\n" {
				t.Fatal("DSM member operation did not run", err)
			}
			change("UPDATE dsm_accounts SET provision_status='linked_existing'")
			if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
				t.Fatal(err)
			}
			if err := server.resetSyncedUserPassword(cfg, syncedPasswordPayload("alice", "test-only")); !errors.Is(err, errDingTalkMembershipOnly) {
				t.Fatalf("reset result: %v", err)
			}
			if err := server.authorizeLogin(cfg, map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}); err == nil {
				t.Fatal("used directory name for login")
			}
			for _, scenario := range []struct{ change, undo string }{
				{"UPDATE identity_sources SET enabled=0", "UPDATE identity_sources SET enabled=1"},
				{"UPDATE external_accounts SET subject='replacement'", "UPDATE external_accounts SET subject='subject'"},
				{"UPDATE external_accounts SET display_name='other'", "UPDATE external_accounts SET display_name='alice'"},
				{"UPDATE dsm_mapping_entries SET provider_group_id='some-other-department' WHERE mapping_type='member'", "UPDATE dsm_mapping_entries SET provider_group_id='dept-42' WHERE mapping_type='member'"},
				{"INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name) VALUES('duplicate','source','other','other','user','alice')", "DELETE FROM external_accounts WHERE id='duplicate'"},
				{"UPDATE dsm_mapping_entries SET active=0 WHERE mapping_type='member'", "UPDATE dsm_mapping_entries SET active=1 WHERE mapping_type='member'"},
			} {
				change(scenario.change)
				if r := server.mutateGroup(cfg, "scoped_add_group_member", member); r["success"] == true {
					t.Fatalf("accepted invalid membership: %s", scenario.change)
				}
				change(scenario.undo)
			}
			change("UPDATE dsm_mapping_entries SET active=0 WHERE mapping_type='member'")
			if err := service.ReconcileFinalGroupMembers(ctx); err != nil {
				t.Fatal(err)
			}
			var status string
			if err := q.DBTX().QueryRowContext(ctx, "SELECT provision_status FROM group_members WHERE active=0 AND dsm_group_id='group' AND dsm_account_id='account'").Scan(&status); err != nil || status != "disabled" {
				t.Fatalf("department departure: %q, %v", status, err)
			}
			change("UPDATE dsm_mapping_entries SET active=1 WHERE mapping_type='member'")
			if err := service.ReconcileFinalGroupMembers(ctx); err != nil {
				t.Fatal(err)
			}
			groupFile, err := os.ReadFile(cfg.GroupPath)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, cfg.GroupPath, strings.Replace(string(groupFile), "engineering:x:65536:", "engineering:x:65550:", 1))
			if r := server.mutateGroup(cfg, "scoped_add_group_member", member); r["success"] == true {
				t.Fatal("accepted changed GID")
			}
			if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
				t.Fatal(err)
			}
			if r := server.provisionAccount(context.Background(), cfg, member); r["success"] == true {
				t.Fatal("relinked revoked account")
			}
		})
	}
}

func TestFutureDingTalkMappingRequiresFixedUIDAndEligibleSource(t *testing.T) {
	cfg := policyTestConfig(t)
	q := syncedPasswordTestStore(t, "alice")
	server := NewWithStore(cfg, q)
	snapshot := func() (*db.HelperEnrollmentSnapshot, error) {
		return db.HelperEnrollmentCandidates(context.Background(), q)
	}
	if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := server.linkDingTalkDirectoryUser(cfg, "bob"); err == nil {
		t.Fatal("unknown authority accepted")
	}
	if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE identity_sources SET provider_type='dingtalk'"); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil || p.DingTalkScope.Users["bob"] != 1027 {
		t.Fatalf("missing local scope: %v", err)
	}
	if _, found := p.DingTalkScope.Users["operator"]; found {
		t.Fatal("captured an administrator")
	}
	data, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, strings.Replace(string(data), "bob:x:1027:", "bob:x:1050:", 1))
	if _, err := server.linkDingTalkDirectoryUser(cfg, "bob"); err == nil || !strings.Contains(err.Error(), "1027") {
		t.Fatalf("did not reject a changed UID: %v", err)
	}
}
