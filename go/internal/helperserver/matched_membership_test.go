package helperserver

import (
	"context"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestMatchedMembershipRequiresLocalGroupAndLiveMapping(t *testing.T) {
	for _, provider := range []string{"feishu", "dingtalk"} {
		t.Run(provider, func(t *testing.T) { checkMatchedMembership(t, provider) })
	}
}

func checkMatchedMembership(t *testing.T, provider string) {
	cfg := policyTestConfig(t)
	q := syncedPasswordTestStore(t, "alice")
	addEngineeringMapping(t, q)
	exec := func(sql string) {
		t.Helper()
		if _, err := q.DBTX().ExecContext(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE identity_sources SET provider_type='feishu'; UPDATE external_accounts SET display_name='alice';
 INSERT INTO group_members(id,dsm_group_id,dsm_account_id) VALUES('member','group','account');
 INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id,dsm_group_id) VALUES('member','member','source','external','department','account','group');`)
	if provider == "dingtalk" {
		exec("UPDATE identity_sources SET provider_type='dingtalk'; UPDATE dsm_accounts SET managed=0; INSERT INTO directory_owner_choices VALUES('account','external','source','subject','alice',1026); INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name) VALUES('other','source','other','other','user','alice')")
	}
	s := NewWithStore(cfg, q)
	if ok, err := s.recordDirectoryMatch(cfg, "alice"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := s.requireMemberEnrollment(cfg, "scoped_add_group_member", "alice", "engineering"); err == nil {
		t.Fatal("unapproved group accepted")
	}
	if err := updateAccountPolicy(cfg, "engineering", true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.applyGroupMembers(cfg, "engineering", []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	grant, err := userEnrollment(cfg, "alice")
	if err != nil || grant == nil || grant.Groups["engineering"] != 65536 {
		t.Fatal(grant, err)
	}
	if err := s.requireMemberEnrollment(cfg, "scoped_add_group_member", "alice", "engineering"); err != nil {
		t.Fatal(err)
	}
	if provider == "dingtalk" {
		exec("UPDATE directory_owner_choices SET uid=9999")
		if _, err := s.applyGroupMembers(cfg, "engineering", []string{"alice"}); err == nil {
			t.Fatal("batch accepted a replacement UID")
		}
		if err := s.requireMemberEnrollment(cfg, "scoped_add_group_member", "alice", "engineering"); err == nil {
			t.Fatal("single accepted a replacement UID")
		}
		exec("UPDATE directory_owner_choices SET uid=1026")
	}
	exec("UPDATE dsm_mapping_entries SET active=0 WHERE mapping_type='member'")
	if err := s.requireMemberEnrollment(cfg, "scoped_add_group_member", "alice", "engineering"); err == nil {
		t.Fatal("stale membership accepted")
	}
	if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "login", Username: "alice"}); err == nil {
		t.Fatal("directory match became a login")
	}
}
