package helperserver

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/identity"
)

func TestRetainedNamesakesLoginWithoutDirectorySync(t *testing.T) {
	ctx := context.Background()
	cfg := policyTestConfig(t)
	old := syncedPasswordTestStore(t, "alice")
	database := old.DBTX().(*sql.DB)
	_, err := database.Exec(`
UPDATE identity_sources SET provider_type='dingtalk';
UPDATE external_accounts SET display_name='同名员工';
INSERT INTO app_identities(id,status) VALUES('identity2','active');
INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id,display_name,active)
VALUES('external2','source','subject2','subject2','directory_subject','identity2','同名员工',1);
INSERT INTO dsm_accounts(id,app_identity_id,dsm_username,dsm_username_norm,provision_status)
VALUES('account2','identity2','bob','bob','created');
INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id)
VALUES('mapping2','user','source','external2','','account2');`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Users = map[string]int{"alice": 1026, "bob": 1027}
	p.CredentialOwners = map[string]db.CredentialIdentity{
		"alice": {Username: "alice", SourceSlug: "source", Subject: "subject"},
		"bob":   {Username: "bob", SourceSlug: "source", Subject: "subject2"},
	}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.AccountPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	var path, name string
	var seq int
	if err := database.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	q := db.New(reopened)
	server := NewWithStore(cfg, q)
	service := identity.NewService(config.BackendConfig{}, q)
	for _, subject := range []string{"subject2", "subject", "subject2"} {
		_, id, account, err := service.ResolveAuthorizedLogin(ctx, "source", subject)
		if err != nil {
			t.Fatal(err)
		}
		if p.CredentialOwners[account.DSMUsername].Subject != subject {
			t.Fatal("wrong namesake", subject)
		}
		if err := server.authorizeLogin(cfg, map[string]any{"dsm_username": account.DSMUsername, "identity_id": id.ID, "login_source": "source"}); err != nil {
			t.Fatal(err)
		}
	}
	var runs int
	if err := reopened.QueryRow("SELECT count(*) FROM sync_runs").Scan(&runs); err != nil || runs != 0 {
		t.Fatalf("sync runs=%d err=%v", runs, err)
	}
	after, err := os.ReadFile(cfg.AccountPolicyPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retained policy changed", err)
	}
	writeFile(t, cfg.PasswdPath, "alice:x:1029:100::/:/bin/sh\nbob:x:1027:100::/:/bin/sh\n")
	if err := server.authorizeLogin(cfg, map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}); err == nil {
		t.Fatal("replacement NAS UID accepted")
	}
	if err := server.authorizeLogin(cfg, map[string]any{"dsm_username": "bob", "identity_id": "identity2", "login_source": "source"}); err != nil {
		t.Fatal("unrelated namesake blocked", err)
	}
}

func TestRetainedMembershipDoesNotGrantLogin(t *testing.T) {
	cfg := policyTestConfig(t)
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.DirectoryUsers = map[string]directoryUserGrant{
		"alice": {UID: 1026, DingTalk: &db.DingTalkUserBinding{SourceSlug: "source", Subject: "subject"}},
	}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	server := NewWithStore(cfg, syncedPasswordTestStore(t, "alice"))
	err = server.authorizeLogin(cfg, map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"})
	if !errors.Is(err, errDingTalkMembershipOnly) {
		t.Fatalf("membership grant accepted for login or misreported: %v", err)
	}
}

func TestRetainedSudoRuleOnlyAllowsSignedUpdate(t *testing.T) {
	rule := retainedHelperRule()
	want := "DSMPASS ALL=(root) NOPASSWD: NOSETENV: " + config.HelperControlPath + " upgrade\n"
	if lines := bytes.Split([]byte(rule), []byte("\n")); len(lines) != 3 || string(lines[1])+"\n" != want {
		t.Fatalf("unexpected reinstallation rule: %s", rule)
	}
}
