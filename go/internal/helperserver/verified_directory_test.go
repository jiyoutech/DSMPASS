package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestVerifiedExistingUserAutomaticallyGetsLoginAndFullSyncPassword(t *testing.T) {
	for _, provider := range []string{"dingtalk", "feishu", "wecom"} {
		t.Run(provider, func(t *testing.T) {
			cfg := policyTestConfig(t)
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			marker := cfg.SynoUserPath + ".reset"
			cmd := "#!/bin/sh\ncase \"$1:$2\" in\n--get:alice) echo 'User Mail : [Alice@example.test]';;\n--setpw:alice) echo reset >> '" + marker + "';;\n*) exit 1;;\nesac\n"
			if err := os.WriteFile(cfg.SynoUserPath, []byte(cmd), 0700); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := q.DBTX().ExecContext(context.Background(), sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec("UPDATE identity_sources SET provider_type=?", provider)
			exec("UPDATE external_accounts SET display_name='alice',email_norm='alice@example.test',email_verified=1")
			// Simulate an installation with a pre-existing membership-only registration.
			p, err := readAccountPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			p.DirectoryUsers = map[string]directoryUserGrant{"alice": {UID: 1026}}
			if err := saveAccountPolicy(cfg, p); err != nil {
				t.Fatal(err)
			}
			snapshot := func() (*db.HelperEnrollmentSnapshot, error) {
				return db.HelperEnrollmentCandidates(context.Background(), q)
			}
			if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
				t.Fatal(err)
			}
			server := NewWithStore(cfg, q)
			login := map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}
			provision := map[string]any{"dsm_username": "alice"}
			if err := server.authorizeLogin(cfg, login); err == nil {
				t.Fatal("credential used before independent DSM verification")
			}
			// A changed stable identifier cannot consume a previously captured candidate.
			exec("UPDATE external_accounts SET subject='substitution'")
			if r := server.provisionAccount(context.Background(), cfg, provision); r["success"] != true {
				t.Fatal(r)
			}
			if err := server.authorizeLogin(cfg, login); err == nil {
				t.Fatal("source subject changed")
			}
			exec("UPDATE external_accounts SET subject='subject'")
			exec("INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,email_norm) VALUES('duplicate','source','x','x','directory_subject','alice@example.test')")
			if r := server.provisionAccount(context.Background(), cfg, provision); r["success"] != true {
				t.Fatal(r)
			}
			if err := server.authorizeLogin(cfg, login); err == nil {
				t.Fatal("accepted shared email")
			}
			exec("DELETE FROM external_accounts WHERE id='duplicate'")
			if r := server.provisionAccount(context.Background(), cfg, provision); r["success"] != true || r["created"] != false {
				t.Fatal(r)
			}
			if err := server.authorizeLogin(cfg, login); err != nil {
				t.Fatal(err)
			}
			if err := server.resetSyncedUserPassword(cfg, syncedPasswordPayload("alice", "test-only")); err != nil {
				t.Fatal(err)
			}
			exec("UPDATE external_accounts SET subject='replacement'")
			if err := server.authorizeLogin(cfg, login); err == nil {
				t.Fatal("login followed replacement subject")
			}
			reset := syncedPasswordPayload("alice", "test-only")
			reset["request_id"] = "new-attempt"
			if err := server.resetSyncedUserPassword(cfg, reset); err == nil {
				t.Fatal("reset followed replacement subject")
			}
			data, err := os.ReadFile(marker)
			if err != nil || string(data) != "reset\n" {
				t.Fatalf("native writes %q, %v", data, err)
			}
			exec("UPDATE external_accounts SET subject='subject'")
			if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
				t.Fatal(err)
			}
			if _, err := migrateAccountPolicy(cfg, nil, snapshot); err != nil {
				t.Fatal(err)
			}
			if r := server.provisionAccount(context.Background(), cfg, provision); r["success"] == true {
				t.Fatal("re-enrolled a revoked UID")
			}
		})
	}
}

func TestVerifiedExistingUserRequiresPinnedOrdinaryDSMAccount(t *testing.T) {
	cfg := policyTestConfig(t)
	q := syncedPasswordTestStore(t, "alice")
	_, err := q.DBTX().ExecContext(context.Background(), "UPDATE external_accounts SET email_norm='alice@example.test',email_verified=1")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := db.HelperEnrollmentCandidates(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	captureVerifiedDirectory(cfg, &p, snap.VerifiedEmails, users, groups)
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, q)
	for _, pair := range [][2]string{{"bob", "alice@example.test"}, {"operator", "alice@example.test"}, {"alice", "different@example.test"}, {"alice", ""}} {
		if ok, err := s.linkVerifiedDirectoryUser(cfg, pair[0], pair[1], nil); err != nil || ok {
			t.Fatal("claimed unrelated account", pair, err)
		}
	}
	data, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, strings.Replace(string(data), "alice:x:1026:", "alice:x:1041:", 1))
	if ok, err := s.linkVerifiedDirectoryUser(cfg, "alice", "alice@example.test", nil); err == nil || ok {
		t.Fatal("claimed replacement UID")
	}
}
