package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestDingTalkNameLogin(t *testing.T) {
	const duplicate = "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name) VALUES('second','source','other','other','directory_subject',' ALICE ')"
	for _, tc := range []struct {
		name, change, identity, expiry string
		selected, allowed              bool
	}{
		{name: "retained membership only", allowed: true},
		{name: "unique despite inactive namesake", change: duplicate + "; UPDATE external_accounts SET active=0 WHERE id='second'", allowed: true},
		{name: "ambiguous even without mapping for second employee", change: duplicate},
		{name: "administrator selected one of two", change: duplicate, selected: true, allowed: true},
		{name: "different login identity", identity: "other-identity"},
		{name: "selected employee needs independent confirmation", change: duplicate, selected: true},
		{name: "trusted email conflicts"},
		{name: "trusted email case difference", allowed: true},
		{name: "selected UID changed", selected: true, change: "UPDATE directory_owner_choices SET uid=8000"},
		{name: "changed employee ID", change: "UPDATE external_accounts SET subject='replacement'"},
		{name: "blank directory name", change: "UPDATE external_accounts SET display_name=''"},
		{name: "different source", change: "UPDATE identity_sources SET provider_type='wecom'"},
		{name: "inactive employee", change: "UPDATE external_accounts SET active=0"},
		{name: "manual login block", change: "UPDATE dsm_accounts SET manual_login_blocked=1"},
		{name: "directory disabled", change: "UPDATE identity_sources SET directory_sync_enabled=0"},
		{name: "login disabled", change: "UPDATE identity_sources SET login_enabled=0"},
		{name: "competing mapping", change: "INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,dsm_account_id) VALUES('other','user','other','x','account')"},
		{name: "unknown DSM status", expiry: "unknown"},
		{name: "disabled DSM user", expiry: "true"},
		{name: "revoked"},
		{name: "unregistered local account"},
		{name: "generic grant without source pin"},
		{name: "source removed from local scope"},
		{name: "replacement DSM UID"},
		{name: "administrator"},
		{name: "unresolved creation receipt"},
		{name: "email cannot decide between namesakes", change: duplicate + "; UPDATE external_accounts SET email_verified=1,email_norm='alice@example.test' WHERE id='external'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := policyTestConfig(t)
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			expiry := tc.expiry
			if expiry == "" {
				expiry = "false"
			}
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 1\necho 'Expired : ["+expiry+"]'\necho 'User Mail : [alice@example.test]'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			exec := func(sql string) {
				t.Helper()
				if _, err := q.DBTX().ExecContext(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			exec("UPDATE identity_sources SET provider_type='dingtalk'; UPDATE external_accounts SET display_name='alice'")
			if tc.selected {
				exec("UPDATE dsm_accounts SET managed=0; INSERT INTO directory_owner_choices VALUES('account','external','source','subject','alice',1026)")
			}
			if tc.change != "" {
				exec(tc.change)
			}
			p, err := readAccountPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			binding := db.DingTalkUserBinding{SourceSlug: "source", Subject: "subject"}
			p.DirectoryUsers = map[string]directoryUserGrant{"alice": {UID: 1026, DingTalk: &binding}}
			switch tc.name {
			case "selected employee needs independent confirmation":
				binding.Subject = "other"
			case "unregistered local account":
				delete(p.DirectoryUsers, "alice")
			case "generic grant without source pin":
				p.DirectoryUsers["alice"] = directoryUserGrant{UID: 1026}
			case "source removed from local scope":
				p.DingTalkScope = &dingTalkDirectoryScope{Sources: []string{"other"}, Users: map[string]int{"alice": 1026}}
			case "revoked":
				p.Users["alice"] = revokedUserID
			case "administrator":
				writeFile(t, cfg.GroupPath, "users:x:100:\nadministrators:x:101:alice\n")
			case "replacement DSM UID":
				writeFile(t, cfg.PasswdPath, "alice:x:1031:100::/:/bin/sh\n")
			case "unresolved creation receipt":
				target := creationTarget{cfg: cfg, name: "alice"}
				if err := target.begin(); err != nil {
					t.Fatal(err)
				}
			case "trusted email conflicts", "trusted email case difference":
				mail := "different@example.test"
				if tc.allowed {
					mail = " ALICE@example.test "
				}
				owner := db.CredentialIdentity{Username: "alice", SourceSlug: "source", Subject: "subject"}
				p.CredentialCandidates = map[string]verifiedAccountCandidate{"alice": {Owner: owner, UID: 1026, Email: mail}}
			case "email cannot decide between namesakes":
				owner := db.CredentialIdentity{Username: "alice", SourceSlug: "source", Subject: "subject"}
				p.CredentialCandidates = map[string]verifiedAccountCandidate{"alice": {Owner: owner, UID: 1026, Email: "alice@example.test"}}
			}
			if err := saveAccountPolicy(cfg, p); err != nil {
				t.Fatal(err)
			}
			s := NewWithStore(cfg, q)
			id := tc.identity
			if id == "" {
				id = "identity"
			}
			login := map[string]any{"dsm_username": "alice", "login_source": "source", "identity_id": id}
			for range 2 {
				err := s.authorizeLogin(cfg, login)
				if (err == nil) != tc.allowed {
					t.Fatalf("login allowed=%t, err=%v", tc.allowed, err)
				}
			}
			p, err = readAccountPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			owner, saved := p.CredentialOwners["alice"]
			if saved != tc.allowed || (saved && (p.Users["alice"] != 1026 || owner.SourceSlug != "source" || owner.Subject != "subject")) {
				t.Fatalf("unexpected saved owner: %+v", owner)
			}
			if tc.allowed {
				if tc.name == "retained membership only" {
					exec(duplicate)
					if err := s.authorizeLogin(cfg, login); err != nil {
						t.Fatal("new namesake displaced the existing employee", err)
					}
					wrong := map[string]any{"dsm_username": "alice", "login_source": "source", "identity_id": "second-identity"}
					if s.authorizeLogin(cfg, wrong) == nil {
						t.Fatal("second employee inherited the existing login")
					}
				}
				if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "password_reset", Username: "alice", SourceSlug: "source", AccountID: "account"}); err != nil {
					t.Fatal(err)
				}
				exec("UPDATE external_accounts SET subject='new-subject' WHERE id='external'")
				if s.authorizeLogin(cfg, login) == nil {
					t.Fatal("replacement employee inherited login")
				}
			}
		})
	}
}
