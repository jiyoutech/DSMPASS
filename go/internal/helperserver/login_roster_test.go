package helperserver

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestDingTalkRosterDirectBinding(t *testing.T) {
	if _, err := BindDingTalkLogins(policyTestConfig(t), "source", false); err == nil {
		t.Fatal("unprivileged command accepted")
	}
	if _, err := db.DingTalkLoginRoster(context.Background(), nil, ""); err == nil {
		t.Fatal("empty source accepted")
	}
	for _, tc := range []struct {
		name, change, expiry string
		eligible             bool
	}{
		{name: "unique without email", eligible: true},
		{name: "namesake", change: "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name) VALUES('duplicate','source','other','other','directory_subject',' ALICE ')"},
		{name: "ambiguous employee ID", change: "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name) VALUES('alias','source','subject','other','directory_subject','different')"},
		{name: "different source employee", change: "UPDATE external_accounts SET subject='replacement'"},
		{name: "temporarily disabled", change: "UPDATE dsm_accounts SET allow_login=0"},
		{name: "manually blocked", change: "UPDATE dsm_accounts SET manual_login_blocked=1"},
		{name: "source disabled", change: "UPDATE identity_sources SET login_enabled=0"},
		{name: "existing conflict", change: "UPDATE dsm_accounts SET conflict_reason='pending choice'"},
		{name: "other source mapping", change: "INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id) VALUES('m2','user','other','x','','account')"},
		{name: "expired native account", expiry: "true"}, {name: "unknown native expiry", expiry: "unknown"},
		{name: "different UID"}, {name: "revoked"}, {name: "new unpinned user"}, {name: "administrator"}, {name: "duplicate pinned identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := policyTestConfig(t)
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			expiry := tc.expiry
			if expiry == "" {
				expiry = "false"
			}
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 1\necho 'Expired : ["+expiry+"]'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			if _, err := q.DBTX().ExecContext(ctx, "UPDATE identity_sources SET provider_type='dingtalk'; UPDATE external_accounts SET display_name='alice';"+tc.change); err != nil {
				t.Fatal(err)
			}
			p, err := readAccountPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			grant := directoryUserGrant{UID: 1026, DingTalk: &db.DingTalkUserBinding{SourceSlug: "source", Subject: "subject"}}
			p.DirectoryUsers = map[string]directoryUserGrant{"alice": grant}
			switch tc.name {
			case "different UID":
				grant.UID++
				p.DirectoryUsers["alice"] = grant
			case "revoked":
				p.Users["alice"] = revokedUserID
			case "new unpinned user":
				delete(p.DirectoryUsers, "alice")
			case "administrator":
				writeFile(t, cfg.GroupPath, "users:x:100:\nadministrators:x:101:alice\n")
			case "duplicate pinned identity":
				p.DirectoryUsers["bob"] = grant
			}
			if err := saveAccountPolicy(cfg, p); err != nil {
				t.Fatal(err)
			}
			query := func() (map[string]string, error) { return db.DingTalkLoginRoster(ctx, q, "source") }
			before, err := os.ReadFile(cfg.AccountPolicyPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, dry := range []bool{true, false} {
				count, err := bindDingTalkLogins(cfg, "source", dry, query)
				if err != nil || (count == 1) != tc.eligible {
					t.Fatalf("dry=%t count=%d error=%v", dry, count, err)
				}
				if dry || !tc.eligible {
					after, err := os.ReadFile(cfg.AccountPolicyPath)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("unexpected policy change", err)
					}
				}
			}
			if tc.eligible {
				s := NewWithStore(cfg, q)
				if err := s.authorizeLogin(cfg, map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}); err != nil {
					t.Fatal(err)
				}
				if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "password_reset", Username: "alice", SourceSlug: "source", AccountID: "account"}); err != nil {
					t.Fatal(err)
				}
				if n, err := bindDingTalkLogins(cfg, "source", false, query); n != 0 || err != nil {
					t.Fatal("repeat", n, err)
				}
				if _, err := q.DBTX().ExecContext(ctx, "UPDATE external_accounts SET subject='replacement'"); err != nil {
					t.Fatal(err)
				}
				if err := s.authorizeLogin(cfg, map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}); err == nil {
					t.Fatal("changed identity inherited grant")
				}
			}
		})
	}
}

func TestDingTalkRoster700(t *testing.T) {
	ctx := context.Background()
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 1\necho 'Expired : [false]'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	q := syncedPasswordTestStore(t, "fixture")
	tx, err := q.DBTX().(*sql.DB).Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE identity_sources SET provider_type='dingtalk'"); err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.DirectoryUsers = make(map[string]directoryUserGrant)
	var passwd strings.Builder
	for i := range 700 {
		name := fmt.Sprintf("staff%03d", i)
		uid := 2000 + i
		fmt.Fprintf(&passwd, "%s:x:%d:100::/:/bin/sh\n", name, uid)
		p.DirectoryUsers[name] = directoryUserGrant{UID: uid, DingTalk: &db.DingTalkUserBinding{SourceSlug: "source", Subject: name}}
		for _, query := range []string{
			"INSERT INTO app_identities(id,status) VALUES(?1,'active')",
			"INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id,display_name) VALUES(?1,'source',?1,?1,'directory_subject',?1,?1)",
			"INSERT INTO dsm_accounts(id,app_identity_id,dsm_username,dsm_username_norm,provision_status) VALUES(?1,?1,?1,?1,'linked_existing')",
			"INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id) VALUES(?1,'user','source',?1,'',?1)",
		} {
			if _, err := tx.Exec(query, name); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, passwd.String())
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	query := func() (map[string]string, error) { return db.DingTalkLoginRoster(ctx, q, "source") }
	calls := 0
	changed := func() (map[string]string, error) {
		rows, err := query()
		calls++
		if calls == 2 {
			delete(rows, "staff699")
		}
		return rows, err
	}
	if n, err := bindDingTalkLogins(cfg, "source", false, changed); err == nil || n != 0 {
		t.Fatal("partial snapshot applied", n, err)
	}
	if n, err := bindDingTalkLogins(cfg, "source", false, query); err != nil || n != 700 {
		t.Fatal("batch", n, err)
	}
	p, err = readAccountPolicy(cfg)
	if err != nil || len(p.CredentialOwners) != 700 || len(p.DirectoryUsers) != 0 {
		t.Fatal("incomplete batch", len(p.CredentialOwners), err)
	}
}
