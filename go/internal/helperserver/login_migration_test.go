package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestLoginMigratesVerifiedBindingWithoutSync(t *testing.T) {
	for _, tc := range []struct {
		name, change, mail, expired, identity, source string
		allowed                                       bool
	}{
		{name: "matching", allowed: true}, {name: "changed identity", identity: "replacement"}, {name: "different source", source: "other"},
		{name: "source disabled", change: "UPDATE identity_sources SET login_enabled=0"},
		{name: "login blocked", change: "UPDATE dsm_accounts SET allow_login=0"},
		{name: "reassigned subject", change: "UPDATE external_accounts SET subject='other'"},
		{name: "duplicate mail", change: "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,email_norm) VALUES('duplicate','source','x','x','directory_subject','a@example.test')"},
		{name: "different native mail", mail: "other@example.test"}, {name: "expired native account", expired: "true"},
		{name: "missing native expiry", expired: "unknown"}, {name: "manual block", change: "UPDATE dsm_accounts SET manual_login_blocked=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policyTestConfig(t)
			q := syncedPasswordTestStore(t, "alice")
			ctx := context.Background()
			if _, err := q.DBTX().ExecContext(ctx, "UPDATE external_accounts SET email_norm='a@example.test',email_verified=1"); err != nil {
				t.Fatal(err)
			}
			if tc.change != "" {
				if _, err := q.DBTX().ExecContext(ctx, tc.change); err != nil {
					t.Fatal(err)
				}
			}
			owner := db.CredentialIdentity{Username: "alice", SourceSlug: "source", Subject: "subject"}
			p, err := readAccountPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			p.CredentialCandidates = map[string]verifiedAccountCandidate{"alice": {UID: 1026, Email: "a@example.test", Owner: owner}}
			if err := saveAccountPolicy(cfg, p); err != nil {
				t.Fatal(err)
			}
			pw := filepath.Join(t.TempDir(), "synouser")
			cfg.SynoUserPath = pw
			mail := tc.mail
			if mail == "" {
				mail = "a@example.test"
			}
			expired := tc.expired
			if expired == "" {
				expired = "false"
			}
			if err := os.WriteFile(pw, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 1\necho 'User Mail : ["+mail+"]'\necho 'Expired : ["+expired+"]'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			ident, source := tc.identity, tc.source
			if ident == "" {
				ident = "identity"
			}
			if source == "" {
				source = "source"
			}
			login := map[string]any{"identity_id": ident, "login_source": source, "dsm_username": "alice"}
			server := NewWithStore(cfg, q)
			err = server.authorizeLogin(cfg, login)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t error=%v", tc.allowed, err)
			}
			p, err = readAccountPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if (p.CredentialOwners["alice"] == owner) != tc.allowed || (p.Users["alice"] == 1026) != tc.allowed {
				t.Fatal("incorrect persistent owner")
			}
			if tc.allowed {
				if err := os.Remove(pw); err != nil {
					t.Fatal(err)
				}
				if err := NewWithStore(cfg, q).authorizeLogin(cfg, login); err != nil {
					t.Fatal("repeat login needed enrollment", err)
				}
			}
		})
	}
}

func TestLoginApprovalForRetainedDirectoryOnlyAccount(t *testing.T) {
	for _, prior := range []string{"subject", "former-member"} {
		t.Run(prior, func(t *testing.T) { checkRetainedLoginApproval(t, prior) })
	}
}

func checkRetainedLoginApproval(t *testing.T, prior string) {
	cfg := policyTestConfig(t)
	q := syncedPasswordTestStore(t, "alice")
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prior != "subject" {
		_, err := q.DBTX().ExecContext(context.Background(), "UPDATE identity_sources SET provider_type='dingtalk'; UPDATE dsm_accounts SET managed=0; INSERT INTO directory_owner_choices VALUES('account','external','source','subject','alice',1026)")
		if err != nil {
			t.Fatal(err)
		}
	}
	p.DirectoryUsers = map[string]directoryUserGrant{"alice": {UID: 1026, DingTalk: &db.DingTalkUserBinding{SourceSlug: "source", Subject: prior}}}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	desc := cfg.SynoUserPath + ".description"
	if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 1\necho 'Expired : [false]'\ncat \"$0.description\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, desc, "Fullname : [original]\n")
	s := NewWithStore(cfg, q)
	payload := map[string]any{"dsm_username": "alice", "source_slug": "source", "identity_id": "identity", "subject": "subject", "verify": false}
	login := map[string]any{"dsm_username": "alice", "login_source": "source", "identity_id": "identity"}
	if err := s.authorizeLogin(cfg, login); err == nil {
		t.Fatal("membership-only login accepted")
	}
	r := s.webLoginApproval(cfg, payload)
	code, _ := r["code"].(string)
	if r["approved"] != false || !strings.HasPrefix(code, "DP-U-") {
		t.Fatal(r)
	}
	if retry := s.webLoginApproval(cfg, payload); retry["code"] != code {
		t.Fatal("ticket not idempotent", retry)
	}
	payload["verify"] = true
	payload["code"] = code
	if r := s.webLoginApproval(cfg, payload); r["success"] == true {
		t.Fatal("browser-supplied proof accepted")
	}
	writeFile(t, desc, "Fullname : [original "+code+"]\n")
	payload["subject"] = "replacement"
	if r := s.webLoginApproval(cfg, payload); r["success"] == true {
		t.Fatal("ticket transferred to another person")
	}
	payload["subject"] = "subject"
	if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_accounts SET allow_login=0"); err != nil {
		t.Fatal(err)
	}
	if r := s.webLoginApproval(cfg, payload); r["success"] == true {
		t.Fatal("disabled mapping accepted")
	}
	if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_accounts SET allow_login=1"); err != nil {
		t.Fatal(err)
	}
	p, err = readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ticket := p.LoginApprovals["alice"]
	ticket.ExpiresAt = 1
	p.LoginApprovals["alice"] = ticket
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	if r := s.webLoginApproval(cfg, payload); r["success"] == true {
		t.Fatal("expired ticket accepted")
	}
	payload["verify"] = false
	r = s.webLoginApproval(cfg, payload)
	fresh, _ := r["code"].(string)
	if fresh == "" || fresh == code {
		t.Fatal("ticket not renewed")
	}
	writeFile(t, desc, "Fullname : [original "+fresh+"]\n")
	payload["verify"] = true
	if r := s.webLoginApproval(cfg, payload); r["approved"] != true {
		t.Fatal(r)
	}
	if err := NewWithStore(cfg, q).authorizeLogin(cfg, login); err != nil {
		t.Fatal(err)
	}
	p, err = readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Users["alice"] != 1026 || p.CredentialOwners["alice"].Subject != "subject" || len(p.LoginApprovals) != 0 {
		t.Fatal("incorrect saved binding")
	}
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	if r := s.webLoginApproval(cfg, payload); r["success"] == true {
		t.Fatal("revoked account reapproved by replay")
	}
}
