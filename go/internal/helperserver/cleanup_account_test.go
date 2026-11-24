package helperserver

import (
	"context"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupExistingMembershipAndInterruptedDisable(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 1\necho 'Expired : [true]'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	q := syncedPasswordTestStore(t, "alice")
	if _, err := q.DBTX().ExecContext(context.Background(), "INSERT INTO source_cleanup_targets(source_slug,account_id,username,request_id) VALUES('source','account','alice','cleanup')"); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, q)
	payload := map[string]any{"dsm_username": "alice", "account_id": "account", "source_slug": "source", "request_id": "cleanup"}
	if err := saveAccountPolicy(cfg, accountPolicy{Users: map[string]int{}, Groups: map[string]int{}, DirectoryUsers: map[string]directoryUserGrant{"alice": {UID: 1026}}}); err != nil {
		t.Fatal(err)
	}
	if r := s.cleanupAccount(cfg, payload); r["outcome"] != "membership_only" {
		t.Fatal(r)
	}
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	if r := s.cleanupAccount(cfg, payload); r["outcome"] != "disabled" {
		t.Fatal(r)
	}
	payload["request_id"] = "wrong"
	if r := s.cleanupAccount(cfg, payload); r["success"] == true {
		t.Fatal(r)
	}
}

func TestCleanupRemovesSourceOwnerAtomicallyAndReplays(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	writeFile(t, cfg.SynoUserPath, "#!/bin/sh\necho 'Expired : [true]'\n")
	if err := os.Chmod(cfg.SynoUserPath, 0700); err != nil {
		t.Fatal(err)
	}
	q := syncedPasswordTestStore(t, "alice")
	if _, err := q.DBTX().ExecContext(context.Background(), "INSERT INTO source_cleanup_targets VALUES('source','account','alice','cleanup','pending')"); err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Users["alice"] = 1026
	p.CredentialOwners = map[string]db.CredentialIdentity{"alice": {Username: "alice", SourceSlug: "source", Subject: "subject"}}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, q)
	for range 2 {
		r := s.cleanupAccount(cfg, map[string]any{"source_slug": "source", "account_id": "account", "request_id": "cleanup", "dsm_username": "alice"})
		if r["outcome"] != "disabled" {
			t.Fatal(r)
		}
		p, err = readAccountPolicy(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.Users["alice"]; ok || p.CredentialOwners["alice"].Subject != "" {
			t.Fatal("old credential or UID retained")
		}
	}
	// A new source cannot inherit the retired credential. A fresh native
	// proof can enroll the same physical user after the administrator enables it.
	_, err = q.DBTX().ExecContext(context.Background(), "UPDATE identity_sources SET slug='replacement'; UPDATE external_accounts SET provider_slug='replacement',email_verified=1,email_norm='a@example.test'; UPDATE dsm_mapping_entries SET provider_slug='replacement'")
	if err != nil {
		t.Fatal(err)
	}
	login := map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "replacement"}
	if s.authorizeLogin(cfg, login) == nil {
		t.Fatal("new source inherited old credential")
	}
	owner := db.CredentialIdentity{Username: "alice", SourceSlug: "replacement", Subject: "subject"}
	p.CredentialCandidates = map[string]verifiedAccountCandidate{"alice": {UID: 1026, Email: "a@example.test", Owner: owner}}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	if s.authorizeLogin(cfg, login) == nil {
		t.Fatal("disabled account was reenabled")
	}
	if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\necho 'Expired : [false]'\necho 'User Mail : [a@example.test]'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.authorizeLogin(cfg, login); err != nil {
		t.Fatal(err)
	}
}
func TestCleanupAbsentMappedAndProtectedConflict(t *testing.T) {
	for _, tc := range []struct {
		name, status, outcome string
		revoke                bool
	}{
		{"vanished", "created", "absent", false}, {"vanished", "linked_existing", "absent", false}, {"alice", "failed", "unmapped_conflict", false}, {"alice", "pending", "unmapped_conflict", false}, {"alice", "conflict", "unmapped_conflict", true}, {"admin", "conflict", "unmapped_conflict", false},
	} {
		t.Run(tc.name+tc.status, func(t *testing.T) {
			cfg := policyTestConfig(t)
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || exit 9\necho 'synoerr=[0x1d00]' >&2\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, tc.name)
			if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_accounts SET provision_status=?", tc.status); err != nil {
				t.Fatal(err)
			}
			if _, err := q.DBTX().ExecContext(context.Background(), "INSERT INTO source_cleanup_targets VALUES('source','account',?,'req','pending')", tc.name); err != nil {
				t.Fatal(err)
			}
			if tc.revoke {
				if err := updateAccountPolicy(cfg, tc.name, false, true); err != nil {
					t.Fatal(err)
				}
			}
			s := NewWithStore(cfg, q)
			r := s.cleanupAccount(cfg, map[string]any{"source_slug": "source", "account_id": "account", "request_id": "req", "dsm_username": tc.name})
			if r["outcome"] != tc.outcome {
				t.Fatal(r)
			}
			if tc.revoke {
				p, err := readAccountPolicy(cfg)
				if err != nil || p.Users[tc.name] != revokedUserID {
					t.Fatal("revocation removed", err)
				}
			}
		})
	}
}

func TestForgetAbsentLegacyUserRequiresNativeProof(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\necho 'synoerr=[0x1d00]' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.Users["old"] = revokedUserID
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	if forgetAbsentUser(cfg, "old") == nil {
		t.Fatal("explicit revocation lost")
	}
	p.Users["old"] = 2000
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	if forgetAbsentUser(cfg, "alice") == nil {
		t.Fatal("existing DSM user forgotten")
	}
	if err := forgetAbsentUser(cfg, "old"); err != nil {
		t.Fatal(err)
	}
	if err := verifyAccountAbsent(cfg, "old"); err != nil {
		t.Fatal(err)
	}
}
