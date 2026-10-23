package helperserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func syncedPasswordTestStore(t *testing.T, username string) *db.Queries {
	t.Helper()
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.PrepareSchema(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
INSERT INTO identity_sources (slug, provider_type, display_name) VALUES ('source','feishu','Test');
INSERT INTO app_identities (id, status) VALUES ('identity','active');
INSERT INTO external_accounts (id,provider_slug,subject,subject_norm,subject_type,app_identity_id,active)
VALUES ('external','source','subject','subject','directory_subject','identity',1);`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO dsm_accounts (id,app_identity_id,dsm_username,dsm_username_norm,managed,provision_status)
VALUES ('account','identity',?,?,1,'linked_existing')`, username, username); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO dsm_mapping_entries (id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id)
VALUES ('mapping','user','source','external','','account')`); err != nil {
		t.Fatal(err)
	}
	return db.New(database)
}

func syncedPasswordPayload(username, password string) map[string]any {
	return map[string]any{"request_id": "test-reset", "source_slug": "source", "account_id": "account", "dsm_username": username, "password": password}
}

func TestResetSyncedUserPasswordScopeAndErrors(t *testing.T) {
	cases := []struct {
		name, change, field, value      string
		pending, noStore, fail, allowed bool
	}{
		{name: "managed linked account", allowed: true},
		{name: "created account", change: `UPDATE dsm_accounts SET provision_status='created'`, allowed: true},
		{name: "manually named synced account", change: `UPDATE dsm_accounts SET managed=0`, allowed: true},
		{name: "not synchronized", change: `DELETE FROM dsm_mapping_entries`},
		{name: "inactive mapping", change: `UPDATE dsm_mapping_entries SET active=0`},
		{name: "inactive source", change: `UPDATE identity_sources SET enabled=0`},
		{name: "sync paused", change: `UPDATE identity_sources SET directory_sync_enabled=0`},
		{name: "inactive user", change: `UPDATE external_accounts SET active=0`},
		{name: "inactive identity", change: `UPDATE app_identities SET status='disabled'`},
		{name: "conflict", change: `UPDATE dsm_accounts SET provision_status='conflict'`},
		{name: "wrong external link", change: `UPDATE external_accounts SET app_identity_id='other'`},
		{name: "missing account", change: `DELETE FROM dsm_accounts`},
		{name: "wrong source", field: "source_slug", value: "other"},
		{name: "wrong username", field: "dsm_username", value: "bob"},
		{name: "reserved username", field: "dsm_username", value: "root"},
		{name: "missing password", field: "password", value: ""},
		{name: "invalid password", field: "password", value: "bad\npassword"},
		{name: "pending login", pending: true},
		{name: "missing database", noStore: true},
		{name: "command failure", fail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := syncedPasswordTestStore(t, "alice")
			if tc.change != "" {
				if _, err := q.DBTX().ExecContext(context.Background(), tc.change); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			marker := filepath.Join(dir, "called")
			command := filepath.Join(dir, "synouser")
			body := "#!/bin/sh\n[ \"$1\" = --setpw ] && [ \"$2\" = alice ] && [ \"$3\" = test-password ] || exit 2\nprintf called > '" + marker + "'\n"
			if tc.fail {
				body += "echo test-password >&2\nexit 1\n"
			}
			if err := os.WriteFile(command, []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			cfg := config.HelperConfig{SynoUserPath: command, LockDir: filepath.Join(dir, "locks"), ShadowLockPath: filepath.Join(dir, "shadow.lock"), JournalDir: filepath.Join(dir, "journal")}
			if tc.pending {
				if err := os.MkdirAll(cfg.JournalDir, 0700); err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(journal{RequestID: "pending", DSMUsername: "alice", Status: journalStatusActiveBrowser})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(cfg.JournalDir, "pending.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := NewWithStore(cfg, q)
			if tc.noStore {
				s.store = nil
			}
			payload := syncedPasswordPayload("alice", "test-password")
			if tc.field != "" {
				payload[tc.field] = tc.value
			}
			err := s.resetSyncedUserPassword(cfg, payload)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, err=%v", tc.allowed, err)
			}
			if err != nil && strings.Contains(err.Error(), "test-password") {
				t.Fatal("password leaked in error")
			}
			_, statErr := os.Stat(marker)
			if (statErr == nil) != (tc.allowed || tc.fail) {
				t.Fatal("unexpected password command execution")
			}
		})
	}
}

func TestPermanentResetFailureBlocksLoginAndExplicitFullSyncCanRepair(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	q := syncedPasswordTestStore(t, "alice")
	command := filepath.Join(t.TempDir(), "synouser")
	cfg.SynoUserPath = command
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, q)
	payload := syncedPasswordPayload("alice", "test-password")
	if err := s.resetSyncedUserPassword(cfg, payload); !errors.Is(err, errPasswordResetUnknown) {
		t.Fatalf("native failure must be reported as unconfirmed: %v", err)
	}
	if _, err := prepareBrowserLogin(cfg, "blocked-login", "alice"); !errors.Is(err, errPasswordResetUnknown) {
		t.Fatalf("temporary login bypassed unconfirmed permanent reset: %v", err)
	}
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.resetSyncedUserPassword(cfg, payload); !errors.Is(err, errPasswordResetUnknown) {
		t.Fatal("same request automatically retried an unconfirmed reset")
	}
	payload["request_id"] = "explicit-full-sync-repair"
	if err := s.resetSyncedUserPassword(cfg, payload); err != nil {
		t.Fatal(err)
	}
	// A successful retry can be acknowledged without executing the command again.
	if err := os.Remove(command); err != nil {
		t.Fatal(err)
	}
	current, err := loadPasswordReset(cfg, "alice")
	if err != nil {
		t.Fatal(err)
	}
	current.Status = "applying"
	if err := savePasswordReset(cfg, current); err != nil {
		t.Fatal(err)
	}
	if err := s.resetSyncedUserPassword(cfg, payload); err != nil {
		t.Fatalf("completed request was not idempotent: %v", err)
	}
	if err := s.resetSyncedUserPassword(cfg, syncedPasswordPayload("alice", "test-password")); !errors.Is(err, errPasswordResetUnknown) {
		t.Fatal("delayed failed request was executed after a newer repair")
	}
	if err := checkPasswordResetPending(cfg, "alice"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(passwordResetPath(cfg, "alice"))
	if err != nil || strings.Contains(string(data), "test-password") {
		t.Fatal("password reset journal leaked plaintext")
	}
	payload["password"] = "different-password"
	if err := s.resetSyncedUserPassword(cfg, payload); err == nil {
		t.Fatal("reused reset ID accepted different arguments")
	}
}

func TestPermanentResetRefusesConflictingIdentitySources(t *testing.T) {
	q := syncedPasswordTestStore(t, "alice")
	if _, err := q.DBTX().ExecContext(context.Background(), `
INSERT INTO identity_sources (slug,provider_type,display_name) VALUES ('other','feishu','Other');
INSERT INTO external_accounts (id,provider_slug,subject,subject_norm,subject_type,app_identity_id,active)
VALUES ('other-external','other','subject','subject','directory_subject','identity',1);
INSERT INTO dsm_mapping_entries (id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_account_id)
VALUES ('other-mapping','user','other','other-external','','account');`); err != nil {
		t.Fatal(err)
	}
	allowed, err := db.SyncedPasswordResetAllowed(context.Background(), q, "source", "account", "alice")
	if allowed || !errors.Is(err, db.ErrSyncedPasswordSourceConflict) {
		t.Fatalf("conflicting password sources were accepted: %v", err)
	}
	if _, err := q.DBTX().ExecContext(context.Background(), `UPDATE identity_sources SET enabled=0 WHERE slug='other'`); err != nil {
		t.Fatal(err)
	}
	allowed, err = db.SyncedPasswordResetAllowed(context.Background(), q, "source", "account", "alice")
	if err != nil || !allowed {
		t.Fatalf("inactive source blocked repair: %v", err)
	}
}

func TestNativeAccountCommandHasDeadlineAndRedactsOutput(t *testing.T) {
	command := filepath.Join(t.TempDir(), "synouser")
	if err := os.WriteFile(command, []byte("#!/bin/sh\necho secret-password >&2\nsleep 20\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runAccountCommand(ctx, command)
	if err == nil || strings.Contains(err.Error(), "secret-password") || time.Since(started) > 3*time.Second {
		t.Fatalf("command timeout or redaction failed: %v", err)
	}
}
