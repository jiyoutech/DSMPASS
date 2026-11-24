package helperserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestDingTalkVerifiedDirectoryLogin(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.ShadowPath = filepath.Join(filepath.Dir(cfg.PasswdPath), "shadow")
	writeFile(t, cfg.ShadowPath, "alice:$old:19000:0:99999:7:::\n")
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	writeProfile := func(mail string) {
		t.Helper()
		if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] && [ \"$2\" = alice ] || exit 1\necho 'User Mail : ["+mail+"]'\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeProfile("employee@company.example")
	cfg.HMACSecret = "test-secret"
	cfg.TimestampSkewSeconds = 60
	cfg.OpenSSLPath = testShadowHashCommand(t)
	cfg.TempPasswordLength = 32
	q := syncedPasswordTestStore(t, "alice")
	var blockDuringRelay atomic.Bool
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api") == "SYNO.API.Auth" {
			if blockDuringRelay.Load() {
				if _, err := q.DBTX().ExecContext(r.Context(), "UPDATE dsm_accounts SET allow_login=0"); err != nil {
					t.Error(err)
				}
			}
			if r.URL.Query().Get("account") != "alice" {
				t.Error("wrong DSM login account")
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"test-session"}}`))
		} else {
			_, _ = w.Write([]byte(`{"isLogined":true}`))
		}
	}))
	defer auth.Close()
	cfg.DSMLoginAPI = auth.URL
	cfg.DSMTimeoutSeconds = 2
	server := NewWithStore(cfg, q)
	exec := func(statement string) {
		t.Helper()
		if _, err := q.DBTX().ExecContext(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
	}
	setup := func() {
		t.Helper()
		_, err := migrateAccountPolicy(cfg, nil, func() (*db.HelperEnrollmentSnapshot, error) {
			return db.HelperEnrollmentCandidates(context.Background(), q)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	payload := map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}
	exec("UPDATE identity_sources SET provider_type='dingtalk'; UPDATE external_accounts SET display_name='alice'")
	setup()
	exec("UPDATE external_accounts SET email_verified=1, email_norm='employee@company.example'")
	setup()
	if err := server.authorizeLogin(cfg, payload); err == nil {
		t.Fatal("personal email or historical profile verification granted login")
	}
	exec("UPDATE external_accounts SET dingtalk_org_email='unknown'")
	setup()
	if err := server.authorizeLogin(cfg, payload); err == nil {
		t.Fatal("accepted a malformed organization mailbox")
	}
	exec("UPDATE external_accounts SET dingtalk_org_email='employee@company.example'")
	if err := server.authorizeLogin(cfg, payload); err == nil {
		t.Fatal("package database alone granted login")
	}
	setup()
	setup()
	writeProfile("different@company.example")
	if err := server.authorizeLogin(cfg, payload); err == nil {
		t.Fatal("accepted different local DSM owner")
	}
	writeProfile("EMPLOYEE@company.example")
	if err := server.authorizeLogin(cfg, payload); err != nil {
		t.Fatal(err)
	}
	if err := server.resetSyncedUserPassword(cfg, syncedPasswordPayload("alice", "test-only")); !errors.Is(err, errDingTalkMembershipOnly) {
		t.Fatalf("directory-only password policy changed: %v", err)
	}
	for _, tc := range []struct{ name, change, undo string }{
		{"changed subject", "UPDATE external_accounts SET subject='another'", "UPDATE external_accounts SET subject='subject'"},
		{"changed org email", "UPDATE external_accounts SET dingtalk_org_email=NULL", "UPDATE external_accounts SET dingtalk_org_email='employee@company.example'"},
		{"manual block", "UPDATE dsm_accounts SET manual_login_blocked=1", "UPDATE dsm_accounts SET manual_login_blocked=0"},
		{"disabled login", "UPDATE identity_sources SET login_enabled=0", "UPDATE identity_sources SET login_enabled=1"},
		{"inactive identity", "UPDATE external_accounts SET active=0", "UPDATE external_accounts SET active=1"},
		{"duplicate name", "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name) VALUES ('dup','source','other','other','user','alice')", "DELETE FROM external_accounts WHERE id='dup'"},
		{"duplicate mailbox", "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,dingtalk_org_email) VALUES ('dup','source','other','other','user','employee@company.example')", "DELETE FROM external_accounts WHERE id='dup'"},
		{"second external identity", "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id) VALUES ('dup','source','other','other','user','identity')", "DELETE FROM external_accounts WHERE id='dup'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec(tc.change)
			t.Cleanup(func() { exec(tc.undo) })
			if err := server.authorizeLogin(cfg, payload); err == nil {
				t.Fatal("accepted invalid binding")
			}
		})
	}
	passwd, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, strings.Replace(string(passwd), "alice:x:1026:", "alice:x:2026:", 1))
	if err := server.authorizeLogin(cfg, payload); err == nil {
		t.Fatal("accepted a replacement DSM UID")
	}
	writeFile(t, cfg.PasswdPath, string(passwd))
	call := func(action, requestID string) map[string]any {
		return server.handlePayload(signedPayload(t, cfg.HMACSecret, map[string]any{"action": action, "request_id": requestID, "dsm_username": "alice", "identity_id": "identity", "login_source": "source"}))
	}
	if result := call("scoped_prepare_browser_login", "browser-login"); result["success"] != true {
		t.Fatalf("helper failed: %v", result["error_code"])
	}
	if result := call("complete_browser_login", "browser-login"); result["success"] != true {
		t.Fatalf("helper failed: %v", result["error_code"])
	}
	if result := call("scoped_relay_login", "relay-login"); result["success"] != true || result["sid"] != "test-session" {
		t.Fatalf("helper failed: %v", result["error_code"])
	}
	blockDuringRelay.Store(true)
	if result := call("scoped_relay_login", "revoked-during-relay"); result["success"] == true || result["sid"] != nil {
		t.Fatal("session returned after login was blocked")
	}
	if got, err := os.ReadFile(cfg.ShadowPath); err != nil || string(got) != "alice:$old:19000:0:99999:7:::\n" {
		t.Fatal("DSM credential was not restored", err)
	}
	exec("UPDATE dsm_accounts SET allow_login=1")
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	setup()
	if err := server.authorizeLogin(cfg, payload); err == nil {
		t.Fatal("re-enabled revoked user")
	}
}
