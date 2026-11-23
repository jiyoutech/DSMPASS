//go:build dsm_integration && linux

package helperserver

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestDSMVerifiedExistingAccount(t *testing.T) {
	if os.Getenv("DSMPASS_DSM_VERIFIED_ACCOUNT_TEST") != "1" {
		t.Skip("requires explicit DSM verified-account test opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root on a DSM test host")
	}
	dir := t.TempDir()
	cfg := config.HelperConfig{PasswdPath: "/etc/passwd", GroupPath: "/etc/group", SynoUserPath: dsmIntegrationSynouserPath,
		AccountPolicyPath: filepath.Join(dir, "policy.json"), LockDir: filepath.Join(dir, "locks"), JournalDir: filepath.Join(dir, "journal"), ShadowLockPath: filepath.Join(dir, "writer.lock"),
		DSMLoginAPI: "https://127.0.0.1:5001/webapi/entry.cgi", DSMTLSSkipVerify: true, DSMSession: "webui", DSMTimeoutSeconds: 10,
	}
	var nonce [7]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("dspverify%x", nonce)
	mail := name + "@example.invalid"
	if err := verifyAccountAbsent(cfg, name); err != nil {
		t.Fatal(err)
	}
	if err := runAccountCommand(context.Background(), cfg.SynoUserPath, synouserAddArgs(name, "Aa7!"+randomPassword(40), "DSMPASS verified fixture", mail)...); err != nil {
		t.Fatal(err)
	}
	user, err := normalUser(cfg, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created isolated ordinary DSM fixture %s", name)
	t.Cleanup(func() {
		current, err := normalUser(cfg, name)
		if err != nil || current.id != user.id {
			t.Errorf("fixture UID changed: %v", err)
			return
		}
		if err := run(cfg.SynoUserPath, "--del", name); err != nil {
			t.Error(err)
			return
		}
		if _, err := normalUser(cfg, name); err != os.ErrNotExist {
			t.Errorf("fixture still present: %v", err)
		}
	})
	q := syncedPasswordTestStore(t, name)
	ctx := context.Background()
	if _, err := q.DBTX().ExecContext(ctx, "UPDATE external_accounts SET email_norm=?,email_verified=1", mail); err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.DirectoryUsers = map[string]directoryUserGrant{name: {UID: user.id}}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateAccountPolicy(cfg, nil, func() (*db.HelperEnrollmentSnapshot, error) { return db.HelperEnrollmentCandidates(ctx, q) }); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, q)
	if r := s.provisionAccount(cfg, map[string]any{"dsm_username": name}); r["success"] != true || r["created"] != false {
		t.Fatal(r)
	}
	if err := s.authorizeLogin(cfg, map[string]any{"dsm_username": name, "identity_id": "identity", "login_source": "source"}); err != nil {
		t.Fatal(err)
	}
	password := "Aa8!" + randomPassword(40)
	if err := s.resetSyncedUserPassword(cfg, syncedPasswordPayload(name, password)); err != nil {
		t.Fatal(err)
	}
	result, err := dsmLogin(cfg, "verified-fixture", name, password)
	if err != nil {
		t.Fatal(err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	assertDSMSMBLogin(t, name, password)
	t.Log("automatic link, login authorization, permanent reset, DSM and SMB authentication verified")
}
