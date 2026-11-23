//go:build dsm_integration && linux

package helperserver

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Compare the native work of the old and new full-sync paths on the same accounts.
// Test each supplied password against DSM and SMB before executing the legacy reset.
func TestDSMFullSyncPasswordAtCreation(t *testing.T) {
	f := newBatchFixtures(t, "DSMPASS_DSM_FRESH_PASSWORD_TEST", "1")
	cfg := f.cfg
	dir := t.TempDir()
	cfg.LockDir = filepath.Join(dir, "locks")
	cfg.JournalDir = filepath.Join(dir, "journal")
	cfg.DSMLoginAPI = "https://127.0.0.1:5001/webapi/entry.cgi"
	cfg.DSMTLSSkipVerify = true
	cfg.DSMSession = "webui"
	cfg.DSMTimeoutSeconds = 10
	var creation, reset time.Duration
	for i := range 12 {
		name := fmt.Sprintf("%sc%02d", f.prefix, i)
		password := "D9!v" + randomPassword(36)
		s := NewWithStore(cfg, syncedPasswordTestStore(t, name))
		f.create(t, name, false, func() error {
			start := time.Now()
			result := s.provisionAccount(cfg, map[string]any{"dsm_username": name, "display_name": "DSMPASS fresh password fixture", "initial_password": password})
			creation += time.Since(start)
			if result["success"] != true || result["created"] != true || result["initial_password_applied"] != true {
				return fmt.Errorf("unconfirmed fixture creation: %v", result)
			}
			return nil
		})
		sid, err := dsmLogin(cfg, "fresh-account-verify", name, password)
		if err != nil {
			t.Fatal(err)
		}
		registerDSMSessionCleanup(t, cfg, sid.SID)
		assertDSMSMBLogin(t, name, password)
		values := syncedPasswordPayload(name, password)
		values["request_id"] = fmt.Sprintf("legacy-control-%d", i)
		start := time.Now()
		if err := s.resetSyncedUserPassword(cfg, values); err != nil {
			t.Fatal(err)
		}
		reset += time.Since(start)
	}
	t.Logf("12 DSM and SMB logins verified before reset; creation=%s redundant_reset=%s old_native_total=%s", creation.Round(time.Millisecond), reset.Round(time.Millisecond), (creation + reset).Round(time.Millisecond))
}
