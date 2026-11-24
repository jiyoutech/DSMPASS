package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionPreservesNativeDisable(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, syncedPasswordTestStore(t, "alice"))
	for _, expiry := range []string{"true", "unknown"} {
		script := "#!/bin/sh\ncase \"$1\" in\n--get) echo 'Expired : [" + expiry + "]';;\n*) touch \"$0.modified\";;\nesac\n"
		if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		result := s.provisionAccount(context.Background(), cfg, map[string]any{"dsm_username": "alice", "display_name": "New"})
		if result["success"] == true || (expiry == "true" && result["error_code"] != "DSM_ACCOUNT_DISABLED") {
			t.Fatal(result)
		}
		if _, err := os.Stat(cfg.SynoUserPath + ".modified"); !os.IsNotExist(err) {
			t.Fatal("modified an account without a confirmed active state", err)
		}
	}
}

func TestSyncRestoreRequiresSameLiveIdentityAndObservedDSMTransition(t *testing.T) {
	for _, tc := range []struct {
		name, change             string
		alreadyDisabled, restore bool
	}{
		{"returned employee", "", false, true},
		{"manual disable before departure", "", true, false},
		{"different subject", "UPDATE external_accounts SET subject='replacement'", false, false},
		{"manual login block", "UPDATE dsm_accounts SET manual_login_blocked=1", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := policyTestConfig(t)
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			script := `#!/bin/sh
case "$1" in
--get) if [ -f "$0.disabled" ]; then echo 'Expired : [true]'; else echo 'Expired : [false]'; fi ;;
--modify) if [ "$4" = 1 ]; then touch "$0.disabled"; else rm "$0.disabled"; fi ;;
*) exit 1 ;;
esac
`
			if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if tc.alreadyDisabled {
				writeFile(t, cfg.SynoUserPath+".disabled", "1")
			}
			if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			change := func(query string) {
				t.Helper()
				if _, err := q.DBTX().ExecContext(ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			change("UPDATE dsm_mapping_entries SET active=0; INSERT INTO sync_runs(id,source_slug,status,dry_run) VALUES('r','source','running',0)")
			s := NewWithStore(cfg, q)
			r := s.disableAccount(cfg, map[string]any{"action": "scoped_disable_missing_user", "source_slug": "source", "account_id": "account", "subject": "subject", "run_id": "r", "dsm_username": "alice"})
			if r["disabled"] != true {
				t.Fatal(r)
			}
			change("UPDATE dsm_mapping_entries SET active=1; UPDATE dsm_accounts SET provision_status='disabled',allow_login=0")
			if tc.change != "" {
				change(tc.change)
			}
			r = s.provisionAccount(ctx, cfg, map[string]any{"dsm_username": "alice"})
			if (r["success"] == true) != tc.restore {
				t.Fatal(r)
			}
			_, err := os.Stat(cfg.SynoUserPath + ".disabled")
			if os.IsNotExist(err) != tc.restore {
				t.Fatal("native disable flag", err)
			}
			if tc.restore {
				writeFile(t, cfg.SynoUserPath+".disabled", "1")
				if got := s.provisionAccount(ctx, cfg, map[string]any{"dsm_username": "alice"}); got["success"] == true {
					t.Fatal("reused a consumed disable receipt")
				}
			}
		})
	}
}
