package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestDingTalkDisableChecksBoundSourceAndCurrentRunInsideHelper(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	marker := cfg.SynoUserPath + ".disabled"
	script := "#!/bin/sh\ncase \"$1\" in\n--get) if [ -f '" + marker + "' ]; then echo 'Expired : [true]'; fi; exit 0;;\n--modify) [ \"$2\" = alice ] && [ \"$4\" = 1 ] && echo disabled >> '" + marker + "' ;;\n*) exit 1;;\nesac\n"
	if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	q := syncedPasswordTestStore(t, "alice")
	change := func(sql string) {
		t.Helper()
		if _, err := q.DBTX().ExecContext(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	change("UPDATE identity_sources SET provider_type='dingtalk'; UPDATE external_accounts SET active=0; UPDATE dsm_mapping_entries SET active=0; INSERT INTO sync_runs(id,source_slug,status,dry_run) VALUES('run','source','running',0)")
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.DirectoryUsers = map[string]directoryUserGrant{"alice": {UID: 1026, DingTalk: &db.DingTalkUserBinding{SourceSlug: "source", Subject: "subject"}}}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	server := NewWithStore(cfg, q)
	payload := map[string]any{"action": "scoped_disable_dingtalk_user", "dsm_username": "alice", "account_id": "account", "subject": "subject", "run_id": "run", "source_slug": "source"}
	check := func(want bool) {
		t.Helper()
		r := server.disableAccount(cfg, payload)
		if (r["success"] == true) != want {
			t.Fatalf("disable response %#v", r)
		}
	}
	check(false)
	change("INSERT INTO dingtalk_offboarding(source_slug,account_id,subject,run_id,reason) VALUES('source','account','subject','run','disabled')")
	for _, key := range []string{"source_slug", "account_id", "subject", "run_id", "action"} {
		original := payload[key]
		payload[key] = "other"
		check(false)
		payload[key] = original
	}
	change("UPDATE external_accounts SET active=1")
	check(false)
	change("UPDATE external_accounts SET active=0")
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unconfirmed disable reached DSM", err)
	}
	change("INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name,active) VALUES('other','source','other','other','directory_subject','alice',1)")
	candidates, err := db.DingTalkOffboardingCandidates(context.Background(), q, "source")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("namesake hid departed employee: %v, %v", candidates, err)
	}
	check(true)
	if output, err := os.ReadFile(marker); err != nil || string(output) != "disabled\n" {
		t.Fatal("missing native disable", err)
	}
	change("UPDATE sync_runs SET status='success'")
	check(false)
}

func TestOffboardNeverCreatedAccountNeedsConfirmedAbsence(t *testing.T) {
	for _, sourceType := range []string{"feishu", "wecom", "dingtalk"} {
		t.Run(sourceType, func(t *testing.T) { checkAbsentDeparted(t, sourceType) })
	}
}
func checkAbsentDeparted(t *testing.T, sourceType string) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	name := "never-created"
	q := syncedPasswordTestStore(t, name)
	if _, err := q.DBTX().ExecContext(context.Background(), `UPDATE identity_sources SET provider_type='dingtalk';
UPDATE dsm_accounts SET provision_status='failed'; UPDATE external_accounts SET active=0;
INSERT INTO sync_runs(id,source_slug,status,dry_run) VALUES('run','source','running',0);
INSERT INTO dingtalk_offboarding VALUES('source','account','subject','run','departed')`); err != nil {
		t.Fatal(err)
	}
	if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE identity_sources SET provider_type=?; ", sourceType); err != nil {
		t.Fatal(err)
	}
	if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_mapping_entries SET active=0"); err != nil {
		t.Fatal(err)
	}
	action := "scoped_disable_dingtalk_user"
	if sourceType != "dingtalk" {
		action = "scoped_disable_missing_user"
	}
	s := NewWithStore(cfg, q)
	payload := map[string]any{"action": action, "source_slug": "source", "dsm_username": name, "subject": "subject", "account_id": "account", "run_id": "run"}
	for _, tc := range []struct {
		message         string
		pending, absent bool
	}{
		{"permission denied", false, false}, {"synoerr=[0x1d00]", false, true}, {"synoerr=[0x1d00]", true, false},
	} {
		if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\necho '"+tc.message+"' >&2\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if tc.pending {
			if err := (creationTarget{cfg: cfg, name: name}).begin(); err != nil {
				t.Fatal(err)
			}
		}
		got := s.disableAccount(cfg, payload)
		if (got["absent"] == true) != tc.absent || (got["success"] == true) != tc.absent {
			t.Fatal(got)
		}
	}
}

func TestDirectoryOnlyDeparturePreservesNativeUser(t *testing.T) {
	cfg := policyTestConfig(t)
	q := syncedPasswordTestStore(t, "alice")
	_, err := q.DBTX().ExecContext(context.Background(), "UPDATE external_accounts SET active=0; UPDATE dsm_mapping_entries SET active=0; INSERT INTO sync_runs(id,source_slug,status,dry_run) VALUES('run','source','running',0)")
	if err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.DirectoryUsers = map[string]directoryUserGrant{"alice": {UID: 1026}}
	if err := saveAccountPolicy(cfg, p); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, q)
	for range 2 {
		r := s.disableAccount(cfg, map[string]any{"action": "scoped_disable_missing_user", "source_slug": "source", "subject": "subject", "account_id": "account", "run_id": "run", "dsm_username": "alice"})
		if r["success"] != true || r["membership_only"] != true || r["disabled"] != false {
			t.Fatal(r)
		}
	}
}
