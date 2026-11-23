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
	check(true)
	if output, err := os.ReadFile(marker); err != nil || string(output) != "disabled\n" {
		t.Fatal("missing native disable", err)
	}
	change("UPDATE sync_runs SET status='success'")
	check(false)
}
