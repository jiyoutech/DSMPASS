package helperserver

import (
	"context"
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
