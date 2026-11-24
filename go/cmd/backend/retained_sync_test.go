package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/backend"
)

func TestRetainedInstallStartsDingTalkInManualMode(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	database, _, err := backend.OpenDatabase(ctx, "sqlite://"+filepath.Join(dir, "dsmpass.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	_, err = database.Exec(`INSERT INTO identity_sources(slug,provider_type,display_name,config_json)
	VALUES('d','dingtalk','D','{"sync_interval_minutes":10,"client_id":"saved"}'),('f','feishu','F','{"sync_interval_minutes":10}'),('empty','dingtalk','Empty','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	check := func(slug, want string) {
		t.Helper()
		var got string
		if err := database.QueryRow("SELECT config_json FROM identity_sources WHERE slug=?", slug).Scan(&got); err != nil || got != want {
			t.Fatalf("source %s got %q, error %v", slug, got, err)
		}
	}
	if err := restoreManualSync(ctx, database, dir); err != nil {
		t.Fatal(err)
	}
	check("d", `{"sync_interval_minutes":10,"client_id":"saved"}`)
	marker := filepath.Join(dir, "restore-manual-sync")
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreManualSync(ctx, database, dir); err != nil {
		t.Fatal(err)
	}
	check("d", `{"sync_interval_minutes":0,"client_id":"saved"}`)
	check("empty", "{}")
	check("f", `{"sync_interval_minutes":10}`)
	if _, err := database.Exec(`UPDATE identity_sources SET config_json='{"sync_interval_minutes":5}' WHERE slug='d'`); err != nil {
		t.Fatal(err)
	}
	if err := restoreManualSync(ctx, database, dir); err != nil {
		t.Fatal(err)
	}
	check("d", `{"sync_interval_minutes":5}`)
}
