package db

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPrepareSchemaCreatesPerformanceIndexes(t *testing.T) {
	ctx := context.Background()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := PrepareSchema(ctx, database); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"deployment_settings",
		"idx_external_accounts_provider_active_seen",
		"idx_external_accounts_app_identity",
		"idx_provider_groups_provider_active_updated",
		"idx_group_links_dsm_group",
		"idx_group_members_account",
		"idx_group_members_active_status_updated",
		"idx_dsm_mapping_entries_target",
		"idx_dsm_mapping_entries_source_updated",
		"idx_sync_runs_source_started",
		"idx_sync_operation_logs_source_created",
		"idx_login_audit_logs_provider_created",
	} {
		var count int
		objectType := "index"
		if name == "deployment_settings" {
			objectType = "table"
		}
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?`, objectType, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("index %s count got %d want 1", name, count)
		}
	}
}

func TestLegacyLoginPreferenceMigratesOnce(t *testing.T) {
	ctx := context.Background()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err = PrepareSchema(ctx, database); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`ALTER TABLE dsm_accounts DROP COLUMN manual_login_blocked;
 INSERT INTO dsm_accounts(id,app_identity_id,dsm_username,dsm_username_norm,allow_login) VALUES('a','i','demo','demo',0)`); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{1, 0} {
		if err = PrepareSchema(ctx, database); err != nil {
			t.Fatal(err)
		}
		var got int
		if err = database.QueryRow("SELECT manual_login_blocked FROM dsm_accounts").Scan(&got); err != nil || got != want {
			t.Fatalf("manual block=%d want=%d err=%v", got, want, err)
		}
		if _, err = database.Exec("UPDATE dsm_accounts SET manual_login_blocked=0"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDirectoryCollationMatchesUnicodePlanning(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var equal bool
	if err := database.QueryRow("SELECT ? = ? COLLATE dsmpass_name", " Élodie ", "élodie").Scan(&equal); err != nil || !equal {
		t.Fatal(equal, err)
	}
}
