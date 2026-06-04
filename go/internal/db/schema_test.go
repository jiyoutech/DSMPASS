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
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("index %s count got %d want 1", name, count)
		}
	}
}
