package backend

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func OpenDatabase(ctx context.Context, databaseURL string) (*sql.DB, *db.Queries, error) {
	database, queries, err := openDatabase(ctx, databaseURL)
	if err != nil {
		return nil, nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA synchronous = NORMAL"); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	if err := db.PrepareSchema(ctx, database); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	return database, queries, nil
}

func OpenDatabaseReader(ctx context.Context, databaseURL string) (*sql.DB, *db.Queries, error) {
	return openDatabase(ctx, databaseURL)
}

func OpenLogDatabase(ctx context.Context, databaseURL string) (*sql.DB, *db.Queries, error) {
	database, queries, err := openDatabase(ctx, databaseURL)
	if err != nil {
		return nil, nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA synchronous = NORMAL"); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	if err := db.PrepareLogSchema(ctx, database); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	return database, queries, nil
}

func LogDatabaseURL(databaseURL string) string {
	if databaseURL == "sqlite://:memory:" || databaseURL == ":memory:" {
		return databaseURL
	}
	dsn := strings.TrimPrefix(databaseURL, "sqlite://")
	query := ""
	if index := strings.Index(dsn, "?"); index >= 0 {
		query = dsn[index:]
		dsn = dsn[:index]
	}
	ext := filepath.Ext(dsn)
	base := strings.TrimSuffix(dsn, ext)
	if ext == "" {
		ext = ".db"
	}
	return "sqlite://" + base + "-logs" + ext + query
}

func MigrateLogsToLogDatabase(ctx context.Context, mainDB, logDB *sql.DB) error {
	if mainDB == nil || logDB == nil || mainDB == logDB {
		return nil
	}
	if err := copyLogRows(ctx, mainDB, logDB, "sync_runs", []string{"id", "source_slug", "dry_run", "status", "started_at", "finished_at", "error"}); err != nil {
		return err
	}
	if err := copyLogRows(ctx, mainDB, logDB, "sync_operation_logs", []string{"id", "sync_run_id", "source_slug", "object_type", "object_key", "dsm_name", "action", "status", "before_state", "after_state", "error", "created_at"}); err != nil {
		return err
	}
	return copyLogRows(ctx, mainDB, logDB, "login_audit_logs", []string{"id", "request_id", "provider_slug", "external_account_id", "app_identity_id", "dsm_username", "result", "error_code", "ip_address", "ip_hash", "user_agent_hash", "duration_ms", "created_at"})
}

func copyLogRows(ctx context.Context, source, target *sql.DB, table string, columns []string) error {
	var exists int
	if err := source.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	columnList := strings.Join(columns, ", ")
	insert := `INSERT OR IGNORE INTO ` + table + ` (` + columnList + `) VALUES (` + placeholders(len(columns)) + `)`
	rows, err := source.QueryContext(ctx, `SELECT `+columnList+` FROM `+table)
	if err != nil {
		return err
	}
	defer rows.Close()
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for rows.Next() {
		values := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, insert, values...); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func openDatabase(ctx context.Context, databaseURL string) (*sql.DB, *db.Queries, error) {
	dsn := sqliteDSN(strings.TrimPrefix(databaseURL, "sqlite://"))
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, err
	}
	database.SetMaxOpenConns(5)
	database.SetMaxIdleConns(2)
	if _, err := database.ExecContext(ctx, "PRAGMA busy_timeout = 10000"); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA query_only = OFF"); err != nil {
		_ = database.Close()
		return nil, nil, err
	}
	return database, db.New(database), nil
}

func sqliteDSN(dsn string) string {
	if dsn == ":memory:" || strings.Contains(dsn, "_pragma=busy_timeout") {
		return dsn
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	return dsn + separator + "_pragma=busy_timeout(10000)"
}
