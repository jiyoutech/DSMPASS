package backend

import (
	"context"
	"database/sql"
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

func openDatabase(ctx context.Context, databaseURL string) (*sql.DB, *db.Queries, error) {
	dsn := strings.TrimPrefix(databaseURL, "sqlite://")
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
