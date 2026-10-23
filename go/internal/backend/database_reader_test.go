package backend

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHelperDatabaseReaderCannotWriteOrCreateDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reader.db")
	if database, _, err := OpenDatabaseReader(ctx, "sqlite://"+path); err == nil {
		database.Close()
		t.Fatal("reader created a missing database")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("reader created a database file")
	}
	writer, _, err := OpenDatabase(ctx, "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ExecContext(ctx, "CREATE TABLE reader_test (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO reader_test VALUES ('original')"); err != nil {
		t.Fatal(err)
	}
	reader, _, err := OpenDatabaseReader(ctx, "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var value string
	if err := reader.QueryRowContext(ctx, "SELECT value FROM reader_test").Scan(&value); err != nil || value != "original" {
		t.Fatalf("reader could not read committed state: %v", err)
	}
	if _, err := reader.ExecContext(ctx, "UPDATE reader_test SET value='changed'"); err == nil {
		t.Fatal("read-only Helper connection modified the database")
	}
}
