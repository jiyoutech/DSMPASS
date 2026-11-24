package backend

import (
	"context"
	"database/sql"
	"errors"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"testing"
	"time"
)

type retryCleanupHelper struct {
	testHelper
	db       *sql.DB
	requests map[string]string
	fail     bool
}

func (h *retryCleanupHelper) CleanupUser(ctx context.Context, id, source, account, name string) (string, error) {
	// With only one connection, this write would block inside an open transaction.
	if _, err := h.db.ExecContext(ctx, "UPDATE identity_sources SET enabled=enabled WHERE slug=?", source); err != nil {
		return "", err
	}
	if previous := h.requests[name]; previous != "" && previous != id {
		return "", errors.New("cleanup request ID changed")
	}
	h.requests[name] = id
	if h.fail && name == "bob" {
		return "", errors.New("temporary native failure")
	}
	return "disabled", nil
}
func TestCleanupRetriesAfterPartialDisableOutsideTransaction(t *testing.T) {
	for _, remove := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		database.SetMaxOpenConns(1)
		if _, err := database.ExecContext(ctx, "INSERT INTO identity_sources(slug,provider_type,display_name) VALUES('src','feishu','test')"); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"alice", "bob"} {
			seedSyncedAccount(t, ctx, database, "src", name, "ext-"+name, name, name, "2000-01-01")
		}
		if _, err := database.ExecContext(ctx, "INSERT INTO dingtalk_offboarding VALUES(\x27src\x27,\x27retired\x27,\x27employee\x27,\x27old\x27,\x27departed\x27)"); err != nil {
			t.Fatal(err)
		}
		h := &retryCleanupHelper{db: database, requests: map[string]string{}, fail: true}
		s := newServer(config.BackendConfig{}, h, database, q)
		if _, _, err := s.runProviderCleanup(ctx, "src", remove, nil); err == nil {
			t.Fatal("partial cleanup succeeded")
		}
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM dsm_accounts").Scan(&count); err != nil || count != 2 {
			t.Fatal(count, err)
		}
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM source_cleanup_targets WHERE outcome='disabled'").Scan(&count); err != nil || count != 1 {
			t.Fatal(count, err)
		}
		h.fail = false
		s = newServer(config.BackendConfig{}, h, database, q)
		if _, _, err := s.runProviderCleanup(ctx, "src", remove, nil); err != nil {
			t.Fatal(err)
		}
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM dingtalk_offboarding").Scan(&count); err != nil || count != 0 {
			t.Fatal(count, err)
		}
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM source_cleanup_targets").Scan(&count); err != nil || count != 0 {
			t.Fatal(count, err)
		}
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM identity_sources").Scan(&count); err != nil || (count == 0) != remove {
			t.Fatal(count, err)
		}
	}
}
