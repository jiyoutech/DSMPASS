package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestResolveAuthorizedLoginDoesNotCreateUnsyncedUser(t *testing.T) {
	ctx := context.Background()
	database, queries := openIdentityTestDB(t, ctx)
	defer database.Close()

	service := NewService(config.BackendConfig{}, queries)
	_, _, _, err := service.ResolveAuthorizedLogin(ctx, "feishu-main", "open-id-1")
	if err == nil || !strings.Contains(err.Error(), "identity not synchronized") {
		t.Fatalf("expected unsynchronized identity error, got %v", err)
	}
	assertTableCount(t, ctx, database, "external_accounts", 0)
	assertTableCount(t, ctx, database, "app_identities", 0)
	assertTableCount(t, ctx, database, "dsm_accounts", 0)
}

func TestResolveAuthorizedLoginRequiresProvisionedAllowedAccount(t *testing.T) {
	ctx := context.Background()
	database, queries := openIdentityTestDB(t, ctx)
	defer database.Close()

	service := NewService(config.BackendConfig{UsernameReadableDelimiter: "_", UsernameReadableSuffixSize: 4}, queries)
	verified := true
	external, err := service.UpsertProfile(ctx, ExternalProfile{
		ProviderSlug:  "feishu-main",
		Subject:       "open-id-1",
		SubjectType:   "directory_subject",
		DisplayName:   "Zay",
		Email:         "zay@example.com",
		EmailVerified: &verified,
	})
	if err != nil {
		t.Fatal(err)
	}
	appIdentity, err := service.ResolveOrCreateIdentity(ctx, external)
	if err != nil {
		t.Fatal(err)
	}
	account, err := service.EnsureDSMAccount(ctx, appIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if account.ProvisionStatus != "pending" {
		t.Fatalf("expected pending account, got %#v", account)
	}
	_, _, _, err = service.ResolveAuthorizedLogin(ctx, "feishu-main", "open-id-1")
	if err == nil || !strings.Contains(err.Error(), "DSM account not provisioned") {
		t.Fatalf("expected not provisioned error, got %v", err)
	}

	_, err = queries.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = 'created', allow_login = 0 WHERE id = ?`, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = service.ResolveAuthorizedLogin(ctx, "feishu-main", "open-id-1")
	if err == nil || !strings.Contains(err.Error(), "login not allowed") {
		t.Fatalf("expected login disabled error, got %v", err)
	}

	_, err = queries.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET allow_login = 1 WHERE id = ?`, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	resolvedExternal, resolvedIdentity, resolvedAccount, err := service.ResolveAuthorizedLogin(ctx, "feishu-main", "open-id-1")
	if err != nil {
		t.Fatal(err)
	}
	if resolvedExternal.ID != external.ID || resolvedIdentity.ID != appIdentity.ID || resolvedAccount.ID != account.ID {
		t.Fatalf("resolved wrong records: external=%#v identity=%#v account=%#v", resolvedExternal, resolvedIdentity, resolvedAccount)
	}
}

func openIdentityTestDB(t *testing.T, ctx context.Context) (*sql.DB, *db.Queries) {
	t.Helper()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "PRAGMA busy_timeout = 10000"); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := db.PrepareSchema(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database, db.New(database)
}

func assertTableCount(t *testing.T, ctx context.Context, database *sql.DB, table string, want int) {
	t.Helper()
	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s count got %d want %d", table, count, want)
	}
}
