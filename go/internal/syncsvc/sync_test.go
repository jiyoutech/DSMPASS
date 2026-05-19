package syncsvc

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

func TestDisambiguateDuplicateGroupNamesUsesPathOnlyForDuplicates(t *testing.T) {
	groups := []provider.Group{
		{Subject: "sup5-a", Name: "sup5", Path: "matrix/sup1/sup2/sup5"},
		{Subject: "sup5-b", Name: "sup5", Path: "matrix/sup1/sup3/sup5"},
		{Subject: "marketing", Name: "marketing", Path: "matrix/marketing"},
	}
	got := disambiguateDuplicateGroupNames(groups)

	if got[0].Name != "matrix/sup1/sup2/sup5" {
		t.Fatalf("first duplicate name got %q", got[0].Name)
	}
	if got[1].Name != "matrix/sup1/sup3/sup5" {
		t.Fatalf("second duplicate name got %q", got[1].Name)
	}
	if got[2].Name != "marketing" {
		t.Fatalf("unique name should stay unchanged, got %q", got[2].Name)
	}
	if groups[0].Name != "sup5" {
		t.Fatalf("input groups should not be mutated")
	}
}

func TestSyncProviderMarksAllDuplicateUsersConflict(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()

	directory := fakeDirectory{
		users: []provider.User{
			{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "amktest", Active: true},
			{ProviderSlug: "feishu-main", Subject: "u2", DisplayName: "amktest", Active: true},
		},
	}
	if _, err := NewEngine(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries).SyncProvider(ctx, directory); err != nil {
		t.Fatal(err)
	}
	assertProvisionCount(t, ctx, database, "dsm_accounts", "conflict", 2)
	assertProvisionCount(t, ctx, database, "dsm_accounts", "pending", 0)
}

func TestSyncProviderKeepsExistingMappedUserWhenFeishuNameLaterDuplicates(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngine(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries)

	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		users: []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "amktest", Active: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		users: []provider.User{
			{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "amktest", Active: true},
			{ProviderSlug: "feishu-main", Subject: "u2", DisplayName: "amktest", Active: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	assertAccountStatusForSubject(t, ctx, database, "u1", "pending")
	assertAccountStatusForSubject(t, ctx, database, "u2", "conflict")
	assertProvisionCount(t, ctx, database, "dsm_accounts", "conflict", 1)
}

func TestSyncProviderMarksAllDuplicateGroupsConflict(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()

	directory := fakeDirectory{
		groups: []provider.Group{
			{ProviderSlug: "feishu-main", Subject: "g1", Name: "sup5", Path: "matrix/sup1/sup2/sup5"},
			{ProviderSlug: "feishu-main", Subject: "g2", Name: "sup5", Path: "matrix/sup1/sup3/sup5"},
		},
	}
	if _, err := NewEngine(config.BackendConfig{}, queries).SyncProvider(ctx, directory); err != nil {
		t.Fatal(err)
	}
	assertProvisionCount(t, ctx, database, "dsm_groups", "conflict", 2)
	assertProvisionCount(t, ctx, database, "dsm_groups", "pending", 0)
}

type fakeDirectory struct {
	users  []provider.User
	groups []provider.Group
}

func (f fakeDirectory) Slug() string { return "feishu-main" }

func (f fakeDirectory) ListUsers() ([]provider.User, error) { return f.users, nil }

func (f fakeDirectory) ListGroups() ([]provider.Group, error) { return f.groups, nil }

func (f fakeDirectory) ListGroupMembers(groupSubject string) ([]string, error) { return nil, nil }

func openSyncTestDB(t *testing.T, ctx context.Context) (*sql.DB, *db.Queries) {
	t.Helper()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PrepareSchema(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database, db.New(database)
}

func assertProvisionCount(t *testing.T, ctx context.Context, database *sql.DB, table, status string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE provision_status = ?", status).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s status %s got %d want %d", table, status, got, want)
	}
}

func assertAccountStatusForSubject(t *testing.T, ctx context.Context, database *sql.DB, subject, want string) {
	t.Helper()
	var got string
	err := database.QueryRowContext(ctx, `
SELECT a.provision_status
FROM external_accounts e
JOIN dsm_accounts a ON a.app_identity_id = e.app_identity_id
WHERE e.subject = ?`, subject).Scan(&got)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("subject %s status got %s want %s", subject, got, want)
	}
}
