package syncsvc

import (
	"context"
	"database/sql"
	"strings"
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

func TestSyncProviderReturnsWeComHintWhenDirectoryIsEmpty(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()

	_, err := NewEngine(config.BackendConfig{}, queries).SyncProvider(ctx, fakeDirectory{
		slug: "wecom-main",
		name: "企业微信",
	})
	if err == nil {
		t.Fatal("expected empty directory error")
	}
	message := err.Error()
	for _, want := range []string{"企业微信通讯录没有返回任何部门或用户", "单独指定成员", "有成员的部门"} {
		if !strings.Contains(message, want) {
			t.Fatalf("empty directory error %q missing %q", message, want)
		}
	}
}

func TestSyncProviderAddsWarningWhenOnlyUsersReturned(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()

	result, err := NewEngine(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries).SyncProvider(ctx, fakeDirectory{
		slug:  "wecom-main",
		name:  "企业微信",
		users: []provider.User{{ProviderSlug: "wecom-main", Subject: "u1", DisplayName: "alice", Active: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var warning string
	for _, item := range result.Items {
		if item.Action == "directory_warning" {
			warning = item.DisplayName
			break
		}
	}
	for _, want := range []string{"成员 ID 列表", "已同步用户", "不会创建 DSM 部门组"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("warning %q missing %q", warning, want)
		}
	}
	assertTableCount(t, ctx, database, "external_accounts", 1)
	assertTableCount(t, ctx, database, "provider_groups", 0)
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

func TestSyncProviderLinksCrossSourceSameNameUser(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngine(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries)

	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		slug:  "source-a",
		users: []provider.User{{ProviderSlug: "source-a", Subject: "u1", DisplayName: "alice", Active: true}},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.SyncProvider(ctx, fakeDirectory{
		slug:  "source-b",
		users: []provider.User{{ProviderSlug: "source-b", Subject: "u2", DisplayName: "alice", Active: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, ctx, database, "app_identities", 1)
	assertTableCount(t, ctx, database, "dsm_accounts", 1)
	assertTableCount(t, ctx, database, "external_accounts", 2)
	assertPlanAction(t, result, "link_existing_dsm_user")
}

func TestSyncProviderKeepsCrossSourceSameNameMemberships(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngine(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries)

	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		slug:   "source-a",
		users:  []provider.User{{ProviderSlug: "source-a", Subject: "u1", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g-a"}}},
		groups: []provider.Group{{ProviderSlug: "source-a", Subject: "g-a", Name: "engineering-a"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		slug:   "source-b",
		users:  []provider.User{{ProviderSlug: "source-b", Subject: "u2", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g-b"}}},
		groups: []provider.Group{{ProviderSlug: "source-b", Subject: "g-b", Name: "engineering-b"}},
	}); err != nil {
		t.Fatal(err)
	}

	assertTableCount(t, ctx, database, "dsm_accounts", 1)
	assertActiveMemberMappingCount(t, ctx, database, "source-a", 1)
	assertActiveMemberMappingCount(t, ctx, database, "source-b", 1)
	assertDistinctActiveMemberTargets(t, ctx, database, 1, 2)
	assertTableCount(t, ctx, database, "group_members", 2)
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

func TestSyncProviderLinksCrossSourceSameNameGroup(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngine(config.BackendConfig{}, queries)

	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		slug:   "source-a",
		groups: []provider.Group{{ProviderSlug: "source-a", Subject: "g1", Name: "engineering"}},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.SyncProvider(ctx, fakeDirectory{
		slug:   "source-b",
		groups: []provider.Group{{ProviderSlug: "source-b", Subject: "g2", Name: "engineering"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, ctx, database, "dsm_groups", 1)
	assertTableCount(t, ctx, database, "provider_groups", 2)
	assertTableCount(t, ctx, database, "group_links", 2)
	assertPlanAction(t, result, "link_existing_dsm_group")
}

func TestSyncProviderMarksMovedGroupMemberForRemoval(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngineWithOptions(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries, Options{DeactivateMissingData: true})

	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		users: []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g1"}}},
		groups: []provider.Group{
			{ProviderSlug: "feishu-main", Subject: "g1", Name: "engineering"},
			{ProviderSlug: "feishu-main", Subject: "g2", Name: "ops"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE dsm_mapping_entries SET updated_at = '2000-01-01 00:00:00' WHERE provider_slug = 'feishu-main'`); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		users: []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g2"}}},
		groups: []provider.Group{
			{ProviderSlug: "feishu-main", Subject: "g1", Name: "engineering"},
			{ProviderSlug: "feishu-main", Subject: "g2", Name: "ops"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	assertMemberState(t, ctx, database, "g1", "u1", false, "disabled")
	assertMemberState(t, ctx, database, "g2", "u1", true, "pending")
}

func TestSyncProviderInheritsNestedDepartmentMemberships(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngineWithOptions(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries, Options{DeactivateMissingData: true})

	directory := fakeDirectory{
		users: []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g3"}}},
		groups: []provider.Group{
			{ProviderSlug: "feishu-main", Subject: "g1", Name: "matrix"},
			{ProviderSlug: "feishu-main", Subject: "g2", ParentSubject: "g1", Name: "sup1"},
			{ProviderSlug: "feishu-main", Subject: "g3", ParentSubject: "g2", Name: "sup2"},
		},
	}
	if _, err := engine.SyncProvider(ctx, directory); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncProvider(ctx, directory); err != nil {
		t.Fatal(err)
	}

	assertMemberState(t, ctx, database, "g1", "u1", true, "pending")
	assertMemberState(t, ctx, database, "g2", "u1", true, "pending")
	assertMemberState(t, ctx, database, "g3", "u1", true, "pending")
}

func TestSyncProviderReactivatesRemovedGroupMemberAsPending(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngineWithOptions(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries, Options{DeactivateMissingData: true})

	directory := fakeDirectory{
		users:  []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g1"}}},
		groups: []provider.Group{{ProviderSlug: "feishu-main", Subject: "g1", Name: "engineering"}},
	}
	if _, err := engine.SyncProvider(ctx, directory); err != nil {
		t.Fatal(err)
	}
	memberID := memberIDForSubject(t, ctx, database, "g1", "u1")
	if _, err := database.ExecContext(ctx, `UPDATE group_members SET active = 0, provision_status = 'removed' WHERE id = ?`, memberID); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncProvider(ctx, directory); err != nil {
		t.Fatal(err)
	}

	assertMemberState(t, ctx, database, "g1", "u1", true, "pending")
}

func TestSyncProviderCanKeepMissingGroupMembersWhenDeactivationDisabled(t *testing.T) {
	ctx := context.Background()
	database, queries := openSyncTestDB(t, ctx)
	defer database.Close()
	engine := NewEngineWithOptions(config.BackendConfig{UsernameReadableDelimiter: "_"}, queries, Options{DeactivateMissingData: false})

	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		users:  []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "alice", Active: true, DepartmentSubjects: []string{"g1"}}},
		groups: []provider.Group{{ProviderSlug: "feishu-main", Subject: "g1", Name: "engineering"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.SyncProvider(ctx, fakeDirectory{
		users:  []provider.User{{ProviderSlug: "feishu-main", Subject: "u1", DisplayName: "alice", Active: true}},
		groups: []provider.Group{{ProviderSlug: "feishu-main", Subject: "g1", Name: "engineering"}},
	}); err != nil {
		t.Fatal(err)
	}

	assertMemberState(t, ctx, database, "g1", "u1", true, "pending")
}

type fakeDirectory struct {
	slug   string
	name   string
	users  []provider.User
	groups []provider.Group
}

func (f fakeDirectory) Slug() string {
	if f.slug != "" {
		return f.slug
	}
	return "feishu-main"
}

func (f fakeDirectory) ProviderDisplayName() string { return f.name }

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

func assertTableCount(t *testing.T, ctx context.Context, database *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s count got %d want %d", table, got, want)
	}
}

func assertPlanAction(t *testing.T, result Result, action string) {
	t.Helper()
	for _, item := range result.Items {
		if item.Action == action {
			return
		}
	}
	t.Fatalf("missing plan action %s in %#v", action, result.Items)
}

func assertActiveMemberMappingCount(t *testing.T, ctx context.Context, database *sql.DB, providerSlug string, want int) {
	t.Helper()
	var got int
	err := database.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM dsm_mapping_entries
WHERE mapping_type = 'member' AND provider_slug = ? AND active = 1`, providerSlug).Scan(&got)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("provider %s active member mapping count got %d want %d", providerSlug, got, want)
	}
}

func assertDistinctActiveMemberTargets(t *testing.T, ctx context.Context, database *sql.DB, wantAccounts, wantGroups int) {
	t.Helper()
	var accounts, groups int
	err := database.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT dsm_account_id), COUNT(DISTINCT dsm_group_id)
FROM dsm_mapping_entries
WHERE mapping_type = 'member' AND active = 1`).Scan(&accounts, &groups)
	if err != nil {
		t.Fatal(err)
	}
	if accounts != wantAccounts || groups != wantGroups {
		t.Fatalf("active member targets got accounts=%d groups=%d want accounts=%d groups=%d", accounts, groups, wantAccounts, wantGroups)
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

func assertMemberState(t *testing.T, ctx context.Context, database *sql.DB, groupSubject, userSubject string, wantActive bool, wantStatus string) {
	t.Helper()
	var active int
	var status string
	err := database.QueryRowContext(ctx, `
SELECT m.active, m.provision_status
FROM group_members m
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups p ON p.id = l.provider_group_id
JOIN dsm_accounts a ON a.id = m.dsm_account_id
JOIN external_accounts e ON e.app_identity_id = a.app_identity_id
WHERE p.subject = ? AND e.subject = ?`, groupSubject, userSubject).Scan(&active, &status)
	if err != nil {
		t.Fatal(err)
	}
	if (active != 0) != wantActive || status != wantStatus {
		t.Fatalf("member %s:%s got active=%t status=%s want active=%t status=%s", groupSubject, userSubject, active != 0, status, wantActive, wantStatus)
	}
}

func memberIDForSubject(t *testing.T, ctx context.Context, database *sql.DB, groupSubject, userSubject string) string {
	t.Helper()
	var id string
	err := database.QueryRowContext(ctx, `
SELECT m.id
FROM group_members m
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups p ON p.id = l.provider_group_id
JOIN dsm_accounts a ON a.id = m.dsm_account_id
JOIN external_accounts e ON e.app_identity_id = a.app_identity_id
WHERE p.subject = ? AND e.subject = ?`, groupSubject, userSubject).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
