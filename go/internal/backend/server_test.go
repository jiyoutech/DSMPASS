package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

type testHelper struct{}

func stubTCPPortAvailable(t *testing.T) {
	t.Helper()
	original := tcpPortAvailable
	tcpPortAvailable = func(string) error { return nil }
	t.Cleanup(func() { tcpPortAvailable = original })
}

func (testHelper) HealthCheck(ctx context.Context) (map[string]any, error) {
	return map[string]any{"success": true}, nil
}

func (testHelper) RelayLogin(ctx context.Context, requestID, username, identityID, loginSource string) (helperclient.RelayLoginResult, error) {
	return helperclient.RelayLoginResult{SID: "sid"}, nil
}

func (testHelper) PrepareBrowserLogin(ctx context.Context, requestID, username, identityID, loginSource string) (helperclient.BrowserLoginResult, error) {
	return helperclient.BrowserLoginResult{Username: username, TempPassword: "temp-password", ExpiresAt: "2026-05-18T00:00:02Z", TTLSeconds: 2}, nil
}

func (testHelper) CompleteBrowserLogin(ctx context.Context, requestID string) error {
	return nil
}

func (testHelper) ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error) {
	return true, nil
}

type existingUserHelper struct {
	testHelper
}

func (existingUserHelper) ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error) {
	return false, nil
}

func (testHelper) DisableUser(ctx context.Context, requestID, username string) (bool, error) {
	return true, nil
}

func (testHelper) ProvisionGroup(ctx context.Context, requestID, groupname string) (bool, error) {
	return true, nil
}

func (testHelper) AddGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	return true, nil
}

func (testHelper) RemoveGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	return true, nil
}

type recordingHelper struct {
	testHelper
	disabled    []string
	provisioned []string
	removed     []string
}

func (h *recordingHelper) DisableUser(ctx context.Context, requestID, username string) (bool, error) {
	h.disabled = append(h.disabled, username)
	return true, nil
}

func (h *recordingHelper) ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error) {
	h.provisioned = append(h.provisioned, username)
	return false, nil
}

func (h *recordingHelper) RemoveGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	h.removed = append(h.removed, groupname+":"+username)
	return true, nil
}

type provisioningOrderHelper struct {
	testHelper
	operations []string
}

func (h *provisioningOrderHelper) ProvisionGroup(ctx context.Context, requestID, groupname string) (bool, error) {
	h.operations = append(h.operations, "group:"+groupname)
	return true, nil
}

func (h *provisioningOrderHelper) ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error) {
	h.operations = append(h.operations, "user:"+username)
	return true, nil
}

func (h *provisioningOrderHelper) AddGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	h.operations = append(h.operations, "member:"+groupname+":"+username)
	return true, nil
}

func TestSourceConfigDefaultsEnablePermissionCleanupButNotMissingUserDisable(t *testing.T) {
	defaults := decodeSourceConfig(`{}`)
	if boolValue(defaults.DisableMissingUsers, true) || !boolValue(defaults.DeactivateMissingData, false) {
		t.Fatalf("defaults should keep missing user disable off and permission cleanup on: %#v", defaults)
	}
	explicit := decodeSourceConfig(`{"disable_missing_users":false,"deactivate_missing_data":false}`)
	if boolValue(explicit.DisableMissingUsers, true) || boolValue(explicit.DeactivateMissingData, true) {
		t.Fatalf("explicit missing cleanup settings should be preserved: %#v", explicit)
	}
}

func TestSyncSourceToDSMMarksStaleGroupMemberForManualRemoval(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	helper := &recordingHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)
	seedSyncedAccount(t, ctx, database, "feishu-main", "identity-1", "external-1", "u1", "alice", "2999-01-01 00:00:00")
	seedGroupMember(t, ctx, database, "feishu-main", "group-1", "dsm-group-1", "member-1", "g1", "engineering", "identity-1", 0, "remove_pending")

	operations, err := server.syncSourceToDSM(ctx, "sync_test", "feishu-main", "2000-01-01 00:00:00", sourceSyncPolicy{DisableMissingUsers: true, DeactivateMissingData: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(helper.removed) != 0 {
		t.Fatalf("stale member should not be removed automatically from DSM, got %#v", helper.removed)
	}
	assertLocalMemberStatus(t, ctx, database, "member-1", 0, "disabled")
	found := false
	for _, operation := range operations {
		if operation.Action == "disable_local_group_member" && operation.DSMGroupname == "engineering" && operation.DSMUsername == "alice" && operation.ProvisionStatus == "disabled" {
			found = true
		}
	}
	if !found {
		t.Fatalf("local member disable operation missing from result: %#v", operations)
	}
}

func TestSyncSourceToDSMDisableMissingUsersPolicy(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	helper := &recordingHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)
	seedSyncedAccount(t, ctx, database, "feishu-main", "identity-1", "external-1", "u1", "alice", "2000-01-01 00:00:00")

	if _, err := server.syncSourceToDSM(ctx, "sync_test", "feishu-main", "2999-01-01 00:00:00", sourceSyncPolicy{DisableMissingUsers: false, DeactivateMissingData: false}); err != nil {
		t.Fatal(err)
	}
	if len(helper.disabled) != 0 {
		t.Fatalf("disabled missing user while policy was off: %#v", helper.disabled)
	}

	if _, err := server.syncSourceToDSM(ctx, "sync_test", "feishu-main", "2999-01-01 00:00:00", sourceSyncPolicy{DisableMissingUsers: true, DeactivateMissingData: true}); err != nil {
		t.Fatal(err)
	}
	if len(helper.disabled) != 1 || helper.disabled[0] != "alice" {
		t.Fatalf("missing user was not disabled in DSM, got %#v", helper.disabled)
	}
}

func TestSyncSourceToDSMPreservesMissingGroupsForUserOnlyDirectory(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	helper := &recordingHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)
	seedSyncedAccount(t, ctx, database, "wecom-main", "identity-1", "external-identity-1", "u1", "alice", "2000-01-01 00:00:00")
	seedGroupMember(t, ctx, database, "wecom-main", "group-1", "dsm-group-1", "member-1", "g1", "engineering", "identity-1", 1, "created")
	if _, err := database.ExecContext(ctx, `
UPDATE provider_groups SET updated_at = '2000-01-01 00:00:00' WHERE provider_slug = 'wecom-main';
UPDATE dsm_mapping_entries SET updated_at = '2000-01-01 00:00:00' WHERE provider_slug = 'wecom-main';
`); err != nil {
		t.Fatal(err)
	}

	if _, err := server.syncSourceToDSM(ctx, "sync_test", "wecom-main", "2999-01-01 00:00:00", sourceSyncPolicy{DeactivateMissingData: true, PreserveMissingGroups: true}); err != nil {
		t.Fatal(err)
	}
	var providerGroupActive, groupMappingActive, memberMappingActive, userMappingActive int
	if err := database.QueryRowContext(ctx, `SELECT active FROM provider_groups WHERE id = 'group-1'`).Scan(&providerGroupActive); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT active FROM dsm_mapping_entries WHERE id = 'map-group-member-1'`).Scan(&groupMappingActive); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT active FROM dsm_mapping_entries WHERE id = 'map-member-member-1'`).Scan(&memberMappingActive); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT active FROM dsm_mapping_entries WHERE id = 'map-user-external-identity-1'`).Scan(&userMappingActive); err != nil {
		t.Fatal(err)
	}
	if providerGroupActive != 1 || groupMappingActive != 1 || memberMappingActive != 1 {
		t.Fatalf("group data should be preserved, providerGroup=%d groupMapping=%d memberMapping=%d", providerGroupActive, groupMappingActive, memberMappingActive)
	}
	if userMappingActive != 0 {
		t.Fatalf("stale user mapping active=%d, want 0", userMappingActive)
	}
}

func TestSyncSourceToDSMReenablesMappedDisabledUser(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	helper := &recordingHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)
	seedSyncedAccount(t, ctx, database, "feishu-main", "identity-1", "external-1", "u1", "alice", "2999-01-01 00:00:00")
	if _, err := database.ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = 'disabled', allow_login = 0 WHERE id = 'account-identity-1'`); err != nil {
		t.Fatal(err)
	}

	if _, err := server.syncSourceToDSM(ctx, "sync_test", "feishu-main", "2000-01-01 00:00:00", sourceSyncPolicy{DisableMissingUsers: true, DeactivateMissingData: true}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(helper.provisioned) != fmt.Sprint([]string{"alice"}) {
		t.Fatalf("disabled mapped user should be provisioned again, got %#v", helper.provisioned)
	}
	var allowLogin int
	var status string
	if err := database.QueryRowContext(ctx, `SELECT allow_login, provision_status FROM dsm_accounts WHERE id = 'account-identity-1'`).Scan(&allowLogin, &status); err != nil {
		t.Fatal(err)
	}
	if allowLogin != 1 || status != "linked_existing" {
		t.Fatalf("disabled mapped user was not re-enabled, allow_login=%d status=%s", allowLogin, status)
	}
}

func TestSyncSourceToDSMOnlyProvisionsRequestedSource(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
	INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name, active)
	VALUES
		('provider-group-a', 'source-a', 'dep-a', 'dep-a', 'Engineering A', 1),
		('provider-group-b', 'source-b', 'dep-b', 'dep-b', 'Engineering B', 1);
	INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, provision_status)
	VALUES
		('group-a', 'engineering_a', 'engineering_a', 'pending'),
		('group-b', 'engineering_b', 'engineering_b', 'pending');
	INSERT INTO group_links (id, provider_group_id, dsm_group_id)
	VALUES
		('link-a', 'provider-group-a', 'group-a'),
		('link-b', 'provider-group-b', 'group-b');
	INSERT INTO app_identities (id, display_name, primary_email)
	VALUES
		('identity-a', 'Alice', 'alice@example.test'),
		('identity-b', 'Bob', 'bob@example.test');
	INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id, active)
	VALUES
		('external-a', 'source-a', 'user-a', 'user-a', 'user', 'identity-a', 1),
		('external-b', 'source-b', 'user-b', 'user-b', 'user', 'identity-b', 1);
	INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, provision_status, allow_login)
	VALUES
		('account-a', 'identity-a', 'alice', 'alice', 'pending', 1),
		('account-b', 'identity-b', 'bob', 'bob', 'pending', 1);
	INSERT INTO group_members (id, dsm_group_id, dsm_account_id, provision_status)
	VALUES
		('member-a', 'group-a', 'account-a', 'pending'),
		('member-b', 'group-b', 'account-b', 'pending');
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id, dsm_group_id)
	VALUES
		('map-group-a', 'group', 'source-a', '', 'provider-group-a', NULL, 'group-a'),
		('map-group-b', 'group', 'source-b', '', 'provider-group-b', NULL, 'group-b'),
		('map-user-a', 'user', 'source-a', 'external-a', '', 'account-a', NULL),
		('map-user-b', 'user', 'source-b', 'external-b', '', 'account-b', NULL),
		('map-member-a', 'member', 'source-a', 'external-a', 'provider-group-a', 'account-a', 'group-a'),
		('map-member-b', 'member', 'source-b', 'external-b', 'provider-group-b', 'account-b', 'group-b');
	`); err != nil {
		t.Fatal(err)
	}
	helper := &provisioningOrderHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)

	if _, err := server.syncSourceToDSM(ctx, "sync-a", "source-a", "2026-05-29 00:00:00", sourceSyncPolicy{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"group:engineering_a", "user:alice", "member:engineering_a:alice"}
	if fmt.Sprint(helper.operations) != fmt.Sprint(want) {
		t.Fatalf("provision operations got %v, want %v", helper.operations, want)
	}
}

func TestSyncSourceToDSMRevalidatesLinkedExistingUsers(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
	INSERT INTO app_identities (id, display_name, primary_email)
	VALUES ('identity-a', 'Alice', 'alice@example.test');
	INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id, active)
	VALUES ('external-a', 'source-a', 'user-a', 'user-a', 'user', 'identity-a', 1);
	INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, provision_status, allow_login)
	VALUES ('account-a', 'identity-a', 'alice', 'alice', 'linked_existing', 1);
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id, dsm_group_id)
	VALUES ('map-user-a', 'user', 'source-a', 'external-a', '', 'account-a', NULL);
	`); err != nil {
		t.Fatal(err)
	}
	helper := &provisioningOrderHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)

	if _, err := server.syncSourceToDSM(ctx, "sync-a", "source-a", "2026-05-29 00:00:00", sourceSyncPolicy{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"user:alice"}
	if fmt.Sprint(helper.operations) != fmt.Sprint(want) {
		t.Fatalf("provision operations got %v, want %v", helper.operations, want)
	}
}

func TestSyncSourceToDSMOnlyCleansRequestedSource(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
	INSERT INTO app_identities (id, display_name)
	VALUES ('identity-a', 'Alice'), ('identity-b', 'Bob');
	INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id, active)
	VALUES
		('external-a', 'source-a', 'user-a', 'user-a', 'user', 'identity-a', 0),
		('external-b', 'source-b', 'user-b', 'user-b', 'user', 'identity-b', 0);
	INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, provision_status, allow_login)
	VALUES
		('account-a', 'identity-a', 'alice', 'alice', 'created', 1),
		('account-b', 'identity-b', 'bob', 'bob', 'created', 1);
	INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name, active)
	VALUES
		('provider-group-a', 'source-a', 'dep-a', 'dep-a', 'Engineering A', 0),
		('provider-group-b', 'source-b', 'dep-b', 'dep-b', 'Engineering B', 0);
	INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, provision_status)
	VALUES
		('group-a', 'engineering_a', 'engineering_a', 'created'),
		('group-b', 'engineering_b', 'engineering_b', 'created');
	INSERT INTO group_links (id, provider_group_id, dsm_group_id)
	VALUES
		('link-a', 'provider-group-a', 'group-a'),
		('link-b', 'provider-group-b', 'group-b');
	INSERT INTO group_members (id, dsm_group_id, dsm_account_id, active, provision_status)
	VALUES
		('member-a', 'group-a', 'account-a', 0, 'remove_pending'),
		('member-b', 'group-b', 'account-b', 0, 'remove_pending');
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id, dsm_group_id, active)
	VALUES
		('map-user-a', 'user', 'source-a', 'external-a', '', 'account-a', NULL, 0),
		('map-user-b', 'user', 'source-b', 'external-b', '', 'account-b', NULL, 0),
		('map-member-a', 'member', 'source-a', 'external-a', 'provider-group-a', 'account-a', 'group-a', 0),
		('map-member-b', 'member', 'source-b', 'external-b', 'provider-group-b', 'account-b', 'group-b', 0);
	`); err != nil {
		t.Fatal(err)
	}
	helper := &recordingHelper{}
	server := NewWithDB(config.BackendConfig{RelayMode: "socket"}, helper, database, queries)

	if _, err := server.syncSourceToDSM(ctx, "sync-a", "source-a", "2026-05-29 00:00:00", sourceSyncPolicy{DisableMissingUsers: true, DeactivateMissingData: true}); err != nil {
		t.Fatal(err)
	}
	if len(helper.removed) != 0 {
		t.Fatalf("members should not be removed automatically from DSM, got %#v", helper.removed)
	}
	if fmt.Sprint(helper.disabled) != fmt.Sprint([]string{"alice"}) {
		t.Fatalf("disabled users got %#v", helper.disabled)
	}
}

func TestServerServesFrontendAndAPI(t *testing.T) {
	dist := t.TempDir()
	if err := os.Mkdir(filepath.Join(dist, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "index.html"), []byte("<html>app</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.BackendConfig{
		FrontendDistDir:   dist,
		RelayMode:         "socket",
		DSMRedirectURL:    "https://nas.example.com/",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := New(cfg, testHelper{}, queries).Router()

	assertStatus(t, server, "GET", "/healthz", http.StatusOK)
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/settings", nil)
	server.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), "app") {
		t.Fatalf("expected frontend fallback, got %s", response.Body.String())
	}
}

func TestAdminAccessControlRejectsOutsideCIDR(t *testing.T) {
	cfg := config.BackendConfig{
		RelayMode:         "socket",
		DSMRedirectURL:    "https://nas.example.com/",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		AdminAllowedCIDRs: "10.0.0.0/8",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/admin/auth/status", nil)
	request.RemoteAddr = "203.0.113.10:12345"
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d body=%s", response.Code, response.Body.String())
	}

	allowed := httptest.NewRecorder()
	allowedRequest := httptest.NewRequest("GET", "/api/admin/auth/status", nil)
	allowedRequest.RemoteAddr = "10.1.2.3:12345"
	router.ServeHTTP(allowed, allowedRequest)
	if allowed.Code == http.StatusForbidden {
		t.Fatalf("expected allowed network, got %d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestIDPAccessControlRequiresIntranet(t *testing.T) {
	cfg := config.BackendConfig{
		PublicBaseURL:     "https://nas.example.com:26000",
		IDPAllowedCIDRs:   "all",
		RelayMode:         "socket",
		DSMRedirectURL:    "https://nas.example.com/",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).IDPRouter()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/idp/source-a/launch", nil)
	request.Host = "nas.example.com:26000"
	request.RemoteAddr = "203.0.113.10:12345"
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d body=%s", response.Code, response.Body.String())
	}

	allowed := httptest.NewRecorder()
	allowedRequest := httptest.NewRequest("GET", "/idp/source-a/launch", nil)
	allowedRequest.Host = "nas.example.com:26000"
	allowedRequest.RemoteAddr = "192.168.1.20:12345"
	router.ServeHTTP(allowed, allowedRequest)
	if allowed.Code == http.StatusForbidden {
		t.Fatalf("expected allowed network, got %d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestNewWithDBGeneratesHelperHMACSecret(t *testing.T) {
	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	server := NewWithDB(cfg, testHelper{}, database, queries)
	if len(server.cfg.RelayHelperHMACSecret) != 64 {
		t.Fatalf("expected generated 32-byte hex helper secret, got %q", server.cfg.RelayHelperHMACSecret)
	}
	row, err := queries.GetRuntimeSetting(context.Background(), "relay_helper_hmac_secret")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := json.Unmarshal([]byte(row.ValueJson), &stored); err != nil {
		t.Fatal(err)
	}
	if stored != server.cfg.RelayHelperHMACSecret {
		t.Fatalf("stored secret does not match runtime secret")
	}
}

func TestAdminCIDRUpdateMustKeepCurrentClientAllowed(t *testing.T) {
	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	rejected := httptest.NewRecorder()
	rejectedRequest := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"admin_allowed_cidrs":"10.0.0.0/8"}`))
	rejectedRequest.Header.Set("Content-Type", "application/json")
	rejectedRequest.RemoteAddr = "203.0.113.10:12345"
	router.ServeHTTP(rejected, rejectedRequest)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", rejected.Code, rejected.Body.String())
	}

	accepted := httptest.NewRecorder()
	acceptedRequest := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"admin_allowed_cidrs":"10.0.0.0/8"}`))
	acceptedRequest.Header.Set("Content-Type", "application/json")
	acceptedRequest.RemoteAddr = "10.1.2.3:12345"
	router.ServeHTTP(accepted, acceptedRequest)
	if accepted.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d body=%s", accepted.Code, accepted.Body.String())
	}
}

func TestSettingsSecretsAreWriteOnlyAndRuntimeApplied(t *testing.T) {
	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"relay_helper_hmac_secret":"super-secret-value","relay_helper_socket":"/tmp/helper.sock"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "super-secret-value") {
		t.Fatalf("secret leaked in response: %s", response.Body.String())
	}
	if server.cfg.RelayMode != "socket" || server.cfg.RelayHelperHMACSecret != "super-secret-value" {
		t.Fatalf("runtime settings were not applied")
	}
}

func TestSettingsUpdateDoesNotPersistPartialChangesWhenLaterValidationFails(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		IDPListen:         "0.0.0.0:26000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		PublicBaseURL:     "https://192.0.2.10:26000",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"access_scheme":"http","helper_dsm_login_mode":"invalid"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", response.Code, response.Body.String())
	}
	row, err := queries.GetDeploymentSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.AccessScheme != "https" || server.cfg.AccessScheme != "https" {
		t.Fatalf("partial settings update was persisted: row=%#v runtime_scheme=%q", row, server.cfg.AccessScheme)
	}
}

func TestSettingsResponseReportsIDPRouteRestartError(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		IDPListen:         "0.0.0.0:26000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		PublicBaseURL:     "https://192.0.2.10:26000",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"access_scheme":"http","helper_dsm_login_mode":"helper"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"idp_route_restart_required":true`,
		`"idp_route_restarted":false`,
		"idp route restarter is not configured",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings response missing %q: %s", want, body)
		}
	}
}

func TestRestartHelperEndpointUsesHelperControlScript(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	script := filepath.Join(dir, "helper-control.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$1\" > '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := helperControlScripts
	helperControlScripts = []string{script}
	t.Cleanup(func() {
		helperControlScripts = original
	})

	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/admin/helper/restart", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	called, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(called) != "restart" {
		t.Fatalf("helper-control called with %q", string(called))
	}
}

func TestProviderOAuthURLsUseConfiguredPublicBaseURL(t *testing.T) {
	cfg := config.BackendConfig{
		PublicBaseURL:     "https://nas.example.com:25000",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{"provider_type":"feishu","display_name":"Feishu","config":{"client_id":"cli_test","client_secret":"secret"}}`))
	createRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusOK {
		t.Fatalf("create provider got %d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Slug        string `json:"slug"`
		LoginURL    string `json:"login_url"`
		CallbackURL string `json:"callback_url"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.LoginURL != "https://nas.example.com:25000/idp/"+created.Slug+"/launch" {
		t.Fatalf("login_url used untrusted host: %s", created.LoginURL)
	}
	if created.CallbackURL != "https://nas.example.com:25000/idp/"+created.Slug+"/callback" {
		t.Fatalf("callback_url used untrusted host: %s", created.CallbackURL)
	}

	listResponse := httptest.NewRecorder()
	listRequest := httptest.NewRequest("GET", "/api/admin/providers", nil)
	listRequest.Host = "evil.example.com"
	listRequest.Header.Set("X-Forwarded-Host", "evil-forwarded.example.com")
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list providers got %d body=%s", listResponse.Code, listResponse.Body.String())
	}
	if strings.Contains(listResponse.Body.String(), "evil") {
		t.Fatalf("provider response trusted request host: %s", listResponse.Body.String())
	}

	launchResponse := httptest.NewRecorder()
	launchRequest := httptest.NewRequest("GET", "/idp/"+created.Slug+"/launch", nil)
	launchRequest.Host = "evil.example.com"
	launchRequest.Header.Set("X-Forwarded-Host", "evil-forwarded.example.com")
	router.ServeHTTP(launchResponse, launchRequest)
	if launchResponse.Code != http.StatusForbidden {
		t.Fatalf("launch through wrong IDP host got %d body=%s", launchResponse.Code, launchResponse.Body.String())
	}

	launchResponse = httptest.NewRecorder()
	launchRequest = httptest.NewRequest("GET", "/idp/"+created.Slug+"/launch", nil)
	launchRequest.Host = "nas.example.com:25000"
	launchRequest.RemoteAddr = "192.168.1.20:12345"
	launchRequest.Header.Set("X-Forwarded-Host", "evil-forwarded.example.com")
	router.ServeHTTP(launchResponse, launchRequest)
	if launchResponse.Code != http.StatusOK {
		t.Fatalf("launch got %d body=%s", launchResponse.Code, launchResponse.Body.String())
	}
	body := launchResponse.Body.String()
	matches := regexp.MustCompile(`var authorizeURL = "([^"]+)"`).FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("launch did not render authorize URL: %s", body)
	}
	location, err := strconv.Unquote(`"` + matches[1] + `"`)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	redirectURI := parsed.Query().Get("redirect_uri")
	if redirectURI != "https://nas.example.com:25000/idp/"+created.Slug+"/callback" {
		t.Fatalf("launch redirect_uri used untrusted host: %s location=%s", redirectURI, location)
	}
	if strings.Contains(body, "evil-forwarded.example.com") {
		t.Fatalf("launch trusted X-Forwarded-Host: %s", body)
	}
	if !strings.Contains(body, `method=logout`) || !strings.Contains(body, `session=webui`) {
		t.Fatalf("launch should call DSM logout before authorization: %s", body)
	}
	cookies := launchResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "id" || cookies[0].MaxAge != -1 {
		t.Fatalf("launch should expire existing DSM session before authorization, got %#v", cookies)
	}
}

func TestWeComProviderRequiresAgentIDForConfiguredCredentials(t *testing.T) {
	cfg := config.BackendConfig{
		PublicBaseURL:     "https://nas.example.com",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{"provider_type":"wecom","display_name":"企业微信","config":{"client_id":" wwcorp ","client_secret":" secret "}}`))
	createRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusOK {
		t.Fatalf("create provider got %d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Slug                  string `json:"slug"`
		ProviderType          string `json:"provider_type"`
		CredentialsConfigured bool   `json:"credentials_configured"`
		WeComAuthorizeURL     string `json:"wecom_authorize_url"`
		Config                struct {
			ClientID     string `json:"client_id"`
			AgentID      string `json:"agent_id"`
			AuthorizeURL string `json:"authorize_url"`
			TokenURL     string `json:"token_url"`
		} `json:"config"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ProviderType != "wecom" || created.CredentialsConfigured {
		t.Fatalf("wecom without agent_id should not be fully configured: %#v", created)
	}
	if created.Config.TokenURL != "https://qyapi.weixin.qq.com/cgi-bin/gettoken" {
		t.Fatalf("unexpected wecom token URL: %s", created.Config.TokenURL)
	}
	if created.Config.ClientID != "wwcorp" {
		t.Fatalf("wecom client_id should be trimmed, got %q", created.Config.ClientID)
	}
	if created.Config.AuthorizeURL != "https://open.work.weixin.qq.com/wwopen/sso/qrConnect" {
		t.Fatalf("wecom default authorize URL should use QR login, got %q", created.Config.AuthorizeURL)
	}
	if !strings.Contains(created.WeComAuthorizeURL, "open.work.weixin.qq.com/wwopen/sso/qrConnect") || !strings.Contains(created.WeComAuthorizeURL, "appid=wwcorp") || strings.Contains(created.WeComAuthorizeURL, "agentid=") || strings.Contains(created.WeComAuthorizeURL, "wechat_redirect") {
		t.Fatalf("unexpected authorize URL without agent_id: %s", created.WeComAuthorizeURL)
	}

	updateResponse := httptest.NewRecorder()
	updateRequest := httptest.NewRequest("PUT", "/api/admin/providers/"+created.Slug, strings.NewReader(`{"config":{"agent_id":" 1000002 "}}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update provider got %d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	var updated struct {
		CredentialsConfigured bool   `json:"credentials_configured"`
		WeComAuthorizeURL     string `json:"wecom_authorize_url"`
		Config                struct {
			AgentID string `json:"agent_id"`
		} `json:"config"`
	}
	if err := json.Unmarshal(updateResponse.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.CredentialsConfigured || updated.Config.AgentID != "1000002" || !strings.Contains(updated.WeComAuthorizeURL, "open.work.weixin.qq.com/wwopen/sso/qrConnect") || !strings.Contains(updated.WeComAuthorizeURL, "agentid=1000002") {
		t.Fatalf("wecom with agent_id should be fully configured: %#v", updated)
	}
}

func TestWeComSourceConfigUpgradesLegacyAuthorizeURL(t *testing.T) {
	config := decodeSourceConfigForType("wecom", `{"authorize_url":"https://open.weixin.qq.com/connect/oauth2/authorize"}`)
	if config.AuthorizeURL != "https://open.work.weixin.qq.com/wwopen/sso/qrConnect" {
		t.Fatalf("legacy wecom authorize URL should upgrade to QR login, got %q", config.AuthorizeURL)
	}
}

func TestDingTalkProviderUsesQRLoginAuthorizeURL(t *testing.T) {
	cfg := config.BackendConfig{
		PublicBaseURL:     "https://nas.example.com",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	typesResponse := httptest.NewRecorder()
	router.ServeHTTP(typesResponse, httptest.NewRequest("GET", "/api/admin/provider-types", nil))
	if typesResponse.Code != http.StatusOK {
		t.Fatalf("provider types got %d body=%s", typesResponse.Code, typesResponse.Body.String())
	}
	if !strings.Contains(typesResponse.Body.String(), `"type":"dingtalk"`) || !strings.Contains(typesResponse.Body.String(), `"display_name":"钉钉"`) {
		t.Fatalf("provider types missing dingtalk: %s", typesResponse.Body.String())
	}

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{"provider_type":"dingtalk","display_name":"钉钉","config":{"client_id":" ding-app-key ","client_secret":" secret "}}`))
	createRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusOK {
		t.Fatalf("create provider got %d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		ProviderType          string `json:"provider_type"`
		CredentialsConfigured bool   `json:"credentials_configured"`
		DingTalkAuthorizeURL  string `json:"dingtalk_authorize_url"`
		Config                struct {
			ClientID       string `json:"client_id"`
			AuthorizeURL   string `json:"authorize_url"`
			TokenURL       string `json:"token_url"`
			UserInfoURL    string `json:"user_info_url"`
			TenantTokenURL string `json:"tenant_token_url"`
			ContactBaseURL string `json:"contact_base_url"`
		} `json:"config"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ProviderType != "dingtalk" || !created.CredentialsConfigured {
		t.Fatalf("unexpected dingtalk credentials state: %#v", created)
	}
	if created.Config.ClientID != "ding-app-key" {
		t.Fatalf("dingtalk client_id should be trimmed, got %q", created.Config.ClientID)
	}
	if created.Config.AuthorizeURL != "https://login.dingtalk.com/oauth2/auth" {
		t.Fatalf("dingtalk default authorize URL should use QR login, got %q", created.Config.AuthorizeURL)
	}
	if created.Config.TokenURL != "https://api.dingtalk.com/v1.0/oauth2/userAccessToken" || created.Config.UserInfoURL != "https://api.dingtalk.com/v1.0/contact/users/me" {
		t.Fatalf("unexpected dingtalk oauth URLs: %#v", created.Config)
	}
	if created.Config.TenantTokenURL != "https://oapi.dingtalk.com/gettoken" || created.Config.ContactBaseURL != "https://oapi.dingtalk.com/topapi" {
		t.Fatalf("unexpected dingtalk directory URLs: %#v", created.Config)
	}
	if !strings.Contains(created.DingTalkAuthorizeURL, "login.dingtalk.com/oauth2/auth") || !strings.Contains(created.DingTalkAuthorizeURL, "client_id=ding-app-key") || !strings.Contains(created.DingTalkAuthorizeURL, "scope=openid") {
		t.Fatalf("unexpected dingtalk authorize URL: %s", created.DingTalkAuthorizeURL)
	}
}

func TestSettingsPreserveHTTPSPublicBaseURL(t *testing.T) {
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"access_host":"192.0.2.10","public_base_url":"https://192.0.2.10:25000"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"public_base_url":"https://192.0.2.10:25000"`) {
		t.Fatalf("public base url was not preserved: %s", response.Body.String())
	}
}

func TestSettingsPublicBaseURLAllowsIndependentIDPSchemeHostPort(t *testing.T) {
	stubTCPPortAvailable(t)
	idpPort := 26000
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		AccessHost:        "192.0.2.10",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(fmt.Sprintf(`{"access_host":"192.0.2.10","public_base_url":"http://idp.example.com:%d"}`, idpPort)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), fmt.Sprintf(`"public_base_url":"http://idp.example.com:%d"`, idpPort)) {
		t.Fatalf("public base url did not preserve independent IDP scheme/host/port: %s", response.Body.String())
	}
}

func TestRuntimeDeploymentSettingsMigrateToDeploymentSettings(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://default.example.com:25000",
		AccessHost:        "default.example.com",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for key, value := range map[string]any{
		"deployment_mode":      "reverse_proxy",
		"access_host":          "nas.local",
		"access_scheme":        "https",
		"idp_port":             26000,
		"public_base_url":      "https://login.example.com",
		"dsm_redirect_url":     "https://nas.example.com:5001/",
		"helper_dsm_login_api": "https://nas.example.com:5001/webapi/entry.cgi",
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO runtime_settings (key, value_json) VALUES (?, ?)`, key, string(raw)); err != nil {
			t.Fatal(err)
		}
	}

	server := NewWithDB(cfg, testHelper{}, database, queries)
	row, err := queries.GetDeploymentSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.Mode != "reverse_proxy" ||
		row.AccessHost != "nas.local" ||
		row.AccessScheme != "https" ||
		row.IDPPort != 26000 ||
		row.PublicBaseURL != "https://login.example.com" ||
		row.DSMRedirectURL != "https://nas.example.com:5001/" ||
		row.HelperDSMLoginAPI != "https://nas.example.com:5001/webapi/entry.cgi" {
		t.Fatalf("unexpected migrated deployment settings: %#v", row)
	}
	if server.cfg.PublicBaseURL != "https://login.example.com" || server.IDPListenAddress() != "0.0.0.0:26000" {
		t.Fatalf("server did not apply migrated deployment settings: public=%q idp_listen=%q", server.cfg.PublicBaseURL, server.IDPListenAddress())
	}
}

func TestSettingsWriteDeploymentSettingsTable(t *testing.T) {
	stubTCPPortAvailable(t)
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{
		"deployment_mode":"reverse_proxy",
		"access_host":"nas.local",
		"access_scheme":"https",
		"idp_port":26000,
		"public_base_url":"https://login.example.com",
		"dsm_redirect_url":"https://nas.example.com:5001/",
		"helper_dsm_login_api":"https://nas.example.com:5001/webapi/entry.cgi"
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"deployment_mode":"reverse_proxy"`) ||
		!strings.Contains(body, `"public_base_url":"https://login.example.com"`) ||
		!strings.Contains(body, `"idp_port":26000`) {
		t.Fatalf("settings response did not use deployment settings: %s", body)
	}
	row, err := queries.GetDeploymentSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row.Mode != "reverse_proxy" || row.IDPPort != 26000 || row.PublicBaseURL != "https://login.example.com" {
		t.Fatalf("deployment settings were not persisted: %#v", row)
	}
	var legacyDeploymentRows int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM runtime_settings WHERE key IN ('deployment_mode', 'access_host', 'access_scheme', 'idp_port', 'public_base_url', 'dsm_redirect_url', 'helper_dsm_login_api')`).Scan(&legacyDeploymentRows); err != nil {
		t.Fatal(err)
	}
	if legacyDeploymentRows != 0 {
		t.Fatalf("deployment settings should not be written to runtime_settings, got %d rows", legacyDeploymentRows)
	}
}

func TestSettingsPublicBaseURLPortDoesNotDriveIDPListenPort(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"public_base_url":"https://login.example.com:443"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	if server.IDPListenAddress() != "0.0.0.0:26000" {
		t.Fatalf("public_base_url port should not drive IDP listen port, got %q", server.IDPListenAddress())
	}
}

func TestRuntimeDeploymentSettingsSeparatesLegacyIDPPortFromManagementPort(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		IDPListen:         "0.0.0.0:26000",
		PublicBaseURL:     "https://192.0.2.10:26000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
		INSERT INTO deployment_settings (
			id, mode, access_host, access_scheme, idp_port, public_base_url, dsm_redirect_url, helper_dsm_login_api
		) VALUES (
			1, 'direct', '192.0.2.10', 'https', 25000, 'https://192.0.2.10:25000', 'https://192.0.2.10:5001/', 'https://192.0.2.10:5001/webapi/entry.cgi'
		)
	`); err != nil {
		t.Fatal(err)
	}
	server := NewWithDB(cfg, testHelper{}, database, queries)
	if server.IDPListenAddress() != "0.0.0.0:26000" {
		t.Fatalf("legacy idp port should be separated from management port, got %q", server.IDPListenAddress())
	}
	if server.cfg.PublicBaseURL != "https://192.0.2.10:26000" {
		t.Fatalf("legacy direct public base url should follow separated idp port, got %q", server.cfg.PublicBaseURL)
	}
}

func TestSettingsRejectsIDPPortMatchingManagementPort(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		IDPListen:         "0.0.0.0:26000",
		PublicBaseURL:     "https://192.0.2.10:26000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"idp_port":25000}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "idp_port must be different from the management port") {
		t.Fatalf("unexpected error body: %s", response.Body.String())
	}
	if server.IDPListenAddress() != "0.0.0.0:26000" {
		t.Fatalf("rejected idp_port update changed runtime listen: %q", server.IDPListenAddress())
	}
}

func TestSettingsOverviewSeparatesRuntimeFactsAndConfigurationEffects(t *testing.T) {
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		IDPListen:         "0.0.0.0:26000",
		PublicBaseURL:     "https://login.example.com",
		AccessHost:        "nas.example.com",
		AccessScheme:      "https",
		DSMRedirectURL:    "https://nas.example.com:5001/",
		HelperDSMLoginAPI: "https://nas.example.com:5001/webapi/entry.cgi",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/admin/settings/overview", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"title":"系统说明"`,
		`"title":"管理后台本机监听"`,
		`"value":"0.0.0.0:25000"`,
		`"title":"认证入口本机监听"`,
		`"value":"0.0.0.0:26000"`,
		`"change_method":"系统设置 \u003e 入口与域名 \u003e 认证入口本机端口"`,
		`"applies":"保存后刷新认证路由；无需重启套件"`,
		`"label":"认证入口公网地址"`,
		`"change_method":"系统设置 \u003e 入口与域名 \u003e 认证入口公网地址"`,
		`"applies":"保存后立即影响新生成的登录地址、回调地址和身份源展示"`,
		`"effect":"决定登录链接和 OAuth redirect_uri/callback_url，是企业微信、飞书、钉钉等平台需要配置的外部地址。"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings overview missing %q: %s", want, body)
		}
	}
}

func TestSettingsPublicBaseURLSchemeDoesNotFollowInternalIDPScheme(t *testing.T) {
	stubTCPPortAvailable(t)
	ctx := context.Background()
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{
		"deployment_mode":"reverse_proxy",
		"access_scheme":"http",
		"idp_port":26000,
		"public_base_url":"https://login.example.com",
		"helper_dsm_login_mode":"helper"
	}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"access_scheme":"http"`) || !strings.Contains(body, `"public_base_url":"https://login.example.com"`) {
		t.Fatalf("reverse proxy public URL should keep its external scheme: %s", body)
	}
	if server.IDPTLSEnabled() {
		t.Fatalf("internal IDP route should use access_scheme, not public_base_url scheme")
	}
}

func TestSettingsAccessSchemeHTTPDerivesHTTPURLs(t *testing.T) {
	stubTCPPortAvailable(t)
	idpPort := 26001
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(fmt.Sprintf(`{"access_host":"192.0.2.10","access_scheme":"http","idp_port":%d}`, idpPort)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"access_scheme":"http"`) ||
		!strings.Contains(body, fmt.Sprintf(`"public_base_url":"http://192.0.2.10:%d"`, idpPort)) ||
		!strings.Contains(body, `"dsm_redirect_url":"http://192.0.2.10:5000/"`) ||
		!strings.Contains(body, `"helper_dsm_login_api":"http://192.0.2.10:5000/webapi/entry.cgi"`) ||
		!strings.Contains(body, `"dsm_cookie_secure":false`) {
		t.Fatalf("http scheme did not derive all http settings: %s", body)
	}
}

func TestSettingsAccessSchemeHTTPSDerivesDSMDefaultHTTPSPort(t *testing.T) {
	stubTCPPortAvailable(t)
	idpPort := 26002
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "http://192.0.2.10:26001",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "http",
		DSMRedirectURL:    "http://192.0.2.10:5000/",
		HelperDSMLoginAPI: "http://192.0.2.10:5000/webapi/entry.cgi",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(fmt.Sprintf(`{
		"access_host":"192.0.2.10",
		"access_scheme":"https",
		"idp_port":%d,
		"dsm_redirect_url":"https://192.0.2.10:5000/",
		"helper_dsm_login_api":"https://192.0.2.10:5000/webapi/entry.cgi"
	}`, idpPort)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"access_scheme":"https"`) ||
		!strings.Contains(body, `"dsm_redirect_url":"https://192.0.2.10:5001/"`) ||
		!strings.Contains(body, `"helper_dsm_login_api":"https://192.0.2.10:5001/webapi/entry.cgi"`) ||
		!strings.Contains(body, `"dsm_cookie_secure":true`) {
		t.Fatalf("https scheme did not derive DSM https default port: %s", body)
	}
}

func TestSettingsWithAccessHostPreservesExplicitDSMURLs(t *testing.T) {
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:25000",
		AccessHost:        "192.0.2.10",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{
		"access_host":"192.0.2.10",
		"public_base_url":"https://192.0.2.10:25000",
		"dsm_redirect_url":"https://192.0.2.10:5443",
		"helper_dsm_login_api":"https://192.0.2.10:5443//webapi/entry.cgi",
		"helper_dsm_tls_skip_verify":true
	}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"dsm_redirect_url":"https://192.0.2.10:5443/"`) ||
		!strings.Contains(body, `"helper_dsm_login_api":"https://192.0.2.10:5443/webapi/entry.cgi"`) ||
		!strings.Contains(body, `"helper_dsm_tls_skip_verify":true`) {
		t.Fatalf("explicit dsm urls were not preserved and normalized: %s", body)
	}
}

func TestBrowserDSMLoginModeRequiresSameProtocolAsIDP(t *testing.T) {
	cfg := config.BackendConfig{
		Listen:            "0.0.0.0:25000",
		PublicBaseURL:     "https://192.0.2.10:26000",
		AccessHost:        "192.0.2.10",
		AccessScheme:      "https",
		DSMRedirectURL:    "http://192.0.2.10:5000/",
		HelperDSMLoginAPI: "http://192.0.2.10:5000/webapi/entry.cgi",
		DSMLoginMode:      "helper",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		TLSEnabled:        true,
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader(`{"helper_dsm_login_mode":"browser"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "DSM 地址协议必须和 IDP 协议一致") {
		t.Fatalf("unexpected error body: %s", response.Body.String())
	}
}

func TestCreateProviderGeneratesUUIDSlug(t *testing.T) {
	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{
		"provider_type": "feishu",
		"display_name": "公司飞书",
		"config": {
			"client_id": "cli_test",
			"client_secret": "secret"
		}
	}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidPattern.MatchString(body.Slug) {
		t.Fatalf("expected uuid slug, got %q", body.Slug)
	}
}

func TestCreateProviderRejectsClientSlug(t *testing.T) {
	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{
		"slug": "custom-source",
		"provider_type": "feishu",
		"display_name": "公司飞书",
		"config": {
			"client_id": "cli_test",
			"client_secret": "secret"
		}
	}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "slug is generated by the server") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestDeleteProviderDeletesIdentitySourceAndDisablesDSMUsers(t *testing.T) {
	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	helper := &recordingHelper{}
	router := NewWithDB(cfg, helper, database, queries).Router()

	_, err = database.ExecContext(context.Background(), `
INSERT INTO identity_sources (slug, provider_type, display_name, config_json) VALUES ('source-a', 'feishu', '公司飞书', '{}');
INSERT INTO app_identities (id, display_name) VALUES ('identity-a', 'Alice');
INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id) VALUES ('external-a', 'source-a', 'alice', 'alice', 'user', 'identity-a');
INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm) VALUES ('account-a', 'identity-a', 'alice', 'alice');
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name) VALUES ('provider-group-a', 'source-a', 'department-a', 'department-a', 'Engineering');
	INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, provision_status) VALUES ('group-a', 'engineering', 'engineering', 'created');
	INSERT INTO group_links (id, provider_group_id, dsm_group_id) VALUES ('link-a', 'provider-group-a', 'group-a');
	INSERT INTO group_members (id, dsm_group_id, dsm_account_id, provision_status) VALUES ('member-a', 'group-a', 'account-a', 'created');
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id, dsm_group_id) VALUES
	('map-user-a', 'user', 'source-a', 'external-a', '', 'account-a', NULL),
	('map-group-a', 'group', 'source-a', '', 'provider-group-a', NULL, 'group-a'),
	('map-member-a', 'member', 'source-a', 'external-a', 'provider-group-a', 'account-a', 'group-a');
	INSERT INTO sync_runs (id, source_slug, status) VALUES ('sync-a', 'source-a', 'success');
INSERT INTO sync_operation_logs (id, sync_run_id, source_slug, object_type, object_key, action, status) VALUES ('log-a', 'sync-a', 'source-a', 'user', 'alice', 'sync', 'success');
INSERT INTO login_audit_logs (id, request_id, provider_slug, result) VALUES ('audit-a', 'request-a', 'source-a', 'success');
`)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest("DELETE", "/api/admin/providers/source-a", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	if len(helper.disabled) != 1 || helper.disabled[0] != "alice" {
		t.Fatalf("expected alice disabled, got %#v", helper.disabled)
	}
	if len(helper.removed) != 0 {
		t.Fatalf("DSM group members should not be removed automatically, got %#v", helper.removed)
	}
	for _, item := range []struct {
		table string
		where string
	}{
		{"identity_sources", "slug = 'source-a'"},
		{"external_accounts", "provider_slug = 'source-a'"},
		{"app_identities", "id = 'identity-a'"},
		{"dsm_accounts", "id = 'account-a'"},
		{"provider_groups", "id = 'provider-group-a'"},
		{"dsm_groups", "id = 'group-a'"},
		{"group_links", "id = 'link-a'"},
		{"group_members", "id = 'member-a'"},
		{"sync_runs", "source_slug = 'source-a'"},
		{"sync_operation_logs", "source_slug = 'source-a'"},
		{"login_audit_logs", "provider_slug = 'source-a'"},
	} {
		var count int
		row := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+item.table+" WHERE "+item.where)
		if err := row.Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expected %s cleaned, got %d rows", item.table, count)
		}
	}
}

func TestDirectoryDebugListsHashProviderSubjects(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries).Router()

	_, err = database.ExecContext(ctx, `
INSERT INTO app_identities (id, display_name) VALUES ('identity-a', 'Alice');
INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id) VALUES ('external-a', 'source-a', 'alice-open-id', 'alice-open-id', 'user', 'identity-a');
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, parent_subject, name) VALUES ('provider-group-a', 'source-a', 'department-a', 'department-a', 'root-department', 'Engineering');
`)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/admin/external-accounts", "/api/admin/provider-groups"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest("GET", path, nil)
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s got %d body=%s", path, response.Code, response.Body.String())
		}
		body := response.Body.String()
		if strings.Contains(body, "alice-open-id") || strings.Contains(body, "department-a") || strings.Contains(body, "root-department") {
			t.Fatalf("%s leaked raw provider subject: %s", path, body)
		}
	}
}

func TestDSMAccountsSearchesBeforePagination(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries).Router()
	seedSyncedAccount(t, ctx, database, "source-a", "identity-a", "external-a", "alice", "alice", "2999-01-01 00:00:00")
	seedSyncedAccount(t, ctx, database, "source-a", "identity-b", "external-b", "bob", "bob", "2999-01-01 00:00:00")
	seedGroupMember(t, ctx, database, "source-a", "provider-group-a", "dsm-group-a", "member-a", "department-a", "Engineering", "identity-b", 1, "created")

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/admin/dsm-accounts?provider=source-a&q=Engineering&page=1&limit=1", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Total int `json:"total"`
		Items []struct {
			DSMUsername string `json:"dsm_username"`
		} `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].DSMUsername != "bob" {
		t.Fatalf("search should filter before pagination, got %#v", body)
	}

	membersResponse := httptest.NewRecorder()
	membersRequest := httptest.NewRequest("GET", "/api/admin/group-members?provider=source-a", nil)
	router.ServeHTTP(membersResponse, membersRequest)
	if membersResponse.Code != http.StatusOK {
		t.Fatalf("group members got %d body=%s", membersResponse.Code, membersResponse.Body.String())
	}
	var membersBody struct {
		Items []struct {
			DSMGroupID   string `json:"dsm_group_id"`
			DSMAccountID string `json:"dsm_account_id"`
			DSMUsername  string `json:"dsm_username"`
		} `json:"items"`
	}
	if err := json.Unmarshal(membersResponse.Body.Bytes(), &membersBody); err != nil {
		t.Fatal(err)
	}
	if len(membersBody.Items) != 1 || membersBody.Items[0].DSMGroupID != "dsm-group-a" || membersBody.Items[0].DSMAccountID != "account-identity-b" || membersBody.Items[0].DSMUsername != "bob" {
		t.Fatalf("group members should expose stable relation ids, got %#v", membersBody)
	}
}

func TestCleanupLogsRemovesExpiredRows(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries)
	_, err = database.ExecContext(ctx, `
INSERT INTO sync_runs (id, source_slug, status, started_at) VALUES ('sync-old', 'source-a', 'success', '2000-01-01 00:00:00');
INSERT INTO sync_runs (id, source_slug, status, started_at) VALUES ('sync-new', 'source-a', 'success', CURRENT_TIMESTAMP);
INSERT INTO sync_operation_logs (id, sync_run_id, source_slug, object_type, object_key, action, status, created_at)
VALUES ('sync-log-old', 'sync-old', 'source-a', 'user', 'old', 'sync', 'success', '2000-01-01 00:00:00');
INSERT INTO sync_operation_logs (id, sync_run_id, source_slug, object_type, object_key, action, status, created_at)
VALUES ('sync-log-new', 'sync-new', 'source-a', 'user', 'new', 'sync', 'success', CURRENT_TIMESTAMP);
INSERT INTO login_audit_logs (id, request_id, provider_slug, result, created_at)
VALUES ('audit-old', 'request-old', 'source-a', 'success', '2000-01-01 00:00:00');
INSERT INTO login_audit_logs (id, request_id, provider_slug, result, created_at)
VALUES ('audit-new', 'request-new', 'source-a', 'success', CURRENT_TIMESTAMP);
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.cleanupLogs(ctx); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		table string
		id    string
		want  int
	}{
		{"sync_operation_logs", "sync-log-old", 0},
		{"sync_operation_logs", "sync-log-new", 1},
		{"login_audit_logs", "audit-old", 0},
		{"login_audit_logs", "audit-new", 1},
	} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+item.table+" WHERE id = ?", item.id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != item.want {
			t.Fatalf("%s id=%s got %d want %d", item.table, item.id, count, item.want)
		}
	}
}

func TestAdminAuthUsesJWTCookie(t *testing.T) {
	dist := t.TempDir()
	if err := os.WriteFile(filepath.Join(dist, "index.html"), []byte("<html>app</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.BackendConfig{
		FrontendDistDir:   dist,
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		AdminAuthEnabled:  true,
		AdminUsername:     "admin",
		AdminPassword:     "secret",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	assertStatus(t, router, "GET", "/api/admin/version", http.StatusUnauthorized)
	assertStatus(t, router, "GET", "/", http.StatusOK)
	missingIDPResponse := httptest.NewRecorder()
	missingIDPRequest := httptest.NewRequest("GET", "/idp/missing/launch", nil)
	missingIDPRequest.RemoteAddr = "192.168.1.20:12345"
	router.ServeHTTP(missingIDPResponse, missingIDPRequest)
	if missingIDPResponse.Code != http.StatusNotFound {
		t.Fatalf("GET /idp/missing/launch got %d want %d", missingIDPResponse.Code, http.StatusNotFound)
	}

	loginResponse := httptest.NewRecorder()
	loginRequest := httptest.NewRequest("POST", "/api/admin/auth/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login got %d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	cookies := loginResponse.Result().Cookies()
	expectedCookieName := server.adminSessionCookieName()
	if len(cookies) != 1 || cookies[0].Name != expectedCookieName || strings.Count(cookies[0].Value, ".") != 2 {
		t.Fatalf("expected jwt cookie, got %#v", cookies)
	}
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected admin cookie SameSite=Lax, got %#v", cookies[0].SameSite)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/admin/version", nil)
	request.AddCookie(cookies[0])
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated admin got %d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminSetupWritesSQLiteAndIssuesJWTCookie(t *testing.T) {
	cfg := config.BackendConfig{
		RelayMode:        "socket",
		DSMCookieName:    "id",
		AdminAuthEnabled: true,
		AdminUsername:    "admin",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	statusResponse := httptest.NewRecorder()
	statusRequest := httptest.NewRequest("GET", "/api/admin/auth/status", nil)
	router.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"setup_required":true`) {
		t.Fatalf("expected setup required, got %d body=%s", statusResponse.Code, statusResponse.Body.String())
	}
	assertStatus(t, router, "GET", "/api/admin/version", http.StatusPreconditionRequired)

	setupResponse := httptest.NewRecorder()
	setupRequest := httptest.NewRequest("POST", "/api/admin/auth/setup", strings.NewReader(`{"username":"owner","password":"new-secret"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusOK {
		t.Fatalf("setup got %d body=%s", setupResponse.Code, setupResponse.Body.String())
	}
	cookies := setupResponse.Result().Cookies()
	expectedCookieName := server.adminSessionCookieName()
	if len(cookies) != 1 || cookies[0].Name != expectedCookieName || strings.Count(cookies[0].Value, ".") != 2 {
		t.Fatalf("expected jwt cookie, got %#v", cookies)
	}
	if cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected setup cookie SameSite=Lax, got %#v", cookies[0].SameSite)
	}

	rows, err := queries.ListRuntimeSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]string{}
	for _, row := range rows {
		stored[row.Key] = row.ValueJson
	}
	if stored["admin_username"] != `"owner"` {
		t.Fatalf("admin username not stored: %#v", stored)
	}
	if !strings.HasPrefix(stored["admin_password_hash"], `"pbkdf2-sha256:`) || strings.Contains(stored["admin_password_hash"], "new-secret") {
		t.Fatalf("admin password hash not stored safely: %q", stored["admin_password_hash"])
	}
	if !strings.HasPrefix(stored["admin_jwt_secret"], `"`) || len(stored["admin_jwt_secret"]) < 20 {
		t.Fatalf("admin jwt secret was not initialized: %#v", stored)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/admin/version", nil)
	request.AddCookie(cookies[0])
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated setup cookie got %d body=%s", response.Code, response.Body.String())
	}
}

func TestAdminSessionCookieUsesAdminPortNotIDPPort(t *testing.T) {
	cfg := config.BackendConfig{
		Listen:           "0.0.0.0:25000",
		PublicBaseURL:    "https://192.0.2.10:25001",
		RelayMode:        "socket",
		DSMCookieName:    "id",
		AdminAuthEnabled: true,
		AdminUsername:    "admin",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	setupResponse := httptest.NewRecorder()
	setupRequest := httptest.NewRequest("POST", "/api/admin/auth/setup", strings.NewReader(`{"username":"owner","password":"new-secret"}`))
	setupRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(setupResponse, setupRequest)
	if setupResponse.Code != http.StatusOK {
		t.Fatalf("setup got %d body=%s", setupResponse.Code, setupResponse.Body.String())
	}
	cookies := setupResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminSessionCookieBaseName+"_25000" {
		t.Fatalf("expected admin port cookie, got %#v", cookies)
	}

	server.cfg.PublicBaseURL = "https://192.0.2.10:26001"
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/admin/version", nil)
	request.AddCookie(cookies[0])
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("admin cookie should survive idp port change, got %d body=%s", response.Code, response.Body.String())
	}
}

func TestWriteDSMCookiesAppliesConfiguredAttributes(t *testing.T) {
	cfg := config.BackendConfig{
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSecure:   true,
		DSMCookieHTTPOnly: true,
		DSMCookieSameSite: "Strict",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/callback", nil)
	c, _ := gin.CreateTestContext(response)
	c.Request = request
	server.writeDSMCookies(c, helperclient.RelayLoginResult{
		SID: "sid-from-helper",
		Cookies: []helperclient.RelayCookie{
			{Name: "id", Value: "raw-id", Path: "/", MaxAge: 3600},
			{Name: "did", Value: "device-id", Path: "/", MaxAge: 31536000},
		},
	})

	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected two cookies, got %#v", cookies)
	}
	for _, cookie := range cookies {
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie attributes were not applied: %#v", cookie)
		}
	}
	if cookies[0].Name != "id" || cookies[0].Value != "sid-from-helper" {
		t.Fatalf("session cookie should use helper sid, got %#v", cookies[0])
	}
}

func TestClearDSMCookieExpiresExistingBrowserSession(t *testing.T) {
	cfg := config.BackendConfig{
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSecure:   true,
		DSMCookieHTTPOnly: true,
		DSMCookieSameSite: "Lax",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)

	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/callback", nil)
	c, _ := gin.CreateTestContext(response)
	c.Request = request
	server.clearDSMCookie(c)

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one expired DSM cookie, got %#v", cookies)
	}
	if cookies[0].Name != "id" || cookies[0].Value != "" || cookies[0].MaxAge != -1 {
		t.Fatalf("expected expired id cookie, got %#v", cookies[0])
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attributes were not preserved: %#v", cookies[0])
	}
}

func TestSetDSMAccountUsernameResolvesConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `INSERT INTO app_identities (id, display_name, primary_email) VALUES ('identity-a', '张三', 'a@example.com'), ('identity-b', '张三', 'b@example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, conflict_reason, allow_login)
VALUES
('account-a', 'identity-a', 'zhangsan_conflict_a', 'zhangsan_conflict_a', 1, 'conflict', '飞书用户姓名重名', 0),
('account-b', 'identity-b', 'zhangsan', 'zhangsan', 1, 'conflict', '飞书用户姓名重名', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id, display_name, email, email_norm, mobile_masked)
VALUES ('external-a', 'feishu-main', 'user-a', 'user-a', 'user', 'identity-a', '张三', 'a@example.com', 'a@example.com', '13****63')`); err != nil {
		t.Fatal(err)
	}
	router := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries).Router()

	listResponse := httptest.NewRecorder()
	listRequest := httptest.NewRequest("GET", "/api/admin/dsm-accounts?provider=feishu-main", nil)
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), `"mobile_masked":"13****63"`) || !strings.Contains(listResponse.Body.String(), `"external_emails":"a@example.com"`) {
		t.Fatalf("list accounts missing Feishu contact fields: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}

	duplicate := httptest.NewRecorder()
	duplicateRequest := httptest.NewRequest("PUT", "/api/admin/dsm-accounts/account-a/username", strings.NewReader(`{"dsm_username":"zhangsan"}`))
	duplicateRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(duplicate, duplicateRequest)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate username got %d body=%s", duplicate.Code, duplicate.Body.String())
	}

	unchanged := httptest.NewRecorder()
	unchangedRequest := httptest.NewRequest("PUT", "/api/admin/dsm-accounts/account-a/username", strings.NewReader(`{"dsm_username":"zhangsan_conflict_a"}`))
	unchangedRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(unchanged, unchangedRequest)
	if unchanged.Code != http.StatusOK {
		t.Fatalf("unchanged conflict username got %d body=%s", unchanged.Code, unchanged.Body.String())
	}
	if _, err := database.ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = 'conflict', conflict_reason = '冲突' WHERE id = 'account-a'`); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/dsm-accounts/account-a/username", strings.NewReader(`{"dsm_username":"zhangsan_a"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("resolve username got %d body=%s", response.Code, response.Body.String())
	}
	var managed, allowLogin int
	var status, conflictReason string
	if err := database.QueryRowContext(ctx, `SELECT managed, provision_status, COALESCE(conflict_reason, ''), allow_login FROM dsm_accounts WHERE id = 'account-a'`).Scan(&managed, &status, &conflictReason, &allowLogin); err != nil {
		t.Fatal(err)
	}
	if managed != 0 || status != "pending" || conflictReason != "" || allowLogin != 1 {
		t.Fatalf("account conflict not resolved: managed=%d status=%s reason=%q allow_login=%d", managed, status, conflictReason, allowLogin)
	}
}

func TestProvisionDSMAccountLinksExistingDSMUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `INSERT INTO app_identities (id, display_name, primary_email) VALUES ('identity-a', 'amktest', 'a@example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, allow_login)
VALUES ('account-a', 'identity-a', 'amktest', 'amktest', 1, 'pending', 1)`); err != nil {
		t.Fatal(err)
	}
	router := NewWithDB(config.BackendConfig{}, existingUserHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/admin/dsm-accounts/account-a/provision", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("provision existing user got %d body=%s", response.Code, response.Body.String())
	}
	var status, conflictReason string
	var allowLogin int
	if err := database.QueryRowContext(ctx, `SELECT provision_status, COALESCE(conflict_reason, ''), allow_login FROM dsm_accounts WHERE id = 'account-a'`).Scan(&status, &conflictReason, &allowLogin); err != nil {
		t.Fatal(err)
	}
	if status != "linked_existing" || conflictReason != "" || allowLogin != 1 {
		t.Fatalf("existing DSM user should be linked, got status=%s reason=%q allow_login=%d", status, conflictReason, allowLogin)
	}
}

func TestSetDSMGroupNameResolvesConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name, path)
VALUES ('provider-group-a', 'feishu-main', 'dep-a', 'dep-a', 'sup5', 'matrix/sup1/sup2/sup5')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, managed, provision_status, conflict_reason)
VALUES
('group-a', 'matrix_sup1_sup2_sup5', 'matrix_sup1_sup2_sup5', 1, 'conflict', '飞书部门名重名'),
('group-b', 'sup5', 'sup5', 1, 'conflict', '飞书部门名重名')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO app_identities (id, display_name, primary_email) VALUES ('identity-a', 'Alice', 'alice@example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm) VALUES ('account-a', 'identity-a', 'alice', 'alice')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO group_links (id, provider_group_id, dsm_group_id) VALUES ('link-a', 'provider-group-a', 'group-a')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO group_members (id, dsm_group_id, dsm_account_id, provision_status) VALUES ('member-a', 'group-a', 'account-a', 'created')`); err != nil {
		t.Fatal(err)
	}
	router := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries).Router()

	unchanged := httptest.NewRecorder()
	unchangedRequest := httptest.NewRequest("PUT", "/api/admin/dsm-groups/group-a/name", strings.NewReader(`{"dsm_groupname":"matrix_sup1_sup2_sup5"}`))
	unchangedRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(unchanged, unchangedRequest)
	if unchanged.Code != http.StatusConflict {
		t.Fatalf("unchanged conflict group name got %d body=%s", unchanged.Code, unchanged.Body.String())
	}

	duplicate := httptest.NewRecorder()
	duplicateRequest := httptest.NewRequest("PUT", "/api/admin/dsm-groups/group-a/name", strings.NewReader(`{"dsm_groupname":"sup5"}`))
	duplicateRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(duplicate, duplicateRequest)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate group name got %d body=%s", duplicate.Code, duplicate.Body.String())
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest("PUT", "/api/admin/dsm-groups/group-a/name", strings.NewReader(`{"dsm_groupname":"sup5_a"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("resolve group got %d body=%s", response.Code, response.Body.String())
	}
	var managed int
	var status, conflictReason string
	if err := database.QueryRowContext(ctx, `SELECT managed, provision_status, COALESCE(conflict_reason, '') FROM dsm_groups WHERE id = 'group-a'`).Scan(&managed, &status, &conflictReason); err != nil {
		t.Fatal(err)
	}
	if managed != 0 || status != "pending" || conflictReason != "" {
		t.Fatalf("group conflict not resolved: managed=%d status=%s reason=%q", managed, status, conflictReason)
	}
	var linkCount, memberCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_links WHERE id = 'link-a' AND provider_group_id = 'provider-group-a' AND dsm_group_id = 'group-a'`).Scan(&linkCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM group_members WHERE id = 'member-a' AND dsm_group_id = 'group-a' AND dsm_account_id = 'account-a'`).Scan(&memberCount); err != nil {
		t.Fatal(err)
	}
	if linkCount != 1 || memberCount != 1 {
		t.Fatalf("group relationships were not preserved: links=%d members=%d", linkCount, memberCount)
	}
}

func TestSyncSourceToDSMLogsBlockedGroupConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name, active)
VALUES ('provider-group-a', 'feishu-main', 'dep-a', 'dep-a', 'sup5', 1);
INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, provision_status, conflict_reason)
VALUES ('group-a', 'sup5', 'sup5', 'conflict', '飞书部门名重名');
INSERT INTO group_links (id, provider_group_id, dsm_group_id)
VALUES ('link-a', 'provider-group-a', 'group-a');
INSERT INTO sync_runs (id, source_slug, status)
VALUES ('sync-a', 'feishu-main', 'running')`); err != nil {
		t.Fatal(err)
	}
	server := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries)

	_, err = server.syncSourceToDSM(ctx, "sync-a", "feishu-main", "2026-05-29 00:00:00", sourceSyncPolicy{})
	if err == nil || !strings.Contains(err.Error(), "存在飞书部门名冲突") {
		t.Fatalf("expected group conflict block, got %v", err)
	}
	var status, action, errorText string
	if err := database.QueryRowContext(ctx, `
SELECT status, action, COALESCE(error, '')
FROM sync_operation_logs
WHERE sync_run_id = 'sync-a' AND source_slug = 'feishu-main'`).Scan(&status, &action, &errorText); err != nil {
		t.Fatal(err)
	}
	if status != "blocked" || action != "resolve_group_conflicts" || !strings.Contains(errorText, "存在飞书部门名冲突") {
		t.Fatalf("unexpected blocked log: status=%s action=%s error=%q", status, action, errorText)
	}
}

func TestLogDirectoryLinkPlanRecordsCrossSourceLinks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries)

	server.logDirectoryLinkPlan(ctx, "sync-a", "source-b", []syncsvc.PlanItem{
		{Action: "link_existing_dsm_user", Subject: "user-b", DSMUsername: "alice"},
		{Action: "link_existing_dsm_group", Subject: "group-b", DSMGroupname: "engineering"},
		{Action: "directory_warning", Subject: "source-b", DisplayName: "只同步用户，没有部门组"},
	})

	var userLinks, groupLinks, warnings int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sync_operation_logs WHERE action = 'link_existing_dsm_user' AND status = 'success' AND error LIKE '%跨身份源同名用户%'`).Scan(&userLinks); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sync_operation_logs WHERE action = 'link_existing_dsm_group' AND status = 'success' AND error LIKE '%跨身份源同名部门%'`).Scan(&groupLinks); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sync_operation_logs WHERE action = 'directory_warning' AND status = 'warning' AND object_type = 'identity_source' AND error LIKE '%只同步用户%'`).Scan(&warnings); err != nil {
		t.Fatal(err)
	}
	if userLinks != 1 || groupLinks != 1 || warnings != 1 {
		t.Fatalf("expected link and warning logs, got user=%d group=%d warning=%d", userLinks, groupLinks, warnings)
	}
}

func TestSyncSourceToDSMProvisionsGroupsBeforeUsers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name, active)
VALUES ('provider-group-a', 'feishu-main', 'dep-a', 'dep-a', 'engineering', 1);
INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, provision_status)
VALUES ('group-a', 'engineering', 'engineering', 'pending');
INSERT INTO group_links (id, provider_group_id, dsm_group_id)
VALUES ('link-a', 'provider-group-a', 'group-a');
INSERT INTO app_identities (id, display_name, primary_email)
VALUES ('identity-a', 'Alice', 'alice@example.com');
INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id, active)
VALUES ('external-a', 'feishu-main', 'user-a', 'user-a', 'user', 'identity-a', 1);
INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, provision_status, allow_login)
VALUES ('account-a', 'identity-a', 'alice', 'alice', 'pending', 1);
	INSERT INTO group_members (id, dsm_group_id, dsm_account_id, provision_status)
	VALUES ('member-a', 'group-a', 'account-a', 'pending');
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id, dsm_group_id) VALUES
	('map-user-a', 'user', 'feishu-main', 'external-a', '', 'account-a', NULL),
	('map-group-a', 'group', 'feishu-main', '', 'provider-group-a', NULL, 'group-a'),
	('map-member-a', 'member', 'feishu-main', 'external-a', 'provider-group-a', 'account-a', 'group-a');
	INSERT INTO sync_runs (id, source_slug, status)
VALUES ('sync-a', 'feishu-main', 'running')`); err != nil {
		t.Fatal(err)
	}
	helper := &provisioningOrderHelper{}
	server := NewWithDB(config.BackendConfig{}, helper, database, queries)

	if _, err := server.syncSourceToDSM(ctx, "sync-a", "feishu-main", "2026-05-29 00:00:00", sourceSyncPolicy{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"group:engineering", "user:alice", "member:engineering:alice"}
	if fmt.Sprint(helper.operations) != fmt.Sprint(want) {
		t.Fatalf("provision order got %v, want %v", helper.operations, want)
	}
}

func seedSyncedAccount(t *testing.T, ctx context.Context, database *sql.DB, providerSlug, identityID, externalID, subject, username, lastSeen string) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
INSERT INTO app_identities (id, display_name, primary_email, status, created_by)
VALUES (?, ?, ?, 'active', 'system')`, identityID, username, username+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO external_accounts (id, provider_slug, subject, subject_norm, subject_type, app_identity_id, active, last_seen_at)
VALUES (?, ?, ?, ?, 'directory_subject', ?, 1, ?)`, externalID, providerSlug, subject, subject, identityID, lastSeen); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
	INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, allow_login)
	VALUES (?, ?, ?, ?, 1, 'linked_existing', 1)`, "account-"+identityID, identityID, username, username); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id)
	VALUES (?, 'user', ?, ?, '', ?)`, "map-user-"+externalID, providerSlug, externalID, "account-"+identityID); err != nil {
		t.Fatal(err)
	}
}

func seedGroupMember(t *testing.T, ctx context.Context, database *sql.DB, providerSlug, providerGroupID, dsmGroupID, memberID, groupSubject, groupname, identityID string, active int, status string) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, name, active)
VALUES (?, ?, ?, ?, ?, 1)`, providerGroupID, providerSlug, groupSubject, groupSubject, groupname); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, managed, provision_status)
VALUES (?, ?, ?, 1, 'created')`, dsmGroupID, groupname, groupname); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO group_links (id, provider_group_id, dsm_group_id)
VALUES (?, ?, ?)`, "link-"+memberID, providerGroupID, dsmGroupID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
	INSERT INTO group_members (id, dsm_group_id, dsm_account_id, active, provision_status)
	VALUES (?, ?, ?, ?, ?)`, memberID, dsmGroupID, "account-"+identityID, active, status); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_group_id)
	VALUES (?, 'group', ?, '', ?, ?)`, "map-group-"+memberID, providerSlug, providerGroupID, dsmGroupID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
	INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id, dsm_group_id)
	VALUES (?, 'member', ?, ?, ?, ?, ?)`, "map-member-"+memberID, providerSlug, "external-"+identityID, providerGroupID, "account-"+identityID, dsmGroupID); err != nil {
		t.Fatal(err)
	}
}

func assertLocalMemberStatus(t *testing.T, ctx context.Context, database *sql.DB, memberID string, wantActive int, wantStatus string) {
	t.Helper()
	var active int
	var status string
	if err := database.QueryRowContext(ctx, `SELECT active, provision_status FROM group_members WHERE id = ?`, memberID).Scan(&active, &status); err != nil {
		t.Fatal(err)
	}
	if active != wantActive || status != wantStatus {
		t.Fatalf("member %s got active=%d status=%s want active=%d status=%s", memberID, active, status, wantActive, wantStatus)
	}
}

func assertStatus(t *testing.T, handler http.Handler, method, path string, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	handler.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("%s %s got %d want %d", method, path, response.Code, want)
	}
}
