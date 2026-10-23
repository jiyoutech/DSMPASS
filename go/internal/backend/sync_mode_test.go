package backend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/gin-gonic/gin"
)

type syncPasswordHelper struct {
	existingUserHelper
	resets    []string
	passwords []string
	fail      bool
}

type oldSyncHelper struct{ testHelper }

func (oldSyncHelper) HealthCheck(context.Context) (map[string]any, error) {
	return map[string]any{"success": true}, nil
}

func TestFullSyncRejectsOldHelperBeforeReadingOrChangingDirectory(t *testing.T) {
	ctx := context.Background()
	database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`INSERT INTO identity_sources (slug,provider_type,display_name) VALUES ('a','feishu','A')`); err != nil {
		t.Fatal(err)
	}
	s := NewWithDB(config.BackendConfig{}, oldSyncHelper{}, database, q)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/sync/a/apply", strings.NewReader(`{"mode":"full"}`))
	r.Header.Set("Content-Type", "application/json")
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Helper 不支持全量同步") {
		t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
	}
	var runs int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sync_runs`).Scan(&runs); err != nil || runs != 0 {
		t.Fatal("unsupported full sync started work")
	}
}

func (h *syncPasswordHelper) ResetSyncedUserPassword(ctx context.Context, requestID, sourceSlug, accountID, username, password string) error {
	h.resets = append(h.resets, sourceSlug+":"+username)
	h.passwords = append(h.passwords, password)
	if h.fail {
		return errors.New("test reset failed")
	}
	return nil
}

func TestReadSyncMode(t *testing.T) {
	for _, tc := range []struct {
		body string
		want syncMode
		ok   bool
	}{
		{"", syncIncremental, true}, {"{}", syncIncremental, true},
		{`{"mode":"incremental"}`, syncIncremental, true}, {`{"mode":"full"}`, syncFull, true},
		{`{"mode":"typo"}`, "", false}, {`{"mode":true}`, "", false}, {"{", "", false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			mode, ok := readSyncMode(c)
			if mode != tc.want || ok != tc.ok {
				t.Fatalf("got %q/%v", mode, ok)
			}
			if !ok && w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", w.Code)
			}
		})
	}
}

func TestSyncModesOnlyResetMappedManagedUsersInFullMode(t *testing.T) {
	ctx := context.Background()
	database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	h := &syncPasswordHelper{}
	s := NewWithDB(config.BackendConfig{AdminJWTSecret: "test-key"}, h, database, q)
	if _, err := database.Exec(`INSERT INTO identity_sources (slug, provider_type, display_name) VALUES ('a','feishu','A'),('b','feishu','B')`); err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"alice", "manual", "inactive", "outside", "admin"} {
		source := "a"
		if username == "outside" {
			source = "b"
		}
		seedSyncedAccount(t, ctx, database, source, username, "ext-"+username, username, username, "2999-01-01 00:00:00")
	}
	if _, err := database.Exec(`
UPDATE dsm_accounts SET managed = 0 WHERE dsm_username = 'manual';
UPDATE external_accounts SET active = 0 WHERE subject = 'inactive';
INSERT INTO external_accounts (id,provider_slug,subject,subject_norm,subject_type,app_identity_id)
VALUES ('ext-alice-2','a','alice-2','alice-2','directory_subject','alice');
INSERT INTO dsm_mapping_entries (id, mapping_type, provider_slug, external_account_id, provider_group_id, dsm_account_id)
VALUES ('duplicate','user','a','ext-alice-2','','account-alice');`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.syncSourceToDSM(ctx, "incremental", "a", "2000-01-01", sourceSyncPolicy{}); err != nil {
		t.Fatal(err)
	}
	if len(h.resets) != 0 {
		t.Fatal("incremental sync reset existing passwords")
	}
	for run := 0; run < 2; run++ {
		if _, err := s.syncSourceToDSM(ctx, "full", "a", "2000-01-01", sourceSyncPolicy{FullSync: true}); err != nil {
			t.Fatal(err)
		}
		if len(h.resets) != run+1 || h.resets[run] != "a:alice" {
			t.Fatalf("unexpected targets: %v", h.resets)
		}
	}
	password, ok, err := s.lookupSourceInitialPassword(ctx, "a")
	if err != nil || !ok || password == "" {
		t.Fatal("missing source password")
	}
	if h.passwords[0] != password || h.passwords[1] != password {
		t.Fatal("full-sync retry rotated the source password")
	}
	var logCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sync_operation_logs WHERE action = 'reset_password' AND status = 'success'`).Scan(&logCount); err != nil || logCount != 2 {
		t.Fatalf("success logs = %d, %v", logCount, err)
	}
	var leaked int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sync_operation_logs WHERE error LIKE ? OR after_state LIKE ?`, "%"+password+"%", "%"+password+"%").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("password leaked to sync log")
	}
}

func TestFullSyncResetFailureIsRecordedAndRetryUsesSamePassword(t *testing.T) {
	ctx := context.Background()
	database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	h := &syncPasswordHelper{fail: true}
	s := NewWithDB(config.BackendConfig{AdminJWTSecret: "test-key"}, h, database, q)
	if _, err := database.Exec(`INSERT INTO identity_sources (slug, provider_type, display_name) VALUES ('a','feishu','A')`); err != nil {
		t.Fatal(err)
	}
	seedSyncedAccount(t, ctx, database, "a", "alice", "ext-alice", "alice", "alice", "2999-01-01")
	if _, err := s.syncSourceToDSM(ctx, "failed", "a", "2000-01-01", sourceSyncPolicy{FullSync: true}); err == nil {
		t.Fatal("reset failure was hidden")
	}
	var failures int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sync_operation_logs WHERE action = 'reset_password' AND status = 'failed'`).Scan(&failures); err != nil || failures != 1 {
		t.Fatal("missing failure record")
	}
	h.fail = false
	if _, err := s.syncSourceToDSM(ctx, "retry", "a", "2000-01-01", sourceSyncPolicy{FullSync: true}); err != nil {
		t.Fatal(err)
	}
	if len(h.passwords) != 2 || h.passwords[0] != h.passwords[1] {
		t.Fatal("retry changed the password")
	}
}

func TestFullSyncEmptySourceDoesNotResetPasswords(t *testing.T) {
	database, q, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	h := &syncPasswordHelper{}
	s := NewWithDB(config.BackendConfig{}, h, database, q)
	if _, err := s.resetFullSyncPasswords(context.Background(), "run", "empty", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(h.resets) != 0 {
		t.Fatal("empty source reset passwords")
	}
}

func TestSyncModeEndpointsRejectInvalidModeAndRequireAdmin(t *testing.T) {
	database, q, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, auth := range []bool{false, true} {
		s := NewWithDB(config.BackendConfig{AdminAuthEnabled: auth, AdminJWTSecret: "test-key", AdminUsername: "admin", AdminPassword: "test-secret"}, testHelper{}, database, q)
		for _, path := range []string{"/api/admin/providers/a/sync-runs", "/api/sync/a/apply"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"mode":"typo"}`))
			r.Header.Set("Content-Type", "application/json")
			s.Router().ServeHTTP(w, r)
			if !auth && w.Code != http.StatusBadRequest {
				t.Fatalf("invalid mode: %d", w.Code)
			}
			if auth && w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized reset: %d", w.Code)
			}
		}
	}
}
