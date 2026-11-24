package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

type loginApprovalTestHelper struct {
	testHelper
	called int
}

func (h *loginApprovalTestHelper) WebLoginApproval(_ context.Context, _ string, owner db.CredentialIdentity, identityID string, verify bool) (map[string]any, error) {
	if owner.Username != "alice" || owner.Subject != "emp" || owner.SourceSlug != "source" || identityID != "i" {
		panic("incorrect audit identity")
	}
	h.called++
	return map[string]any{"approved": verify}, nil
}

func TestLoginApprovalUsesLiveMappingAndAdminSession(t *testing.T) {
	ctx := context.Background()
	database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	logDB, logs, err := OpenLogDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer logDB.Close()
	if _, err = database.Exec("INSERT INTO identity_sources(slug,display_name,provider_type) VALUES('source','Source','dingtalk')"); err != nil {
		t.Fatal(err)
	}
	seedSyncedAccount(t, ctx, database, "source", "i", "e", "emp", "alice", "2999-01-01")
	if _, err = logDB.Exec("INSERT INTO login_audit_logs(id,request_id,provider_slug,result,app_identity_id,external_account_id,dsm_username) VALUES('audit','r','source','failed','i','e','alice')"); err != nil {
		t.Fatal(err)
	}
	h := &loginApprovalTestHelper{}
	s := NewWithDatabases(config.BackendConfig{AdminAuthEnabled: true, AdminUsername: "admin", AdminPassword: "fixture"}, h, database, q, logDB, logs)
	router := s.Router()
	token, _, err := s.issueAdminJWT()
	if err != nil {
		t.Fatal(err)
	}
	check := func(auth bool, slug, id, body string, want int) {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/admin/providers/"+slug+"/login-audit/"+id+"/login-approval", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth {
			req.AddCookie(&http.Cookie{Name: s.adminSessionCookieName(), Value: token})
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("HTTP %d expected %d: %s", rec.Code, want, rec.Body.String())
		}
	}
	check(false, "source", "audit", `{"verify":true}`, 401)
	check(true, "wrong", "audit", `{"verify":false}`, 404)
	check(true, "source", "audit", `{}`, 400)
	check(true, "source", "audit", `{"verify":false}`, 200)
	check(true, "source", "audit", `{"verify":true}`, 200)
	if _, err = database.Exec("UPDATE dsm_mapping_entries SET active=0"); err != nil {
		t.Fatal(err)
	}
	check(true, "source", "audit", `{"verify":true}`, 409)
	if h.called != 2 {
		t.Fatalf("unexpected Helper calls %d", h.called)
	}
}
