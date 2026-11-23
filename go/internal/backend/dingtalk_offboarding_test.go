package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

// Exercise the real DingTalk reader, reconciliation, run lifecycle and DSM dispatch together.
func TestDingTalkOffboardingRequiresConfirmedDirectoryResult(t *testing.T) {
	for _, tc := range []struct {
		name                                                                                string
		mode                                                                                syncMode
		present, exclusive, suspended, activated, whole, broken, otherActive, shouldDisable bool
	}{
		{name: "department transfer", mode: syncFull, present: true, activated: true, whole: true},
		{name: "never activated", mode: syncFull, present: true, whole: true},
		{name: "newly frozen enterprise account", mode: syncIncremental, present: true, exclusive: true, suspended: true, activated: true, shouldDisable: true},
		{name: "enabled enterprise account", mode: syncFull, present: true, exclusive: true, activated: true, whole: true},
		{name: "missing in incremental", mode: syncIncremental, whole: true},
		{name: "missing from partial scope", mode: syncFull},
		{name: "missing from entire organization", mode: syncFull, whole: true, shouldDisable: true},
		{name: "another live identity", mode: syncFull, whole: true, otherActive: true},
		{name: "incomplete page", mode: syncFull, whole: true, broken: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var response any
				switch r.URL.Path {
				case "/gettoken":
					response = map[string]any{"access_token": "test"}
				case "/auth/scopes":
					departments := []int{2}
					if tc.whole {
						departments = []int{1}
					}
					response = map[string]any{"auth_org_scopes": map[string]any{"authed_dept": departments}}
				case "/topapi/v2/department/get":
					response = map[string]any{"result": map[string]any{"dept_id": 1, "name": "Engineering"}}
				case "/topapi/v2/department/listsub":
					response = map[string]any{"result": []any{}}
				case "/topapi/user/listsimple":
					list := []any{}
					if tc.present {
						list = append(list, map[string]any{"userid": "employee"})
					}
					response = map[string]any{"result": map[string]any{"list": list, "has_more": tc.broken}}
				case "/topapi/v2/user/get":
					response = map[string]any{"result": map[string]any{"userid": "employee", "unionid": "employee", "name": "alice", "active": tc.activated, "exclusive_account": tc.exclusive, "dept_id_list": []int{1}}}
				case "/v1.0/contact/orgAccounts/status":
					if !tc.exclusive || r.URL.Query().Get("userId") != "employee" || r.Header.Get("x-acs-dingtalk-access-token") != "test" {
						t.Errorf("unexpected status request")
					}
					response = map[string]any{"disable": tc.suspended}
				default:
					t.Errorf("unexpected upstream path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer upstream.Close()
			database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			settings, _ := json.Marshal(identitySourceConfig{ClientID: "fixture", ClientSecret: "fixture", UserInfoURL: upstream.URL + "/me", TenantTokenURL: upstream.URL + "/gettoken", ContactBaseURL: upstream.URL + "/topapi"})
			if _, err := database.Exec("INSERT INTO identity_sources(slug,provider_type,display_name,config_json) VALUES('src','dingtalk','Directory',?)", string(settings)); err != nil {
				t.Fatal(err)
			}
			seedSyncedAccount(t, ctx, database, "src", "i", "ext", "employee", "alice", "2000-01-01")
			if _, err := database.Exec("UPDATE external_accounts SET updated_at='2000-01-01',display_name='alice',subject_type='dingtalk_unionid'; UPDATE dsm_mapping_entries SET updated_at='2000-01-01'"); err != nil {
				t.Fatal(err)
			}
			if tc.name == "department transfer" {
				seedGroupMember(t, ctx, database, "src", "old-dept", "old-group", "old-member", "dept-old", "OldDepartment", "i", 1, "created")
				if _, err := database.Exec("UPDATE dsm_mapping_entries SET updated_at='2000-01-01' WHERE mapping_type IN ('member','group'); UPDATE provider_groups SET updated_at='2000-01-01'"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.otherActive {
				if _, err := database.Exec("INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id) VALUES('second','other','x','x','user','i')"); err != nil {
					t.Fatal(err)
				}
			}
			helper := &recordingHelper{}
			server := NewWithDB(config.BackendConfig{AdminJWTSecret: "test-key"}, helper, database, q)
			_, err = server.runSyncProviderModeWithProgress(ctx, "src", tc.mode, nil)
			if (err != nil) != tc.broken {
				t.Fatalf("sync error: %v", err)
			}
			if tc.name == "department transfer" {
				assertLocalMemberStatus(t, ctx, database, "old-member", 0, "disabled")
				if len(helper.removed) != 0 {
					t.Fatalf("removed existing NAS membership: %v", helper.removed)
				}
			}
			var want []string
			if tc.shouldDisable {
				want = []string{"alice"}
			}
			if !reflect.DeepEqual(helper.disabled, want) {
				t.Fatalf("NAS disabled %v, want %v", helper.disabled, want)
			}
			var status string
			if err := database.QueryRow("SELECT provision_status FROM dsm_accounts WHERE id='account-i'").Scan(&status); err != nil || (status == "disabled") != tc.shouldDisable {
				t.Fatalf("local status %q: %v", status, err)
			}
			if tc.shouldDisable {
				if _, err = server.runSyncProviderModeWithProgress(ctx, "src", tc.mode, nil); err != nil || len(helper.disabled) != 1 {
					t.Fatalf("repeated disable: %v %v", helper.disabled, err)
				}
			}
		})
	}
}
