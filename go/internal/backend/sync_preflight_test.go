package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

type preflightTestHelper struct {
	recordingHelper
	fault    string
	captured atomic.Bool
	matched  bool
	released bool
	names    []string
}

func (h *preflightTestHelper) CaptureDirectory(context.Context, string) error {
	if h.fault == "DSM page" {
		return errors.New("incomplete DSM page")
	}
	h.captured.Store(true)
	return nil
}

func (h *preflightTestHelper) DirectorySnapshot(_ context.Context, _ string, profiles []helperclient.UserProfile) (map[string]helperclient.DirectoryAccountState, error) {
	if !h.captured.Load() || len(h.provisioned) > 0 || len(h.disabled) > 0 {
		return nil, errors.New("DSM write before matching")
	}
	if h.fault == "match" {
		return nil, errors.New("match failed")
	}
	h.matched = true
	result := make(map[string]helperclient.DirectoryAccountState)
	for _, p := range profiles {
		h.names = append(h.names, p.Username)
		result[p.Username] = helperclient.DirectoryReview
	}
	return result, nil
}

func (h *preflightTestHelper) ReleaseDirectory(context.Context, string) error {
	h.released = true
	return nil
}

func TestDirectoryPreflightPrecedesPullAndMissingAccountCleanup(t *testing.T) {
	for _, fault := range []string{"DSM page", "source ID", "match", "none"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			h := &preflightTestHelper{fault: fault}
			var sourceReads atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sourceReads.Add(1)
				if !h.captured.Load() {
					t.Error("source read before complete DSM capture")
				}
				var body string
				switch r.URL.Path {
				case "/tenant":
					body = `{"tenant_access_token":"fixture"}`
				case "/departments/0/children":
					body = `{"data":{"items":[{"open_department_id":"dept","name":"dept"}],"has_more":false}}`
				case "/departments/dept/children":
					body = `{"data":{"items":[],"has_more":false}}`
				case "/users/find_by_department":
					body = `{"data":{"items":[{"open_id":"present","name":"present"}],"has_more":false}}`
					if fault == "source ID" {
						body = `{"data":{"items":[{"open_id":"present","name":"present"},{"name":"before"}],"has_more":false}}`
					}
				default:
					t.Errorf("unexpected source request %s", r.URL.Path)
				}
				_, _ = w.Write([]byte(body))
			}))
			defer remote.Close()
			conf, err := json.Marshal(map[string]any{"tenant_token_url": remote.URL + "/tenant", "contact_base_url": remote.URL, "disable_missing_users": true, "deactivate_missing_data": true})
			if err != nil {
				t.Fatal(err)
			}
			_, err = database.Exec("INSERT INTO identity_sources(slug,provider_type,display_name,enabled,directory_sync_enabled,config_json) VALUES ('review','feishu','Review',1,1,?)", string(conf))
			if err != nil {
				t.Fatal(err)
			}
			seedSyncedAccount(t, ctx, database, "review", "before", "ext-before", "oldsubject", "before", "2000-01-01")
			seedGroupMember(t, ctx, database, "review", "olddept", "oldgroup", "oldmember", "olddept", "oldgroup", "before", 1, "created")
			for _, table := range []string{"dsm_mapping_entries", "provider_groups", "external_accounts"} {
				if _, err := database.Exec("UPDATE " + table + " SET updated_at='2000-01-01'"); err != nil {
					t.Fatal(err)
				}
			}
			s := NewWithDB(config.BackendConfig{RelayMode: "socket", AdminJWTSecret: "test"}, h, database, q)
			_, runErr := s.runSyncProvider(ctx, "review")
			var active int
			if err := database.QueryRow("SELECT active FROM dsm_mapping_entries WHERE id='map-user-ext-before'").Scan(&active); err != nil {
				t.Fatal(err)
			}
			if fault == "none" {
				if runErr != nil || !h.matched || !h.released || active != 0 || !slices.Contains(h.names, "present") || !slices.Equal(h.disabled, []string{"before"}) {
					t.Fatalf("successful sync: %v, matched %v, disabled %v", runErr, h.names, h.disabled)
				}
				return
			}
			want := map[string]string{"DSM page": "incomplete DSM page", "source ID": "身份标识", "match": "match failed"}[fault]
			if runErr == nil || !strings.Contains(runErr.Error(), want) || active != 1 || len(h.provisioned)+len(h.disabled) != 0 {
				t.Fatalf("failure %v, active %d, writes %v / %v", runErr, active, h.provisioned, h.disabled)
			}
			assertLocalMemberStatus(t, ctx, database, "oldmember", 1, "created")
			if (sourceReads.Load() == 0) != (fault == "DSM page") || h.released != (fault != "DSM page") {
				t.Fatalf("source reads %d, released %t", sourceReads.Load(), h.released)
			}
		})
	}
}
