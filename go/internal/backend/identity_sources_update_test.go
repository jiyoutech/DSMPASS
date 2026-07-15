package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestUpdateProviderAllowsCredentialBackfillForIncompleteSource(t *testing.T) {
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(context.Background(), `
INSERT INTO identity_sources (slug, provider_type, display_name, config_json)
VALUES ('legacy-wecom', 'wecom', '历史企业微信', '{}')`); err != nil {
		t.Fatal(err)
	}
	router := NewWithDB(config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}, testHelper{}, database, queries).Router()

	updateResponse := httptest.NewRecorder()
	updateRequest := httptest.NewRequest("PUT", "/api/admin/providers/legacy-wecom", strings.NewReader(`{
		"config": {
			"client_id": " wwcorp ",
			"agent_id": " 1000002 ",
			"client_secret": " secret "
		}
	}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("backfill provider credentials got %d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	var updated struct {
		CredentialsConfigured bool `json:"credentials_configured"`
		Config                struct {
			ClientID string `json:"client_id"`
			AgentID  string `json:"agent_id"`
		} `json:"config"`
	}
	if err := json.Unmarshal(updateResponse.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.CredentialsConfigured || updated.Config.ClientID != "wwcorp" || updated.Config.AgentID != "1000002" {
		t.Fatalf("unexpected backfilled source response: %#v", updated)
	}

	lockedResponse := httptest.NewRecorder()
	lockedRequest := httptest.NewRequest("PUT", "/api/admin/providers/legacy-wecom", strings.NewReader(`{"config":{"agent_id":"1000003"}}`))
	lockedRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(lockedResponse, lockedRequest)
	if lockedResponse.Code != http.StatusBadRequest || !strings.Contains(lockedResponse.Body.String(), "Agent ID cannot be changed") {
		t.Fatalf("agent_id change got %d body=%s", lockedResponse.Code, lockedResponse.Body.String())
	}
}

func TestUpdateProviderAcceptsSameImmutableCredentialValues(t *testing.T) {
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}, testHelper{}, database, queries).Router()

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{
		"provider_type": "feishu",
		"display_name": "飞书",
		"config": {
			"client_id": "cli_original",
			"client_secret": "secret_original"
		}
	}`))
	createRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusOK {
		t.Fatalf("create provider got %d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	updateResponse := httptest.NewRecorder()
	updateRequest := httptest.NewRequest("PUT", "/api/admin/providers/"+created.Slug, strings.NewReader(`{
		"display_name": "飞书主应用",
		"config": {
			"client_id": " cli_original ",
			"client_secret": " secret_original ",
			"sync_interval_minutes": 30
		}
	}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("same credential update got %d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	if strings.Contains(updateResponse.Body.String(), "secret_original") {
		t.Fatalf("provider response leaked client secret: %s", updateResponse.Body.String())
	}
	var updated struct {
		DisplayName string `json:"display_name"`
		Config      struct {
			ClientID            string `json:"client_id"`
			SyncIntervalMinutes int    `json:"sync_interval_minutes"`
		} `json:"config"`
	}
	if err := json.Unmarshal(updateResponse.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "飞书主应用" || updated.Config.ClientID != "cli_original" || updated.Config.SyncIntervalMinutes != 30 {
		t.Fatalf("unexpected same credential update response: %#v", updated)
	}
}

func TestUpdateProviderRejectsImmutableAgentIDChange(t *testing.T) {
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}, testHelper{}, database, queries).Router()

	createResponse := httptest.NewRecorder()
	createRequest := httptest.NewRequest("POST", "/api/admin/providers", strings.NewReader(`{
		"provider_type": "wecom",
		"display_name": "企业微信",
		"config": {
			"client_id": "wwcorp",
			"agent_id": "1000002",
			"client_secret": "secret"
		}
	}`))
	createRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusOK {
		t.Fatalf("create provider got %d body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	updateResponse := httptest.NewRecorder()
	updateRequest := httptest.NewRequest("PUT", "/api/admin/providers/"+created.Slug, strings.NewReader(`{"config":{"agent_id":"1000003"}}`))
	updateRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusBadRequest || !strings.Contains(updateResponse.Body.String(), "Agent ID cannot be changed") {
		t.Fatalf("agent_id update got %d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
}
