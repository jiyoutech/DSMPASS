package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
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

type recordingHelper struct {
	testHelper
	disabled []string
}

func (h *recordingHelper) DisableUser(ctx context.Context, requestID, username string) (bool, error) {
	h.disabled = append(h.disabled, username)
	return true, nil
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
		AdminAllowedCIDRs: "default ban\nallow 10.0.0.0/8",
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

func TestFirewallRulesMatchInOrderWithDefaultPolicy(t *testing.T) {
	ip := net.ParseIP("10.1.2.3")
	if allowed, _ := firewallDecision(ip, "default allow\nban 10.0.0.0/8\nallow 10.1.2.3", "allow"); allowed {
		t.Fatal("expected first matching ban rule to reject")
	}
	if allowed, _ := firewallDecision(ip, "default:allow;ban:10.0.0.0/8;allow:10.1.2.3", "allow"); allowed {
		t.Fatal("expected compact first matching ban rule to reject")
	}
	if allowed, _ := firewallDecision(ip, "default ban\nallow 10.1.2.3\nban 10.0.0.0/8", "ban"); !allowed {
		t.Fatal("expected first matching allow rule to pass")
	}
	if allowed, _ := firewallDecision(net.ParseIP("203.0.113.10"), "default allow\nban 10.0.0.0/8", "allow"); !allowed {
		t.Fatal("expected default allow when no rule matches")
	}
	if allowed, _ := firewallDecision(net.ParseIP("203.0.113.10"), "default ban\nallow 10.0.0.0/8", "ban"); allowed {
		t.Fatal("expected default ban when no rule matches")
	}
}

func TestFirewallDenyWritesSeparateLogDatabase(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.BackendConfig{
		DataDir:           dataDir,
		RelayMode:         "socket",
		DSMRedirectURL:    "https://nas.example.com/",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		AdminAllowedCIDRs: "default ban\nallow 10.0.0.0/8",
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	blocked := httptest.NewRecorder()
	blockedRequest := httptest.NewRequest("GET", "/api/admin/auth/status", nil)
	blockedRequest.RemoteAddr = "203.0.113.10:12345"
	router.ServeHTTP(blocked, blockedRequest)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d body=%s", blocked.Code, blocked.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "firewall.db")); err != nil {
		t.Fatalf("expected separate firewall database: %v", err)
	}

	logs := httptest.NewRecorder()
	logsRequest := httptest.NewRequest("GET", "/api/admin/firewall/logs", nil)
	logsRequest.RemoteAddr = "10.1.2.3:12345"
	router.ServeHTTP(logs, logsRequest)
	if logs.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d body=%s", logs.Code, logs.Body.String())
	}
	if !strings.Contains(logs.Body.String(), "203.0.113.10") {
		t.Fatalf("expected denied remote ip in firewall logs, got %s", logs.Body.String())
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
	rejectedRequest := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader("{\"admin_allowed_cidrs\":\"default ban\\nallow 10.0.0.0/8\"}"))
	rejectedRequest.Header.Set("Content-Type", "application/json")
	rejectedRequest.RemoteAddr = "203.0.113.10:12345"
	router.ServeHTTP(rejected, rejectedRequest)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", rejected.Code, rejected.Body.String())
	}

	accepted := httptest.NewRecorder()
	acceptedRequest := httptest.NewRequest("PUT", "/api/admin/settings", strings.NewReader("{\"admin_allowed_cidrs\":\"default ban\\nallow 10.0.0.0/8\"}"))
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

func TestRestartPackageEndpointSchedulesControlScript(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	script := filepath.Join(dir, "start-stop-status")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$1\" > '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := packageControlScripts
	packageControlScripts = []string{script}
	t.Cleanup(func() {
		packageControlScripts = original
	})

	cfg := config.BackendConfig{RelayMode: "socket", DSMCookieName: "id"}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	router := NewWithDB(cfg, testHelper{}, database, queries).Router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/admin/package/restart", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", response.Code, response.Body.String())
	}
	for range 30 {
		called, err := os.ReadFile(marker)
		if err == nil {
			if string(called) != "restart" {
				t.Fatalf("package control called with %q", string(called))
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("package control script was not called")
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
	if !strings.Contains(body, `method=logout`) || !strings.Contains(body, `session=webui`) {
		t.Fatalf("launch should call DSM logout before authorization: %s", body)
	}
	cookies := launchResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "id" || cookies[0].MaxAge != -1 {
		t.Fatalf("launch should expire existing DSM session before authorization, got %#v", cookies)
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

func TestSettingsPublicBaseURLAllowsIndependentIDPHostPortButUsesDSMScheme(t *testing.T) {
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
	if !strings.Contains(response.Body.String(), fmt.Sprintf(`"public_base_url":"https://idp.example.com:%d"`, idpPort)) {
		t.Fatalf("public base url did not preserve independent IDP host/port with DSM scheme: %s", response.Body.String())
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
	for _, item := range []struct {
		table string
		where string
	}{
		{"identity_sources", "slug = 'source-a'"},
		{"external_accounts", "provider_slug = 'source-a'"},
		{"app_identities", "id = 'identity-a'"},
		{"dsm_accounts", "id = 'account-a'"},
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
	assertStatus(t, router, "GET", "/idp/missing/launch", http.StatusNotFound)

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
	if _, err := database.ExecContext(ctx, `INSERT INTO group_links (id, provider_group_id, dsm_group_id) VALUES ('link-a', 'provider-group-a', 'group-a')`); err != nil {
		t.Fatal(err)
	}
	router := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries).Router()

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
