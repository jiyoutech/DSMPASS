package backend

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func stateFixture(t *testing.T) (*Server, string, *http.Cookie) {
	t.Helper()
	state, entry, cookie, err := newOAuthState("source", true, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{states: map[string]oauthState{state: entry}}, state, cookie
}

func callbackRequest(state string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://nas.example.com/idp/source/callback?state="+state, nil)
	r.RemoteAddr = "192.168.1.20:12345"
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

func TestOAuthStateRequiresOriginalBrowserWithoutConsumingOnMismatch(t *testing.T) {
	for _, test := range []string{"missing_cookie", "another_browser", "nonce_in_url", "wrong_source", "duplicate_cookie", "duplicate_state", "wrong_cookie_name"} {
		t.Run(test, func(t *testing.T) {
			s, state, cookie := stateFixture(t)
			source := "source"
			request := callbackRequest(state, cookie)
			switch test {
			case "missing_cookie":
				request = callbackRequest(state)
			case "another_browser":
				request = callbackRequest(state, &http.Cookie{Name: cookie.Name, Value: strings.Repeat("a", 64)})
			case "nonce_in_url":
				request = callbackRequest(state)
				request.URL.RawQuery += "&browser_nonce=" + cookie.Value
			case "wrong_source":
				source = "another"
			case "duplicate_cookie":
				request.AddCookie(cookie)
			case "duplicate_state":
				request.URL.RawQuery += "&state=other"
			case "wrong_cookie_name":
				request = callbackRequest(state, &http.Cookie{Name: "dsmpass_oauth_other", Value: cookie.Value})
			}
			if _, ok := s.consumeOAuthState(state, source, request); ok {
				t.Fatal("unbound callback accepted")
			}
			if _, ok := s.consumeOAuthState(state, "source", callbackRequest(state, cookie)); !ok {
				t.Fatal("invalid callback consumed legitimate state")
			}
			if _, ok := s.consumeOAuthState(state, "source", callbackRequest(state, cookie)); ok {
				t.Fatal("callback replay accepted")
			}
		})
	}
}

func TestOAuthStateRejectsExpiredUnknownAndLegacyState(t *testing.T) {
	s, state, cookie := stateFixture(t)
	if _, ok := s.consumeOAuthState("unknown", "source", callbackRequest("unknown", cookie)); ok {
		t.Fatal("unknown state accepted")
	}
	entry := s.states[state]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	s.states[state] = entry
	if _, ok := s.consumeOAuthState(state, "source", callbackRequest(state, cookie)); ok {
		t.Fatal("expired state accepted")
	}
	if _, ok := s.states[state]; ok {
		t.Fatal("expired state retained")
	}
	s.states[state] = oauthState{ProviderSlug: "source", ExpiresAt: time.Now().Add(time.Minute)}
	if _, ok := s.consumeOAuthState(state, "source", callbackRequest(state, cookie)); ok {
		t.Fatal("legacy state bypassed binding")
	}
}

func TestOAuthConcurrentCallbacksConsumeStateOnce(t *testing.T) {
	s, state, cookie := stateFixture(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.consumeOAuthState(state, "source", callbackRequest(state, cookie)); ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d callbacks", accepted.Load())
	}
}

func TestOAuthTabsHaveIndependentBindingAndNoPredictableFallback(t *testing.T) {
	s, state, cookie := stateFixture(t)
	second, entry, other, err := newOAuthState("source", true, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.states[second] = entry
	if state == second || cookie.Name == other.Name || cookie.Value == other.Value {
		t.Fatal("shared state or browser nonce")
	}
	if _, ok := s.consumeOAuthState(second, "source", callbackRequest(second, cookie, other)); !ok {
		t.Fatal("second tab failed")
	}
	if _, ok := s.consumeOAuthState(state, "source", callbackRequest(state, cookie, other)); !ok {
		t.Fatal("first tab failed")
	}
	if _, _, _, err := newOAuthState("source", true, strings.NewReader("short")); err != io.ErrUnexpectedEOF {
		t.Fatalf("entropy failure did not fail closed: %v", err)
	}
	_, _, plain, err := newOAuthState("source", false, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Secure || strings.HasPrefix(plain.Name, "__Host-") || !plain.HttpOnly || plain.SameSite != http.SameSiteLaxMode {
		t.Fatal("invalid explicit HTTP cookie")
	}
}

func TestOAuthLaunchAndCallbackEnforceBrowserBinding(t *testing.T) {
	database, q, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`INSERT INTO identity_sources (slug,provider_type,display_name,config_json) VALUES ('source','feishu','Test','{"client_id":"test","client_secret":"test"}')`); err != nil {
		t.Fatal(err)
	}
	s := NewWithDB(config.BackendConfig{PublicBaseURL: "https://nas.example.com", RelayMode: "socket", DSMCookieName: "id"}, testHelper{}, database, q)
	router := s.Router()
	launch := httptest.NewRecorder()
	launchRequest := httptest.NewRequest(http.MethodGet, "https://nas.example.com/idp/source/launch", nil)
	launchRequest.RemoteAddr = "192.168.1.20:12345"
	router.ServeHTTP(launch, launchRequest)
	if launch.Code != http.StatusOK {
		t.Fatalf("launch %d: %s", launch.Code, launch.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range launch.Result().Cookies() {
		if strings.HasPrefix(c.Name, "__Host-dsmpass_oauth_") {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("launch did not set binding")
	}
	state := strings.TrimPrefix(cookie.Name, "__Host-dsmpass_oauth_")
	if strings.Contains(launch.Body.String(), cookie.Value) {
		t.Fatal("browser nonce leaked into HTML or authorize URL")
	}
	if launch.Header().Get("Cache-Control") != "no-store" || launch.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("launch may expose cached state")
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 600 || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	attack := httptest.NewRecorder()
	request := callbackRequest(state)
	request.URL.RawQuery += "&code=attacker-code"
	router.ServeHTTP(attack, request)
	if attack.Code != http.StatusBadRequest || !strings.Contains(attack.Body.String(), "浏览器") {
		t.Fatalf("unbound callback advanced: %d %s", attack.Code, attack.Body.String())
	}
	if !strings.Contains(attack.Body.String(), `"restart_url":"/idp/source/launch"`) {
		t.Fatal("API client did not receive safe restart URL")
	}
	page := httptest.NewRecorder()
	pageRequest := callbackRequest(state)
	pageRequest.URL.RawQuery += "&code=attacker-code&redirect=https://untrusted.example/"
	pageRequest.Header.Set("Accept", "text/html")
	router.ServeHTTP(page, pageRequest)
	if page.Code != http.StatusBadRequest || !strings.Contains(page.Header().Get("Content-Type"), "text/html") || !strings.Contains(page.Body.String(), `href="/idp/source/launch"`) {
		t.Fatal("browser did not receive restart page")
	}
	for _, secret := range []string{state, cookie.Value, "attacker-code", "untrusted.example"} {
		if strings.Contains(page.Body.String(), secret) {
			t.Fatal("old callback data leaked into restart page")
		}
	}
	if page.Header().Get("Cache-Control") != "no-store" || page.Header().Get("Referrer-Policy") != "no-referrer" || page.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("restart page missing protections")
	}
	newLaunch := httptest.NewRecorder()
	newRequest := httptest.NewRequest(http.MethodGet, "https://nas.example.com/idp/source/launch", nil)
	newRequest.RemoteAddr = "192.168.1.20:12345"
	router.ServeHTTP(newLaunch, newRequest)
	newCookie := false
	for _, c := range newLaunch.Result().Cookies() {
		if strings.HasPrefix(c.Name, "__Host-dsmpass_oauth_") && c.Name != cookie.Name && c.Value != cookie.Value {
			newCookie = true
		}
	}
	if !newCookie {
		t.Fatal("restart did not create a fresh browser-bound flow")
	}
	valid := httptest.NewRecorder()
	router.ServeHTTP(valid, callbackRequest(state, cookie))
	// No code is supplied: advancing to code validation proves that the original
	// browser survived the attack without contacting a real OAuth provider.
	if valid.Code != http.StatusBadRequest || !strings.Contains(valid.Body.String(), "missing code") {
		t.Fatalf("original browser rejected: %d %s", valid.Code, valid.Body.String())
	}
	if valid.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("callback is cacheable")
	}
	deleted := valid.Result().Cookies()
	if len(deleted) != 1 || deleted[0].Name != cookie.Name || deleted[0].MaxAge != -1 || !deleted[0].Secure {
		t.Fatal("consumed binding cookie was not cleared")
	}
	replay := httptest.NewRecorder()
	router.ServeHTTP(replay, callbackRequest(state, cookie))
	if !strings.Contains(replay.Body.String(), "浏览器") {
		t.Fatal("replay reached code validation")
	}
}
