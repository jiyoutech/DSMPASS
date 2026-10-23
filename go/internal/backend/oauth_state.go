package backend

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"time"
)

// Use a separate cookie for each attempt, so simultaneous tabs do not replace
// each other's browser binding. The nonce never appears in the authorize URL.
func newOAuthState(source string, secure bool, entropy io.Reader) (string, oauthState, *http.Cookie, error) {
	data := make([]byte, 48)
	if _, err := io.ReadFull(entropy, data); err != nil {
		return "", oauthState{}, nil, err
	}
	state, nonce := hex.EncodeToString(data[:16]), hex.EncodeToString(data[16:])
	name := "dsmpass_oauth_" + state
	if secure {
		name = "__Host-" + name
	}
	entry := oauthState{ProviderSlug: source, ExpiresAt: time.Now().Add(oauthStateTTL), CookieName: name, BrowserHash: sha256.Sum256([]byte(nonce))}
	cookie := &http.Cookie{Name: name, Value: nonce, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(oauthStateTTL.Seconds())}
	return state, entry, cookie, nil
}

func (s *Server) consumeOAuthState(state, source string, request *http.Request) (oauthState, bool) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	entry, ok := s.states[state]
	if !ok {
		return entry, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.states, state)
		return entry, false
	}
	if entry.ProviderSlug != source || entry.CookieName == "" || len(request.URL.Query()["state"]) != 1 {
		return entry, false
	}
	var nonce string
	count := 0
	for _, cookie := range request.Cookies() {
		if cookie.Name == entry.CookieName {
			nonce = cookie.Value
			count++
		}
	}
	if count != 1 || len(nonce) != 64 {
		return entry, false
	}
	hash := sha256.Sum256([]byte(nonce))
	if subtle.ConstantTimeCompare(hash[:], entry.BrowserHash[:]) != 1 {
		return entry, false
	}
	delete(s.states, state)
	return entry, true
}
