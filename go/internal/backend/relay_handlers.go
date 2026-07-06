package backend

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/diaglog"
	"github.com/dsmpass/dsmpass/go/internal/identity"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

func (s *Server) launch(c *gin.Context) {
	providerSlug := c.Param("provider")
	if source, err := s.loadIdentitySource(c.Request.Context(), providerSlug); err == nil && source.Enabled == 1 && source.LoginEnabled == 1 {
		oauthProvider, ok := s.oauthProviderForSource(source)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found or login disabled"})
			return
		}
		requestID := "go_launch_" + randomHex(12)
		state := randomHex(16)
		s.stateMu.Lock()
		now := time.Now()
		for key, entry := range s.states {
			if now.After(entry.ExpiresAt) {
				delete(s.states, key)
			}
		}
		s.states[state] = oauthState{ProviderSlug: source.Slug, ExpiresAt: now.Add(oauthStateTTL)}
		s.stateMu.Unlock()
		redirectURI := effectivePublicBaseURL(s.trustedPublicBaseURL(), requestPublicBaseURL(c)) + "/idp/" + source.Slug + "/callback"
		authorizeURL := oauthProvider.BuildAuthorizeURL(state, redirectURI)
		diaglog.Append(s.cfg.DataDir, requestID, "backend.launch.redirect_to_provider", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"provider_slug": source.Slug,
			"provider_type": source.ProviderType,
			"request_url":   c.Request.URL.String(),
			"host":          c.Request.Host,
			"user_agent":    c.Request.UserAgent(),
			"remote_addr":   c.Request.RemoteAddr,
			"state":         state,
			"redirect_uri":  redirectURI,
			"authorize_url": authorizeURL,
		})
		s.clearDSMCookie(c)
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(renderLaunchLogoutPage(authorizeURL, dsmLogoutURL(requestDSMLoginAPI(c, s.cfg.HelperDSMLoginAPI)))))
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found or login disabled"})
}

func (s *Server) callback(c *gin.Context) {
	providerSlug := c.Param("provider")
	if source, err := s.loadIdentitySource(c.Request.Context(), providerSlug); err == nil && source.Enabled == 1 && source.LoginEnabled == 1 {
		oauthProvider, ok := s.oauthProviderForSource(source)
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found or login disabled"})
			return
		}
		s.handleOAuthCallback(c, source, oauthProvider)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found or login disabled"})
}

func (s *Server) completeBrowserLogin(c *gin.Context) {
	providerSlug := c.Param("provider")
	if source, err := s.loadIdentitySource(c.Request.Context(), providerSlug); err != nil || source.Enabled != 1 || source.LoginEnabled != 1 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found or login disabled"})
		return
	}
	var request struct {
		RequestID string `json:"request_id"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.RequestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "request_id required"})
		return
	}
	if err := s.helper.CompleteBrowserLogin(c.Request.Context(), request.RequestID); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) handleOAuthCallback(c *gin.Context, source db.IdentitySource, oauthProvider provider.OAuth) {
	start := time.Now()
	requestID := "go_" + randomHex(12)
	diaglog.Append(s.cfg.DataDir, requestID, "backend.callback.start", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"provider_slug": source.Slug,
		"provider_type": source.ProviderType,
		"request_url":   c.Request.URL.String(),
		"host":          c.Request.Host,
		"user_agent":    c.Request.UserAgent(),
		"remote_addr":   c.Request.RemoteAddr,
		"state":         c.Query("state"),
		"code_present":  c.Query("code") != "",
	})
	if !s.validateCallbackState(c, source, requestID, start) {
		return
	}
	code := c.Query("code")
	if code == "" {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadRequest,
			Detail:    "missing code",
			ErrorCode: "missing_code",
			EventName: "backend.callback.code.missing",
			Event:     diaglog.Event{"request_url": c.Request.URL.String()},
		})
		return
	}
	redirectURI := effectivePublicBaseURL(s.trustedPublicBaseURL(), requestPublicBaseURL(c)) + "/idp/" + source.Slug + "/callback"
	diaglog.Append(s.cfg.DataDir, requestID, "backend.oauth.exchange_code.request", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"provider_type": source.ProviderType,
		"redirect_uri":  redirectURI,
		"code":          code,
	})
	token, err := oauthProvider.ExchangeCode(code, redirectURI)
	if err != nil {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadGateway,
			Detail:    err.Error(),
			ErrorCode: "exchange_code_failed: " + err.Error(),
			EventName: "backend.oauth.exchange_code.error",
			Event:     diaglog.Event{"provider_type": source.ProviderType, "redirect_uri": redirectURI, "error": err.Error()},
		})
		return
	}
	diaglog.Append(s.cfg.DataDir, requestID, "backend.oauth.exchange_code.success", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"provider_type": source.ProviderType,
		"redirect_uri":  redirectURI,
		"token":         token,
	})
	profile, err := oauthProvider.FetchProfile(token)
	if err != nil {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadGateway,
			Detail:    err.Error(),
			ErrorCode: "fetch_profile_failed: " + err.Error(),
			EventName: "backend.oauth.fetch_profile.error",
			Event:     diaglog.Event{"provider_type": source.ProviderType, "error": err.Error()},
		})
		return
	}
	diaglog.Append(s.cfg.DataDir, requestID, "backend.oauth.fetch_profile.success", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{"provider_type": source.ProviderType, "profile": profile})
	subject, subjectType := oauthProvider.ProfileSubject(profile)
	diaglog.Append(s.cfg.DataDir, requestID, "backend.oauth.subject.selected", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"provider_type": source.ProviderType,
		"subject":       subject,
		"subject_type":  subjectType,
		"name":          firstProfileString(profile, "name", "en_name", "nickname"),
		"email":         firstProfileString(profile, "email"),
		"mobile":        firstProfileString(profile, "mobile"),
	})
	if subject == "" {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadGateway,
			Detail:    "oauth profile missing subject",
			ErrorCode: "profile_missing_subject",
			EventName: "backend.oauth.subject.missing",
			Event:     diaglog.Event{"provider_type": source.ProviderType, "profile": profile},
		})
		return
	}
	service := identity.NewService(s.cfg, s.store)
	external, appIdentity, account, err := service.ResolveAuthorizedLogin(c.Request.Context(), source.Slug, subject)
	if err != nil {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:            http.StatusForbidden,
			Detail:            "login not authorized",
			ErrorCode:         "login_not_authorized: " + err.Error(),
			ExternalAccountID: external.ID,
			AppIdentityID:     appIdentity.ID,
			DSMUsername:       account.DSMUsername,
			EventName:         "backend.identity.login_not_authorized",
			Event: diaglog.Event{
				"error":            err.Error(),
				"external_active":  external.Active,
				"identity_status":  appIdentity.Status,
				"allow_login":      account.AllowLogin,
				"provision_status": account.ProvisionStatus,
				"dsm_username":     account.DSMUsername,
			},
		})
		return
	}
	diaglog.Append(s.cfg.DataDir, requestID, "backend.identity.resolved", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"external_account_id": external.ID,
		"app_identity_id":     appIdentity.ID,
		"display_name":        nullableString(appIdentity.DisplayName),
		"dsm_username":        account.DSMUsername,
		"allow_login":         account.AllowLogin,
		"provision_status":    account.ProvisionStatus,
	})
	if s.cfg.DSMLoginMode == "browser" {
		dsmLoginAPI := requestDSMLoginAPI(c, s.cfg.HelperDSMLoginAPI)
		dsmRedirectURL := requestDSMRedirectURL(c, s.cfg.DSMRedirectURL)
		relaunchURL := effectivePublicBaseURL(s.trustedPublicBaseURL(), requestPublicBaseURL(c)) + "/idp/" + source.Slug + "/launch"
		browserLogin, err := s.helper.PrepareBrowserLogin(c.Request.Context(), requestID, account.DSMUsername, appIdentity.ID, source.Slug)
		if err != nil {
			s.failRelayCallback(c, source, requestID, start, relayFailure{
				Status:            http.StatusBadGateway,
				Detail:            err.Error(),
				ErrorCode:         "prepare_browser_login_failed: " + err.Error(),
				ExternalAccountID: external.ID,
				AppIdentityID:     appIdentity.ID,
				DSMUsername:       account.DSMUsername,
				EventName:         "backend.helper.prepare_browser_login.failed",
				Event:             diaglog.Event{"dsm_username": account.DSMUsername, "error": err.Error()},
			})
			return
		}
		diaglog.Append(s.cfg.DataDir, requestID, "backend.browser_dsm_login.page", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"dsm_username": account.DSMUsername,
			"login_api":    dsmLoginAPI,
			"redirect_url": dsmRedirectURL,
			"relaunch_url": relaunchURL,
			"request_host": c.Request.Host,
			"expires_at":   browserLogin.ExpiresAt,
			"ttl_seconds":  browserLogin.TTLSeconds,
		})
		s.logLoginAudit(c.Request.Context(), loginAuditEvent{
			RequestID:         requestID,
			Provider:          source.Slug,
			ExternalAccountID: external.ID,
			AppIdentityID:     appIdentity.ID,
			DSMUsername:       account.DSMUsername,
			Result:            "success",
			IPAddress:         requestClientIP(c),
			DurationMs:        time.Since(start).Milliseconds(),
		})
		s.clearDSMCookie(c)
		completeURL := effectivePublicBaseURL(s.trustedPublicBaseURL(), requestPublicBaseURL(c)) + "/idp/" + source.Slug + "/browser-login/complete"
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(renderBrowserDSMLoginPage(browserLogin, dsmLoginAPI, dsmRedirectURL, relaunchURL, completeURL, requestID)))
		return
	}
	relayResult, err := s.helper.RelayLogin(c.Request.Context(), requestID, account.DSMUsername, appIdentity.ID, source.Slug)
	if err != nil {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:            http.StatusBadGateway,
			Detail:            err.Error(),
			ErrorCode:         "relay_login_failed: " + err.Error(),
			ExternalAccountID: external.ID,
			AppIdentityID:     appIdentity.ID,
			DSMUsername:       account.DSMUsername,
			EventName:         "backend.helper.relay_login.failed",
			Event:             diaglog.Event{"dsm_username": account.DSMUsername, "error": err.Error()},
		})
		return
	}
	writtenCookies := s.writeDSMCookies(c, relayResult)
	dsmRedirectURL := requestDSMRedirectURL(c, s.cfg.DSMRedirectURL)
	diaglog.Append(s.cfg.DataDir, requestID, "backend.cookie.set", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"cookie_name":     s.cfg.DSMCookieName,
		"cookie_value":    relayResult.SID,
		"cookie_path":     "/",
		"cookie_domain":   "",
		"cookie_secure":   s.cfg.DSMCookieSecure,
		"cookie_httponly": s.cfg.DSMCookieHTTPOnly,
		"redirect_url":    dsmRedirectURL,
		"relay_cookies":   relayResult.Cookies,
		"written_cookies": writtenCookies,
		"set_cookie":      c.Writer.Header().Values("Set-Cookie"),
		"location":        dsmRedirectURL,
	})
	s.logLoginAudit(c.Request.Context(), loginAuditEvent{
		RequestID:         requestID,
		Provider:          source.Slug,
		ExternalAccountID: external.ID,
		AppIdentityID:     appIdentity.ID,
		DSMUsername:       account.DSMUsername,
		Result:            "success",
		IPAddress:         requestClientIP(c),
		DurationMs:        time.Since(start).Milliseconds(),
	})
	c.Redirect(http.StatusFound, dsmRedirectURL)
}
