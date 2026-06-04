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
	if source, err := s.loadIdentitySource(c.Request.Context(), providerSlug); err == nil && source.Enabled == 1 && source.LoginEnabled == 1 && source.ProviderType == "feishu" {
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
		sourceCfg := s.configForSource(source)
		redirectURI := effectivePublicBaseURL(s.trustedPublicBaseURL(), requestPublicBaseURL(c)) + "/idp/" + source.Slug + "/callback"
		feishu := provider.NewFeishuWithSlug(sourceCfg, source.Slug)
		authorizeURL := feishu.BuildAuthorizeURL(state, redirectURI)
		diaglog.Append(s.cfg.DataDir, requestID, "backend.launch.redirect_to_feishu", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"provider_slug": source.Slug,
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
	if source, err := s.loadIdentitySource(c.Request.Context(), providerSlug); err == nil && source.Enabled == 1 && source.LoginEnabled == 1 && source.ProviderType == "feishu" {
		s.handleFeishuCallback(c, source)
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

func (s *Server) handleFeishuCallback(c *gin.Context, source db.IdentitySource) {
	start := time.Now()
	requestID := "go_" + randomHex(12)
	diaglog.Append(s.cfg.DataDir, requestID, "backend.callback.start", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"provider_slug": source.Slug,
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
	sourceCfg := s.configForSource(source)
	feishu := provider.NewFeishuWithSlug(sourceCfg, source.Slug)
	redirectURI := effectivePublicBaseURL(s.trustedPublicBaseURL(), requestPublicBaseURL(c)) + "/idp/" + source.Slug + "/callback"
	diaglog.Append(s.cfg.DataDir, requestID, "backend.feishu.exchange_code.request", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"redirect_uri": redirectURI,
		"code":         code,
	})
	token, err := feishu.ExchangeCode(code, redirectURI)
	if err != nil {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadGateway,
			Detail:    err.Error(),
			ErrorCode: "exchange_code_failed: " + err.Error(),
			EventName: "backend.feishu.exchange_code.error",
			Event:     diaglog.Event{"redirect_uri": redirectURI, "error": err.Error()},
		})
		return
	}
	diaglog.Append(s.cfg.DataDir, requestID, "backend.feishu.exchange_code.success", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"redirect_uri": redirectURI,
		"token":        token,
	})
	profile, err := feishu.FetchProfile(token)
	if err != nil {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadGateway,
			Detail:    err.Error(),
			ErrorCode: "fetch_profile_failed: " + err.Error(),
			EventName: "backend.feishu.fetch_profile.error",
			Event:     diaglog.Event{"error": err.Error()},
		})
		return
	}
	diaglog.Append(s.cfg.DataDir, requestID, "backend.feishu.fetch_profile.success", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{"profile": profile})
	subject, subjectType := feishuProfileSubject(profile)
	diaglog.Append(s.cfg.DataDir, requestID, "backend.feishu.subject.selected", s.cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"subject":      subject,
		"subject_type": subjectType,
		"name":         firstProfileString(profile, "name", "en_name", "nickname"),
		"email":        firstProfileString(profile, "email"),
		"mobile":       firstProfileString(profile, "mobile"),
	})
	if subject == "" {
		s.failRelayCallback(c, source, requestID, start, relayFailure{
			Status:    http.StatusBadGateway,
			Detail:    "feishu profile missing subject",
			ErrorCode: "profile_missing_subject",
			EventName: "backend.feishu.subject.missing",
			Event:     diaglog.Event{"profile": profile},
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

func feishuProfileSubject(profile map[string]any) (string, string) {
	for _, item := range []struct {
		field       string
		subjectType string
	}{
		{"open_id", "feishu_open_id"},
		{"user_id", "feishu_user_id"},
		{"union_id", "feishu_union_id"},
	} {
		if value := firstProfileString(profile, item.field); value != "" {
			return value, item.subjectType
		}
	}
	return "", ""
}
