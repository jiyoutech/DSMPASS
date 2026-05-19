package backend

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) LoadRuntimeSettings(ctx context.Context) error {
	rows, err := s.store.ListRuntimeSettings(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		var value any
		if err := json.Unmarshal([]byte(row.ValueJson), &value); err != nil {
			return err
		}
		switch row.Key {
		case "dsm_redirect_url":
			value = normalizeDSMBaseURL(asRuntimeString(value))
		case "helper_dsm_login_api":
			value = normalizeDSMAPIURL(asRuntimeString(value))
		}
		s.applyRuntimeSetting(row.Key, value)
	}
	if port := parsePortInt(listenAddressPort(s.cfg.IDPListen)); port > 0 {
		s.cfg.PublicBaseURL = replaceBaseURLPort(s.cfg.PublicBaseURL, port)
	}
	s.refreshAdminSetupState()
	if err := s.ensureAdminJWTSecret(ctx); err != nil {
		return err
	}
	if err := s.persistPublicBaseURLPolicy(ctx); err != nil {
		return err
	}
	if err := s.CleanupIdentitySourcePublicBaseURLs(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Server) effectiveSettings(ctx context.Context) (map[string]any, error) {
	settings := map[string]any{
		"access_host":                          s.cfg.AccessHost,
		"access_scheme":                        s.configuredAccessScheme(),
		"admin_port":                           firstPositiveInt(parsePortInt(listenAddressPort(s.cfg.Listen)), 25000),
		"idp_port":                             firstPositiveInt(parsePortInt(publicBaseURLPort(s.cfg.PublicBaseURL)), 25000),
		"admin_allowed_cidrs":                  s.cfg.AdminAllowedCIDRs,
		"idp_allowed_cidrs":                    s.cfg.IDPAllowedCIDRs,
		"public_base_url":                      s.cfg.PublicBaseURL,
		"dsm_redirect_url":                     s.cfg.DSMRedirectURL,
		"dsm_cookie_name":                      s.cfg.DSMCookieName,
		"dsm_cookie_secure":                    s.cfg.DSMCookieSecure,
		"dsm_cookie_httponly":                  s.cfg.DSMCookieHTTPOnly,
		"dsm_cookie_samesite":                  s.cfg.DSMCookieSameSite,
		"helper_dsm_login_mode":                s.cfg.DSMLoginMode,
		"helper_dsm_browser_login_ttl_seconds": s.cfg.DSMBrowserLoginTTLSeconds,
		"helper_dsm_login_api":                 s.cfg.HelperDSMLoginAPI,
		"helper_dsm_session":                   "webui",
		"helper_dsm_format":                    "",
		"helper_dsm_otp_code":                  "",
		"helper_dsm_enable_device_token":       "",
		"helper_dsm_device_name":               "",
		"helper_dsm_device_id":                 "",
		"helper_dsm_tls_skip_verify":           true,
		"setup_completed":                      false,
		"helper_hmac_secret_configured":        s.cfg.RelayHelperHMACSecret != "",
	}
	rows, err := s.store.ListRuntimeSettings(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Key == "relay_mode" || strings.HasPrefix(row.Key, "feishu_") || strings.HasPrefix(row.Key, "username_") || strings.HasPrefix(row.Key, "admin_") {
			if row.Key == "relay_helper_hmac_secret" {
				settings["helper_hmac_secret_configured"] = row.ValueJson != `""`
			}
			continue
		}
		if row.Key == "relay_helper_hmac_secret" {
			settings["helper_hmac_secret_configured"] = row.ValueJson != `""`
			continue
		}
		var value any
		if err := json.Unmarshal([]byte(row.ValueJson), &value); err != nil {
			return nil, err
		}
		settings[row.Key] = value
	}
	return settings, nil
}

func (s *Server) saveSetting(ctx context.Context, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.store.UpsertRuntimeSetting(ctx, db.UpsertRuntimeSettingParams{Key: key, ValueJson: string(raw)})
}

func (s *Server) applyRuntimeSetting(key string, value any) {
	asString := func() string {
		if v, ok := value.(string); ok {
			return v
		}
		return ""
	}
	asBool := func() bool {
		if v, ok := value.(bool); ok {
			return v
		}
		return false
	}
	switch key {
	case "access_host":
		host := normalizeAccessHost(asString())
		s.cfg.AccessHost = host
		s.cfg.PublicBaseURL = s.publicBaseURLForHost(host)
		s.cfg.DSMRedirectURL = dsmRedirectURLForHostScheme(host, s.cfg.AccessScheme)
		s.cfg.HelperDSMLoginAPI = dsmLoginAPIForHostScheme(host, s.cfg.AccessScheme)
	case "access_scheme":
		scheme := normalizedAccessScheme(asString(), s.cfg.TLSEnabled)
		s.cfg.AccessScheme = scheme
		s.cfg.PublicBaseURL = normalizeURLScheme(s.cfg.PublicBaseURL, scheme)
		s.cfg.DSMRedirectURL = normalizeDSMDefaultPortForScheme(s.cfg.DSMRedirectURL, scheme, s.cfg.AccessHost, false)
		s.cfg.HelperDSMLoginAPI = normalizeDSMDefaultPortForScheme(s.cfg.HelperDSMLoginAPI, scheme, s.cfg.AccessHost, true)
		s.cfg.DSMCookieSecure = scheme == "https"
	case "public_base_url":
		s.cfg.PublicBaseURL = normalizeURLScheme(normalizePublicBaseURL(asString(), s.configuredAccessScheme()), s.configuredAccessScheme())
	case "idp_port":
		if port, ok := runtimeInt(value); ok {
			s.cfg.IDPListen = replaceListenPort(s.cfg.IDPListen, s.cfg.Listen, port)
			s.cfg.PublicBaseURL = replaceBaseURLPort(s.cfg.PublicBaseURL, port)
		}
	case "admin_allowed_cidrs":
		s.cfg.AdminAllowedCIDRs = asString()
	case "idp_allowed_cidrs":
		s.cfg.IDPAllowedCIDRs = asString()
	case "dsm_redirect_url":
		s.cfg.DSMRedirectURL = normalizeDSMBaseURL(asString())
	case "helper_dsm_login_api":
		s.cfg.HelperDSMLoginAPI = normalizeDSMAPIURL(asString())
	case "dsm_cookie_name":
		s.cfg.DSMCookieName = asString()
	case "dsm_cookie_secure":
		s.cfg.DSMCookieSecure = asBool()
	case "dsm_cookie_httponly":
		s.cfg.DSMCookieHTTPOnly = asBool()
	case "dsm_cookie_samesite":
		s.cfg.DSMCookieSameSite = asString()
	case "helper_dsm_login_mode":
		mode := strings.ToLower(strings.TrimSpace(asString()))
		if mode == "helper" || mode == "browser" {
			s.cfg.DSMLoginMode = mode
		}
	case "helper_dsm_browser_login_ttl_seconds":
		if v, ok := value.(float64); ok && v > 0 {
			s.cfg.DSMBrowserLoginTTLSeconds = int(v)
		}
	case "relay_helper_hmac_secret":
		s.cfg.RelayHelperHMACSecret = asString()
		s.helper = HelperFromConfig(s.cfg)
	case "admin_username":
		s.cfg.AdminUsername = asString()
	case "admin_password_hash":
		s.cfg.AdminPassword = asString()
	case "admin_jwt_secret":
		s.cfg.AdminJWTSecret = asString()
	}
}

func runtimeInt(value any) (int, bool) {
	switch v := value.(type) {
	case float64:
		if v > 0 {
			return int(v), true
		}
	case int:
		if v > 0 {
			return v, true
		}
	}
	return 0, false
}

func (s *Server) ensureAdminJWTSecret(ctx context.Context) error {
	if !s.cfg.AdminAuthEnabled || s.cfg.AdminJWTSecret != "" || s.store == nil {
		return nil
	}
	secret := randomHex(32)
	if err := s.saveSetting(ctx, "admin_jwt_secret", secret); err != nil {
		return err
	}
	s.cfg.AdminJWTSecret = secret
	return nil
}
