package backend

import (
	"context"
	"strings"
)

func (s *Server) updateSettings(ctx context.Context, update map[string]any, _ string) error {
	processed := map[string]bool{}
	adminScheme := normalizedAccessScheme(asRuntimeString(update["access_scheme"]), s.cfg.TLSEnabled)
	if _, ok := update["access_scheme"]; !ok {
		adminScheme = s.configuredAccessScheme()
	}
	if value, ok := update["access_scheme"]; ok {
		rawScheme := strings.ToLower(strings.TrimSpace(asRuntimeString(value)))
		if rawScheme != "http" && rawScheme != "https" {
			return badRequest("invalid access_scheme")
		}
		if err := s.persistRuntimeSetting(ctx, "access_scheme", rawScheme); err != nil {
			return err
		}
		if _, explicitPublicBaseURL := update["public_base_url"]; !explicitPublicBaseURL {
			if err := s.persistRuntimeSetting(ctx, "public_base_url", s.cfg.PublicBaseURL); err != nil {
				return err
			}
			processed["public_base_url"] = true
		}
		if _, explicitDSMRedirectURL := update["dsm_redirect_url"]; !explicitDSMRedirectURL {
			if err := s.persistRuntimeSetting(ctx, "dsm_redirect_url", s.cfg.DSMRedirectURL); err != nil {
				return err
			}
			processed["dsm_redirect_url"] = true
		}
		if _, explicitDSMLoginAPI := update["helper_dsm_login_api"]; !explicitDSMLoginAPI {
			if err := s.persistRuntimeSetting(ctx, "helper_dsm_login_api", s.cfg.HelperDSMLoginAPI); err != nil {
				return err
			}
			processed["helper_dsm_login_api"] = true
		}
		processed["access_scheme"] = true
	}
	for key, value := range update {
		if processed[key] || !runtimeSettingAllowed(key) {
			continue
		}
		if key == "access_host" {
			if err := s.updateAccessHostSettings(ctx, value, update, adminScheme, processed); err != nil {
				return err
			}
			continue
		}
		if key == "relay_helper_hmac_secret" || key == "feishu_client_secret" {
			if value == nil || value == "" {
				continue
			}
			if err := s.persistRuntimeSetting(ctx, key, value); err != nil {
				return err
			}
			continue
		}
		if key == "public_base_url" {
			normalized := normalizePublicBaseURL(asRuntimeString(value), adminScheme)
			if normalized == "" {
				return badRequest("invalid public_base_url")
			}
			if port := parsePortInt(publicBaseURLPort(normalized)); port > 0 {
				if err := validateUserPort(port, "public_base_url port"); err != nil {
					return err
				}
			}
			normalized = normalizeURLScheme(normalized, adminScheme)
			if err := s.persistRuntimeSetting(ctx, key, normalized); err != nil {
				return err
			}
			if err := s.CleanupIdentitySourcePublicBaseURLs(ctx); err != nil {
				return internalError(err)
			}
			continue
		}
		if key == "dsm_redirect_url" {
			value = normalizeDSMDefaultPortForScheme(asRuntimeString(value), adminScheme, s.cfg.AccessHost, false)
		}
		if key == "helper_dsm_login_api" {
			value = normalizeDSMDefaultPortForScheme(asRuntimeString(value), adminScheme, s.cfg.AccessHost, true)
		}
		if key == "helper_dsm_login_mode" {
			value = strings.ToLower(strings.TrimSpace(asRuntimeString(value)))
			if value != "helper" && value != "browser" {
				return badRequest("invalid helper_dsm_login_mode")
			}
		}
		if key == "idp_port" {
			port, ok := runtimeInt(value)
			if !ok {
				return badRequest("invalid idp_port")
			}
			if err := validateUserPort(port, "idp_port"); err != nil {
				return err
			}
			value = port
		}
		if err := s.persistRuntimeSetting(ctx, key, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) updateAccessHostSettings(ctx context.Context, raw any, update map[string]any, adminScheme string, processed map[string]bool) error {
	host := normalizeAccessHost(asRuntimeString(raw))
	if host == "" {
		return badRequest("invalid access_host")
	}
	if err := s.persistRuntimeSetting(ctx, "access_host", host); err != nil {
		return err
	}
	publicBaseURL := asRuntimeString(update["public_base_url"])
	if publicBaseURL == "" {
		publicBaseURL = s.publicBaseURLForHost(host)
	}
	if port, ok := runtimeInt(update["idp_port"]); ok {
		publicBaseURL = replaceBaseURLPort(publicBaseURL, port)
	}
	dsmRedirectURL := strings.TrimSpace(asRuntimeString(update["dsm_redirect_url"]))
	if dsmRedirectURL == "" {
		dsmRedirectURL = dsmRedirectURLForHostScheme(host, adminScheme)
	}
	helperDSMLoginAPI := strings.TrimSpace(asRuntimeString(update["helper_dsm_login_api"]))
	if helperDSMLoginAPI == "" {
		helperDSMLoginAPI = dsmLoginAPIForHostScheme(host, adminScheme)
	}
	derived := map[string]any{
		"public_base_url":      normalizeURLScheme(normalizePublicBaseURL(publicBaseURL, adminScheme), adminScheme),
		"dsm_redirect_url":     normalizeDSMDefaultPortForScheme(dsmRedirectURL, adminScheme, host, false),
		"helper_dsm_login_api": normalizeDSMDefaultPortForScheme(helperDSMLoginAPI, adminScheme, host, true),
		"dsm_cookie_secure":    adminScheme == "https",
	}
	if port := parsePortInt(publicBaseURLPort(derived["public_base_url"].(string))); port > 0 {
		if err := validateUserPort(port, "public_base_url port"); err != nil {
			return err
		}
	}
	for derivedKey, derivedValue := range derived {
		if err := s.persistRuntimeSetting(ctx, derivedKey, derivedValue); err != nil {
			return err
		}
		processed[derivedKey] = true
	}
	processed["access_host"] = true
	if err := s.CleanupIdentitySourcePublicBaseURLs(ctx); err != nil {
		return internalError(err)
	}
	return nil
}

func (s *Server) persistRuntimeSetting(ctx context.Context, key string, value any) error {
	if err := s.saveSetting(ctx, key, value); err != nil {
		return internalError(err)
	}
	s.applyRuntimeSetting(key, value)
	return nil
}
