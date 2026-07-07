package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"sort"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) updateSettings(ctx context.Context, update map[string]any, _ string, clientIP net.IP) error {
	plan, err := s.planSettingsUpdate(update, clientIP)
	if err != nil {
		return err
	}
	return s.commitSettingsUpdate(ctx, plan)
}

type settingsUpdatePlan struct {
	values                 map[string]any
	cleanupIdentitySources bool
}

func newSettingsUpdatePlan() *settingsUpdatePlan {
	return &settingsUpdatePlan{values: map[string]any{}}
}

func (p *settingsUpdatePlan) set(draft *Server, key string, value any) {
	p.values[key] = value
	draft.applyRuntimeSetting(key, value)
}

func (s *Server) planSettingsUpdate(update map[string]any, clientIP net.IP) (*settingsUpdatePlan, error) {
	draft := &Server{cfg: s.cfg}
	plan := newSettingsUpdatePlan()
	processed := map[string]bool{}
	adminScheme := normalizedAccessScheme(asRuntimeString(update["access_scheme"]), s.cfg.TLSEnabled)
	if _, ok := update["access_scheme"]; !ok {
		adminScheme = s.configuredAccessScheme()
	}
	if err := draft.validateBrowserDSMProtocol(update, adminScheme); err != nil {
		return nil, err
	}
	if value, ok := update["access_scheme"]; ok {
		rawScheme := strings.ToLower(strings.TrimSpace(asRuntimeString(value)))
		if rawScheme != "http" && rawScheme != "https" {
			return nil, badRequest("invalid access_scheme")
		}
		plan.set(draft, "access_scheme", rawScheme)
		if _, explicitPublicBaseURL := update["public_base_url"]; !explicitPublicBaseURL {
			plan.set(draft, "public_base_url", draft.cfg.PublicBaseURL)
			processed["public_base_url"] = true
		}
		if _, explicitDSMRedirectURL := update["dsm_redirect_url"]; !explicitDSMRedirectURL {
			plan.set(draft, "dsm_redirect_url", draft.cfg.DSMRedirectURL)
			processed["dsm_redirect_url"] = true
		}
		if _, explicitDSMLoginAPI := update["helper_dsm_login_api"]; !explicitDSMLoginAPI {
			plan.set(draft, "helper_dsm_login_api", draft.cfg.HelperDSMLoginAPI)
			processed["helper_dsm_login_api"] = true
		}
		processed["access_scheme"] = true
	}
	for key, value := range update {
		if processed[key] || !runtimeSettingAllowed(key) {
			continue
		}
		if key == "access_host" {
			if err := planAccessHostSettings(draft, plan, value, update, adminScheme, processed); err != nil {
				return nil, err
			}
			continue
		}
		if key == "relay_helper_hmac_secret" || key == "feishu_client_secret" {
			if value == nil || value == "" {
				continue
			}
			plan.set(draft, key, value)
			continue
		}
		if key == "public_base_url" {
			normalized := normalizePublicBaseURL(asRuntimeString(value), adminScheme)
			if normalized == "" {
				return nil, badRequest("invalid public_base_url")
			}
			plan.set(draft, key, normalized)
			plan.cleanupIdentitySources = true
			continue
		}
		if key == "deployment_mode" {
			mode := strings.ToLower(strings.TrimSpace(asRuntimeString(value)))
			if !validDeploymentMode(mode) {
				return nil, badRequest("invalid deployment_mode")
			}
			value = mode
		}
		if key == "dsm_redirect_url" {
			value = normalizeDSMDefaultPortForScheme(asRuntimeString(value), adminScheme, draft.cfg.AccessHost, false)
		}
		if key == "helper_dsm_login_api" {
			value = normalizeDSMDefaultPortForScheme(asRuntimeString(value), adminScheme, draft.cfg.AccessHost, true)
		}
		if key == "helper_dsm_login_mode" {
			value = strings.ToLower(strings.TrimSpace(asRuntimeString(value)))
			if value != "helper" && value != "browser" {
				return nil, badRequest("invalid helper_dsm_login_mode")
			}
		}
		if key == "idp_port" {
			port, ok := runtimeInt(value)
			if !ok {
				return nil, badRequest("invalid idp_port")
			}
			if err := validateUserPort(port, "idp_port"); err != nil {
				return nil, err
			}
			value = port
		}
		if key == "admin_allowed_cidrs" {
			value = strings.TrimSpace(asRuntimeString(value))
			if err := validateCIDRList(value.(string), "admin_allowed_cidrs"); err != nil {
				return nil, err
			}
			if clientIP != nil && !allowedByCIDRs(clientIP, value.(string)) {
				return nil, badRequest("admin_allowed_cidrs must include current client IP")
			}
		}
		if key == "idp_allowed_cidrs" {
			value = strings.TrimSpace(asRuntimeString(value))
			if err := validateCIDRList(value.(string), "idp_allowed_cidrs"); err != nil {
				return nil, err
			}
		}
		plan.set(draft, key, value)
	}
	return plan, nil
}

func planAccessHostSettings(draft *Server, plan *settingsUpdatePlan, raw any, update map[string]any, adminScheme string, processed map[string]bool) error {
	host := normalizeAccessHost(asRuntimeString(raw))
	if host == "" {
		return badRequest("invalid access_host")
	}
	plan.set(draft, "access_host", host)
	publicBaseURL := asRuntimeString(update["public_base_url"])
	if publicBaseURL == "" {
		publicBaseURL = draft.publicBaseURLForHost(host)
	}
	if port, ok := runtimeInt(update["idp_port"]); ok && strings.TrimSpace(asRuntimeString(update["public_base_url"])) == "" {
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
	derived := []struct {
		key   string
		value any
	}{
		{"public_base_url", normalizePublicBaseURL(publicBaseURL, adminScheme)},
		{"dsm_redirect_url", normalizeDSMDefaultPortForScheme(dsmRedirectURL, adminScheme, host, false)},
		{"helper_dsm_login_api", normalizeDSMDefaultPortForScheme(helperDSMLoginAPI, adminScheme, host, true)},
		{"dsm_cookie_secure", adminScheme == "https"},
	}
	for _, item := range derived {
		plan.set(draft, item.key, item.value)
		processed[item.key] = true
	}
	processed["access_host"] = true
	plan.cleanupIdentitySources = true
	return nil
}

func (s *Server) commitSettingsUpdate(ctx context.Context, plan *settingsUpdatePlan) error {
	if len(plan.values) == 0 {
		return nil
	}
	if err := s.persistSettingsUpdatePlan(ctx, plan); err != nil {
		return internalError(err)
	}
	for _, key := range sortedSettingKeys(plan.values) {
		s.applyRuntimeSetting(key, plan.values[key])
	}
	if plan.cleanupIdentitySources {
		if err := s.CleanupIdentitySourcePublicBaseURLs(ctx); err != nil {
			return internalError(err)
		}
	}
	return nil
}

func (s *Server) persistSettingsUpdatePlan(ctx context.Context, plan *settingsUpdatePlan) error {
	if s.database == nil {
		return s.saveSettingsWithQueries(ctx, s.store, plan.values)
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := s.saveSettingsWithQueries(ctx, db.New(tx), plan.values); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Server) saveSettingsWithQueries(ctx context.Context, queries *db.Queries, values map[string]any) error {
	if queries == nil {
		return sql.ErrConnDone
	}
	deploymentValues := map[string]any{}
	for key, value := range values {
		if isDeploymentSettingKey(key) {
			deploymentValues[key] = value
		}
	}
	if len(deploymentValues) > 0 {
		state := s.deploymentSettingsFromConfig()
		if existing, err := queries.GetDeploymentSettings(ctx); err == nil {
			state = s.deploymentSettingsFromRow(existing)
		} else if err != sql.ErrNoRows {
			return err
		}
		for _, key := range sortedSettingKeys(deploymentValues) {
			state = s.applyDeploymentSettingValue(state, key, deploymentValues[key])
		}
		if err := queries.UpsertDeploymentSettings(ctx, deploymentSettingsParams(state)); err != nil {
			return err
		}
	}
	for _, key := range sortedSettingKeys(values) {
		if isDeploymentSettingKey(key) {
			continue
		}
		raw, err := json.Marshal(values[key])
		if err != nil {
			return err
		}
		if err := queries.UpsertRuntimeSetting(ctx, db.UpsertRuntimeSettingParams{Key: key, ValueJson: string(raw)}); err != nil {
			return err
		}
	}
	return nil
}

func sortedSettingKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) validateBrowserDSMProtocol(update map[string]any, accessScheme string) error {
	mode := s.cfg.DSMLoginMode
	if value, ok := update["helper_dsm_login_mode"]; ok {
		mode = strings.ToLower(strings.TrimSpace(asRuntimeString(value)))
	}
	if mode != "browser" {
		return nil
	}

	host := s.cfg.AccessHost
	if value, ok := update["access_host"]; ok {
		if normalized := normalizeAccessHost(asRuntimeString(value)); normalized != "" {
			host = normalized
		}
	}

	dsmRedirectURL := strings.TrimSpace(s.cfg.DSMRedirectURL)
	if value, ok := update["dsm_redirect_url"]; ok {
		dsmRedirectURL = strings.TrimSpace(asRuntimeString(value))
	} else if _, changedHost := update["access_host"]; changedHost || hasRuntimeUpdate(update, "access_scheme") {
		dsmRedirectURL = normalizeDSMDefaultPortForScheme(dsmRedirectURL, accessScheme, host, false)
	}
	if dsmRedirectURL == "" {
		dsmRedirectURL = dsmRedirectURLForHostScheme(host, accessScheme)
	}
	if scheme := publicBaseURLScheme(dsmRedirectURL); scheme != "" && scheme != accessScheme {
		return badRequest("浏览器直登模式下，DSM 地址协议必须和 IDP 协议一致")
	}

	dsmLoginAPI := strings.TrimSpace(s.cfg.HelperDSMLoginAPI)
	if value, ok := update["helper_dsm_login_api"]; ok {
		dsmLoginAPI = strings.TrimSpace(asRuntimeString(value))
	} else if _, changedHost := update["access_host"]; changedHost || hasRuntimeUpdate(update, "access_scheme") {
		dsmLoginAPI = normalizeDSMDefaultPortForScheme(dsmLoginAPI, accessScheme, host, true)
	}
	if dsmLoginAPI == "" {
		dsmLoginAPI = dsmLoginAPIForHostScheme(host, accessScheme)
	}
	if scheme := publicBaseURLScheme(dsmLoginAPI); scheme != "" && scheme != accessScheme {
		return badRequest("浏览器直登模式下，DSM Auth API 协议必须和 IDP 协议一致")
	}
	return nil
}

func hasRuntimeUpdate(update map[string]any, key string) bool {
	_, ok := update[key]
	return ok
}

func (s *Server) persistRuntimeSetting(ctx context.Context, key string, value any) error {
	if err := s.saveSetting(ctx, key, value); err != nil {
		return internalError(err)
	}
	s.applyRuntimeSetting(key, value)
	return nil
}
