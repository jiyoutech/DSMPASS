package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

type deploymentSettingsState struct {
	Mode              string
	AccessHost        string
	AccessScheme      string
	IDPPort           int
	PublicBaseURL     string
	DSMRedirectURL    string
	HelperDSMLoginAPI string
}

func isDeploymentSettingKey(key string) bool {
	switch key {
	case "deployment_mode", "access_host", "access_scheme", "idp_port", "public_base_url", "dsm_redirect_url", "helper_dsm_login_api":
		return true
	default:
		return false
	}
}

func validDeploymentMode(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "direct", "reverse_proxy", "advanced":
		return true
	default:
		return false
	}
}

func normalizeDeploymentMode(value string) string {
	mode := strings.ToLower(strings.TrimSpace(value))
	if validDeploymentMode(mode) {
		return mode
	}
	return "direct"
}

func (s *Server) loadOrCreateDeploymentSettings(ctx context.Context, rows []db.RuntimeSetting) (deploymentSettingsState, error) {
	if existing, err := s.store.GetDeploymentSettings(ctx); err == nil {
		return s.deploymentSettingsFromRow(existing), nil
	} else if err != sql.ErrNoRows {
		return deploymentSettingsState{}, err
	}
	state := s.deploymentSettingsFromConfig()
	state = s.deploymentSettingsFromRuntimeRows(state, rows)
	if err := s.store.UpsertDeploymentSettings(ctx, deploymentSettingsParams(state)); err != nil {
		return deploymentSettingsState{}, err
	}
	return state, nil
}

func (s *Server) deploymentSettingsFromConfig() deploymentSettingsState {
	scheme := s.configuredAccessScheme()
	host := normalizeAccessHost(s.cfg.AccessHost)
	idpPort := firstPositiveInt(
		parsePortInt(listenAddressPort(s.cfg.IDPListen)),
		defaultIDPPortForAdmin(parsePortInt(listenAddressPort(s.cfg.Listen))),
	)
	state := deploymentSettingsState{
		Mode:              normalizeDeploymentMode(s.cfg.DeploymentMode),
		AccessHost:        host,
		AccessScheme:      scheme,
		IDPPort:           idpPort,
		PublicBaseURL:     normalizePublicBaseURL(s.cfg.PublicBaseURL, scheme),
		DSMRedirectURL:    normalizeDSMBaseURL(s.cfg.DSMRedirectURL),
		HelperDSMLoginAPI: normalizeDSMAPIURL(s.cfg.HelperDSMLoginAPI),
	}
	return s.normalizeDeploymentSettings(state)
}

func (s *Server) deploymentSettingsFromRow(row db.DeploymentSetting) deploymentSettingsState {
	state := deploymentSettingsState{
		Mode:              row.Mode,
		AccessHost:        row.AccessHost,
		AccessScheme:      row.AccessScheme,
		IDPPort:           int(row.IDPPort),
		PublicBaseURL:     row.PublicBaseURL,
		DSMRedirectURL:    row.DSMRedirectURL,
		HelperDSMLoginAPI: row.HelperDSMLoginAPI,
	}
	return s.normalizeDeploymentSettings(state)
}

func (s *Server) deploymentSettingsFromRuntimeRows(state deploymentSettingsState, rows []db.RuntimeSetting) deploymentSettingsState {
	values := map[string]any{}
	for _, row := range rows {
		if !isDeploymentSettingKey(row.Key) {
			continue
		}
		var value any
		if err := json.Unmarshal([]byte(row.ValueJson), &value); err != nil {
			continue
		}
		values[row.Key] = value
	}
	if value, ok := values["deployment_mode"]; ok {
		state.Mode = normalizeDeploymentMode(asRuntimeString(value))
	}
	if value, ok := values["access_scheme"]; ok {
		state.AccessScheme = normalizedAccessScheme(asRuntimeString(value), s.cfg.TLSEnabled)
	}
	if value, ok := values["access_host"]; ok {
		if host := normalizeAccessHost(asRuntimeString(value)); host != "" {
			state.AccessHost = host
		}
	}
	if value, ok := values["idp_port"]; ok {
		if port, valid := runtimeInt(value); valid {
			state.IDPPort = port
		}
	}
	if value, ok := values["public_base_url"]; ok {
		if publicBaseURL := normalizePublicBaseURL(asRuntimeString(value), state.AccessScheme); publicBaseURL != "" {
			state.PublicBaseURL = publicBaseURL
			if _, hasExplicitIDPPort := values["idp_port"]; !hasExplicitIDPPort {
				if port := parsePortInt(publicBaseURLPort(state.PublicBaseURL)); port >= minUserPort && port <= 65535 {
					state.IDPPort = port
				}
			}
		}
	}
	if value, ok := values["dsm_redirect_url"]; ok {
		state.DSMRedirectURL = normalizeDSMBaseURL(asRuntimeString(value))
	}
	if value, ok := values["helper_dsm_login_api"]; ok {
		state.HelperDSMLoginAPI = normalizeDSMAPIURL(asRuntimeString(value))
	}
	return s.normalizeDeploymentSettings(state)
}

func (s *Server) normalizeDeploymentSettings(state deploymentSettingsState) deploymentSettingsState {
	state.Mode = normalizeDeploymentMode(state.Mode)
	adminPort := parsePortInt(listenAddressPort(s.cfg.Listen))
	if state.AccessScheme != "http" && state.AccessScheme != "https" {
		state.AccessScheme = publicBaseURLScheme(state.PublicBaseURL)
	}
	state.AccessScheme = normalizedAccessScheme(state.AccessScheme, s.cfg.TLSEnabled)
	state.AccessHost = normalizeAccessHost(state.AccessHost)
	if state.IDPPort < minUserPort || state.IDPPort > 65535 {
		state.IDPPort = defaultIDPPortForAdmin(adminPort)
	}
	if adminPort > 0 && state.IDPPort == adminPort {
		state.IDPPort = defaultIDPPortForAdmin(adminPort)
	}
	state.PublicBaseURL = normalizePublicBaseURL(state.PublicBaseURL, state.AccessScheme)
	if state.PublicBaseURL == "" && state.AccessHost != "" {
		state.PublicBaseURL = state.AccessScheme + "://" + state.AccessHost + ":" + strconv.Itoa(state.IDPPort)
	}
	if adminPort > 0 && state.Mode == "direct" && publicBaseURLPort(state.PublicBaseURL) == strconv.Itoa(adminPort) && state.IDPPort != adminPort {
		state.PublicBaseURL = replaceBaseURLPort(state.PublicBaseURL, state.IDPPort)
	}
	state.DSMRedirectURL = normalizeDSMBaseURL(state.DSMRedirectURL)
	if state.DSMRedirectURL == "" && state.AccessHost != "" {
		state.DSMRedirectURL = dsmRedirectURLForHostScheme(state.AccessHost, state.AccessScheme)
	}
	state.HelperDSMLoginAPI = normalizeDSMAPIURL(state.HelperDSMLoginAPI)
	if state.HelperDSMLoginAPI == "" && state.AccessHost != "" {
		state.HelperDSMLoginAPI = dsmLoginAPIForHostScheme(state.AccessHost, state.AccessScheme)
	}
	return state
}

func (s *Server) applyDeploymentSettings(state deploymentSettingsState) {
	s.cfg.DeploymentMode = state.Mode
	s.cfg.AccessScheme = state.AccessScheme
	s.cfg.AccessHost = state.AccessHost
	s.cfg.IDPListen = replaceListenPort(s.cfg.IDPListen, s.cfg.Listen, state.IDPPort)
	s.cfg.PublicBaseURL = state.PublicBaseURL
	s.cfg.DSMRedirectURL = state.DSMRedirectURL
	s.cfg.HelperDSMLoginAPI = state.HelperDSMLoginAPI
}

func (s *Server) saveDeploymentSetting(ctx context.Context, key string, value any) error {
	state := s.deploymentSettingsFromConfig()
	if existing, err := s.store.GetDeploymentSettings(ctx); err == nil {
		state = s.deploymentSettingsFromRow(existing)
	} else if err != sql.ErrNoRows {
		return err
	}
	state = s.applyDeploymentSettingValue(state, key, value)
	return s.store.UpsertDeploymentSettings(ctx, deploymentSettingsParams(state))
}

func (s *Server) applyDeploymentSettingValue(state deploymentSettingsState, key string, value any) deploymentSettingsState {
	switch key {
	case "deployment_mode":
		state.Mode = normalizeDeploymentMode(asRuntimeString(value))
	case "access_host":
		if host := normalizeAccessHost(asRuntimeString(value)); host != "" {
			state.AccessHost = host
		}
	case "access_scheme":
		state.AccessScheme = normalizedAccessScheme(asRuntimeString(value), s.cfg.TLSEnabled)
	case "idp_port":
		if port, ok := runtimeInt(value); ok {
			state.IDPPort = port
		}
	case "public_base_url":
		if publicBaseURL := normalizePublicBaseURL(asRuntimeString(value), state.AccessScheme); publicBaseURL != "" {
			state.PublicBaseURL = publicBaseURL
		}
	case "dsm_redirect_url":
		state.DSMRedirectURL = normalizeDSMBaseURL(asRuntimeString(value))
	case "helper_dsm_login_api":
		state.HelperDSMLoginAPI = normalizeDSMAPIURL(asRuntimeString(value))
	}
	return s.normalizeDeploymentSettings(state)
}

func deploymentSettingsParams(state deploymentSettingsState) db.UpsertDeploymentSettingsParams {
	return db.UpsertDeploymentSettingsParams{
		Mode:              state.Mode,
		AccessHost:        state.AccessHost,
		AccessScheme:      state.AccessScheme,
		IDPPort:           int64(state.IDPPort),
		PublicBaseURL:     state.PublicBaseURL,
		DSMRedirectURL:    state.DSMRedirectURL,
		HelperDSMLoginAPI: state.HelperDSMLoginAPI,
	}
}
