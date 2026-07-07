package backend

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

const (
	defaultWeComAuthorizeURL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	legacyWeComAuthorizeURL  = "https://open.weixin.qq.com/connect/oauth2/authorize"
)

type identitySourceConfig struct {
	PublicBaseURL         string `json:"public_base_url"`
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	AgentID               string `json:"agent_id"`
	AuthorizeURL          string `json:"authorize_url"`
	TokenURL              string `json:"token_url"`
	UserInfoURL           string `json:"user_info_url"`
	TenantTokenURL        string `json:"tenant_token_url"`
	ContactBaseURL        string `json:"contact_base_url"`
	DirectoryPageSize     int    `json:"directory_page_size"`
	SyncIntervalMinutes   int    `json:"sync_interval_minutes"`
	DisableMissingUsers   *bool  `json:"disable_missing_users,omitempty"`
	DeactivateMissingData *bool  `json:"deactivate_missing_data,omitempty"`
	InitialPassword       string `json:"initial_password,omitempty"`
}

func (s *Server) directoryProvider(slug string) (provider.Directory, bool) {
	if source, err := s.loadIdentitySource(context.Background(), slug); err == nil && source.Enabled == 1 && source.DirectorySyncEnabled == 1 {
		return s.directoryProviderForSource(source)
	}
	switch slug {
	case "feishu":
		if s.cfg.FeishuEnabled {
			return provider.NewFeishu(s.cfg), true
		}
		return nil, false
	default:
		return nil, false
	}
}

func (s *Server) directoryProviderForSource(source db.IdentitySource) (provider.Directory, bool) {
	switch source.ProviderType {
	case "feishu":
		return provider.NewFeishuWithSlug(s.feishuConfigForSource(source), source.Slug), true
	case "wecom":
		return provider.NewWeComWithSlug(s.weComConfigForSource(source), source.Slug), true
	default:
		return nil, false
	}
}

func (s *Server) oauthProviderForSource(source db.IdentitySource) (provider.OAuth, bool) {
	switch source.ProviderType {
	case "feishu":
		return provider.NewFeishuWithSlug(s.feishuConfigForSource(source), source.Slug), true
	case "wecom":
		return provider.NewWeComWithSlug(s.weComConfigForSource(source), source.Slug), true
	default:
		return nil, false
	}
}

func (s *Server) providerDisplayNameForSourceSlug(ctx context.Context, slug string) string {
	source, err := s.loadIdentitySource(ctx, slug)
	if err == nil {
		return providerTypeDisplayName(source.ProviderType)
	}
	return providerTypeDisplayName(slug)
}

func (s *Server) loadIdentitySource(ctx context.Context, slug string) (db.IdentitySource, error) {
	row := s.store.DBTX().QueryRowContext(ctx, `
SELECT slug, provider_type, display_name, enabled, login_enabled, directory_sync_enabled, config_json, created_at, updated_at
FROM identity_sources
WHERE slug = ?`, slug)
	var source db.IdentitySource
	err := row.Scan(&source.Slug, &source.ProviderType, &source.DisplayName, &source.Enabled, &source.LoginEnabled, &source.DirectorySyncEnabled, &source.ConfigJSON, &source.CreatedAt, &source.UpdatedAt)
	return source, err
}

func (s *Server) feishuConfigForSource(source db.IdentitySource) config.BackendConfig {
	cfg := s.cfg
	sourceConfig := decodeSourceConfigForType("feishu", source.ConfigJSON)
	cfg.FeishuEnabled = source.Enabled == 1
	cfg.PublicBaseURL = strings.TrimRight(s.cfg.PublicBaseURL, "/")
	cfg.FeishuClientID = sourceConfig.ClientID
	cfg.FeishuClientSecret = sourceConfig.ClientSecret
	cfg.FeishuAuthorizeURL = sourceConfig.AuthorizeURL
	cfg.FeishuTokenURL = sourceConfig.TokenURL
	cfg.FeishuUserInfoURL = sourceConfig.UserInfoURL
	cfg.FeishuTenantTokenURL = sourceConfig.TenantTokenURL
	cfg.FeishuContactBaseURL = sourceConfig.ContactBaseURL
	cfg.FeishuDirectoryPageSize = sourceConfig.DirectoryPageSize
	return cfg
}

func (s *Server) weComConfigForSource(source db.IdentitySource) provider.WeComConfig {
	sourceConfig := decodeSourceConfigForType("wecom", source.ConfigJSON)
	return provider.WeComConfig{
		CorpID:            sourceConfig.ClientID,
		CorpSecret:        sourceConfig.ClientSecret,
		AgentID:           sourceConfig.AgentID,
		AuthorizeURL:      sourceConfig.AuthorizeURL,
		TokenURL:          sourceConfig.TokenURL,
		UserInfoURL:       sourceConfig.UserInfoURL,
		ContactBaseURL:    sourceConfig.ContactBaseURL,
		DirectoryPageSize: sourceConfig.DirectoryPageSize,
	}
}

func feishuAuthorizePreviewURL(clientID, redirectURI string) string {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("response_type", "code")
	return "https://accounts.feishu.cn/open-apis/authen/v1/authorize?" + values.Encode()
}

func weComAuthorizePreviewURL(corpID, agentID, redirectURI string) string {
	values := url.Values{}
	values.Set("appid", corpID)
	values.Set("redirect_uri", redirectURI)
	if strings.TrimSpace(agentID) != "" {
		values.Set("agentid", agentID)
	}
	return defaultWeComAuthorizeURL + "?" + values.Encode()
}

func sourceResponse(source db.IdentitySource, config identitySourceConfig, publicBaseURL string) gin.H {
	publicBaseURL = strings.TrimRight(publicBaseURL, "/")
	config.PublicBaseURL = ""
	loginPath := "/idp/" + source.Slug + "/launch"
	callbackPath := "/idp/" + source.Slug + "/callback"
	callbackURL := strings.TrimRight(publicBaseURL, "/") + callbackPath
	response := gin.H{
		"slug":                   source.Slug,
		"provider_type":          source.ProviderType,
		"display_name":           source.DisplayName,
		"enabled":                source.Enabled == 1,
		"login_enabled":          source.LoginEnabled == 1,
		"directory_sync_enabled": source.DirectorySyncEnabled == 1,
		"credentials_configured": credentialsConfigured(source.ProviderType, config),
		"config":                 publicSourceConfig(config),
		"created_at":             source.CreatedAt,
		"updated_at":             source.UpdatedAt,
		"login_url":              publicBaseURL + loginPath,
		"callback_url":           callbackURL,
	}
	switch source.ProviderType {
	case "feishu":
		response["feishu_authorize_url"] = feishuAuthorizePreviewURL(config.ClientID, callbackURL)
	case "wecom":
		response["wecom_authorize_url"] = weComAuthorizePreviewURL(config.ClientID, config.AgentID, callbackURL)
	}
	return response
}

func (s *Server) CleanupIdentitySourcePublicBaseURLs(ctx context.Context) error {
	rows, err := s.store.DBTX().QueryContext(ctx, `SELECT slug, config_json FROM identity_sources`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type update struct {
		slug string
		raw  string
	}
	updates := []update{}
	for rows.Next() {
		var slug, raw string
		if err := rows.Scan(&slug, &raw); err != nil {
			return err
		}
		var config map[string]any
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			continue
		}
		if _, ok := config["public_base_url"]; !ok {
			continue
		}
		delete(config, "public_base_url")
		encoded, err := json.Marshal(config)
		if err != nil {
			return err
		}
		updates = append(updates, update{slug: slug, raw: string(encoded)})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range updates {
		if _, err := s.store.DBTX().ExecContext(ctx, `UPDATE identity_sources SET config_json = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?`, item.raw, item.slug); err != nil {
			return err
		}
	}
	return nil
}

func withSourceDefaults(config identitySourceConfig) identitySourceConfig {
	return withSourceDefaultsForType("feishu", config)
}

func withSourceDefaultsForType(providerType string, config identitySourceConfig) identitySourceConfig {
	config = trimSourceConfig(config)
	config.PublicBaseURL = ""
	switch providerType {
	case "wecom":
		if config.AuthorizeURL == "" || config.AuthorizeURL == legacyWeComAuthorizeURL {
			config.AuthorizeURL = defaultWeComAuthorizeURL
		}
		if config.TokenURL == "" {
			config.TokenURL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
		}
		if config.UserInfoURL == "" {
			config.UserInfoURL = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
		}
		if config.ContactBaseURL == "" {
			config.ContactBaseURL = "https://qyapi.weixin.qq.com/cgi-bin"
		}
	default:
		if config.AuthorizeURL == "" || config.AuthorizeURL == "https://open.feishu.cn/open-apis/authen/v1/index" {
			config.AuthorizeURL = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
		}
		if config.TokenURL == "" {
			config.TokenURL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
		}
		if config.UserInfoURL == "" {
			config.UserInfoURL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
		}
		if config.TenantTokenURL == "" {
			config.TenantTokenURL = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
		}
		if config.ContactBaseURL == "" {
			config.ContactBaseURL = "https://open.feishu.cn/open-apis/contact/v3"
		}
	}
	if config.DirectoryPageSize <= 0 {
		config.DirectoryPageSize = 50
	}
	if strings.TrimSpace(config.InitialPassword) == "" {
		config.InitialPassword = defaultInitialPassword
	}
	if config.DisableMissingUsers == nil {
		config.DisableMissingUsers = boolPointer(false)
	}
	if config.DeactivateMissingData == nil {
		config.DeactivateMissingData = boolPointer(true)
	}
	return config
}

func decodeSourceConfig(raw string) identitySourceConfig {
	return decodeSourceConfigForType("feishu", raw)
}

func decodeSourceConfigForType(providerType, raw string) identitySourceConfig {
	var config identitySourceConfig
	_ = json.Unmarshal([]byte(raw), &config)
	return withSourceDefaultsForType(providerType, config)
}

func publicSourceConfig(config identitySourceConfig) gin.H {
	return gin.H{
		"client_id":                config.ClientID,
		"agent_id":                 config.AgentID,
		"client_secret_configured": config.ClientSecret != "",
		"authorize_url":            config.AuthorizeURL,
		"token_url":                config.TokenURL,
		"user_info_url":            config.UserInfoURL,
		"tenant_token_url":         config.TenantTokenURL,
		"contact_base_url":         config.ContactBaseURL,
		"directory_page_size":      config.DirectoryPageSize,
		"sync_interval_minutes":    config.SyncIntervalMinutes,
		"disable_missing_users":    boolValue(config.DisableMissingUsers, false),
		"deactivate_missing_data":  boolValue(config.DeactivateMissingData, true),
		"initial_password":         config.InitialPassword,
	}
}

func mergeSourceConfig(existing, update identitySourceConfig) identitySourceConfig {
	return mergeSourceConfigForType("feishu", existing, update)
}

func mergeSourceConfigForType(providerType string, existing, update identitySourceConfig) identitySourceConfig {
	existing.PublicBaseURL = ""
	if value := strings.TrimSpace(update.ClientID); value != "" {
		existing.ClientID = value
	}
	if value := strings.TrimSpace(update.AgentID); value != "" {
		existing.AgentID = value
	}
	if value := strings.TrimSpace(update.ClientSecret); value != "" {
		existing.ClientSecret = value
	}
	if value := strings.TrimSpace(update.AuthorizeURL); value != "" {
		existing.AuthorizeURL = value
	}
	if value := strings.TrimSpace(update.TokenURL); value != "" {
		existing.TokenURL = value
	}
	if value := strings.TrimSpace(update.UserInfoURL); value != "" {
		existing.UserInfoURL = value
	}
	if value := strings.TrimSpace(update.TenantTokenURL); value != "" {
		existing.TenantTokenURL = value
	}
	if value := strings.TrimSpace(update.ContactBaseURL); value != "" {
		existing.ContactBaseURL = value
	}
	if update.DirectoryPageSize > 0 {
		existing.DirectoryPageSize = update.DirectoryPageSize
	}
	if update.SyncIntervalMinutes >= 0 {
		existing.SyncIntervalMinutes = update.SyncIntervalMinutes
	}
	if strings.TrimSpace(update.InitialPassword) != "" {
		existing.InitialPassword = strings.TrimSpace(update.InitialPassword)
	}
	if update.DisableMissingUsers != nil {
		existing.DisableMissingUsers = update.DisableMissingUsers
	}
	if update.DeactivateMissingData != nil {
		existing.DeactivateMissingData = update.DeactivateMissingData
	}
	return withSourceDefaultsForType(providerType, existing)
}

func trimSourceConfig(config identitySourceConfig) identitySourceConfig {
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.ClientSecret = strings.TrimSpace(config.ClientSecret)
	config.AgentID = strings.TrimSpace(config.AgentID)
	config.AuthorizeURL = strings.TrimSpace(config.AuthorizeURL)
	config.TokenURL = strings.TrimSpace(config.TokenURL)
	config.UserInfoURL = strings.TrimSpace(config.UserInfoURL)
	config.TenantTokenURL = strings.TrimSpace(config.TenantTokenURL)
	config.ContactBaseURL = strings.TrimSpace(config.ContactBaseURL)
	config.InitialPassword = strings.TrimSpace(config.InitialPassword)
	return config
}

func credentialsConfigured(providerType string, config identitySourceConfig) bool {
	if strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" {
		return false
	}
	if providerType == "wecom" {
		return strings.TrimSpace(config.AgentID) != ""
	}
	return true
}

func boolPointer(value bool) *bool {
	return &value
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func boolPtrInt(value *bool, fallback bool) int64 {
	if value == nil {
		if fallback {
			return 1
		}
		return 0
	}
	if *value {
		return 1
	}
	return 0
}
