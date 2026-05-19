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

type identitySourceConfig struct {
	PublicBaseURL         string `json:"public_base_url"`
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	AuthorizeURL          string `json:"authorize_url"`
	TokenURL              string `json:"token_url"`
	UserInfoURL           string `json:"user_info_url"`
	TenantTokenURL        string `json:"tenant_token_url"`
	ContactBaseURL        string `json:"contact_base_url"`
	DirectoryPageSize     int    `json:"directory_page_size"`
	SyncIntervalMinutes   int    `json:"sync_interval_minutes"`
	DisableMissingUsers   bool   `json:"disable_missing_users"`
	DeactivateMissingData bool   `json:"deactivate_missing_data"`
	InitialPassword       string `json:"initial_password,omitempty"`
}

func (s *Server) directoryProvider(slug string) (provider.Directory, bool) {
	if source, err := s.loadIdentitySource(context.Background(), slug); err == nil && source.Enabled == 1 && source.DirectorySyncEnabled == 1 {
		if source.ProviderType == "feishu" {
			return provider.NewFeishuWithSlug(s.configForSource(source), source.Slug), true
		}
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

func (s *Server) loadIdentitySource(ctx context.Context, slug string) (db.IdentitySource, error) {
	row := s.store.DBTX().QueryRowContext(ctx, `
SELECT slug, provider_type, display_name, enabled, login_enabled, directory_sync_enabled, config_json, created_at, updated_at
FROM identity_sources
WHERE slug = ?`, slug)
	var source db.IdentitySource
	err := row.Scan(&source.Slug, &source.ProviderType, &source.DisplayName, &source.Enabled, &source.LoginEnabled, &source.DirectorySyncEnabled, &source.ConfigJSON, &source.CreatedAt, &source.UpdatedAt)
	return source, err
}

func (s *Server) configForSource(source db.IdentitySource) config.BackendConfig {
	cfg := s.cfg
	sourceConfig := withSourceDefaults(decodeSourceConfig(source.ConfigJSON))
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

func feishuAuthorizePreviewURL(clientID, redirectURI string) string {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("response_type", "code")
	return "https://accounts.feishu.cn/open-apis/authen/v1/authorize?" + values.Encode()
}

func sourceResponse(source db.IdentitySource, config identitySourceConfig, publicBaseURL string) gin.H {
	publicBaseURL = strings.TrimRight(publicBaseURL, "/")
	config.PublicBaseURL = ""
	loginPath := "/idp/" + source.Slug + "/launch"
	callbackPath := "/idp/" + source.Slug + "/callback"
	callbackURL := strings.TrimRight(publicBaseURL, "/") + callbackPath
	return gin.H{
		"slug":                   source.Slug,
		"provider_type":          source.ProviderType,
		"display_name":           source.DisplayName,
		"enabled":                source.Enabled == 1,
		"login_enabled":          source.LoginEnabled == 1,
		"directory_sync_enabled": source.DirectorySyncEnabled == 1,
		"credentials_configured": config.ClientID != "" && config.ClientSecret != "",
		"config":                 publicSourceConfig(config),
		"created_at":             source.CreatedAt,
		"updated_at":             source.UpdatedAt,
		"login_url":              publicBaseURL + loginPath,
		"callback_url":           callbackURL,
		"feishu_authorize_url":   feishuAuthorizePreviewURL(config.ClientID, callbackURL),
	}
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
	config.PublicBaseURL = ""
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
	if config.DirectoryPageSize <= 0 {
		config.DirectoryPageSize = 50
	}
	if strings.TrimSpace(config.InitialPassword) == "" {
		config.InitialPassword = defaultInitialPassword
	}
	return config
}

func decodeSourceConfig(raw string) identitySourceConfig {
	var config identitySourceConfig
	_ = json.Unmarshal([]byte(raw), &config)
	return withSourceDefaults(config)
}

func publicSourceConfig(config identitySourceConfig) gin.H {
	return gin.H{
		"client_id":                config.ClientID,
		"client_secret_configured": config.ClientSecret != "",
		"authorize_url":            config.AuthorizeURL,
		"token_url":                config.TokenURL,
		"user_info_url":            config.UserInfoURL,
		"tenant_token_url":         config.TenantTokenURL,
		"contact_base_url":         config.ContactBaseURL,
		"directory_page_size":      config.DirectoryPageSize,
		"sync_interval_minutes":    config.SyncIntervalMinutes,
		"disable_missing_users":    config.DisableMissingUsers,
		"deactivate_missing_data":  config.DeactivateMissingData,
		"initial_password":         config.InitialPassword,
	}
}

func mergeSourceConfig(existing, update identitySourceConfig) identitySourceConfig {
	existing.PublicBaseURL = ""
	if update.ClientID != "" {
		existing.ClientID = update.ClientID
	}
	if update.ClientSecret != "" {
		existing.ClientSecret = update.ClientSecret
	}
	if update.AuthorizeURL != "" {
		existing.AuthorizeURL = update.AuthorizeURL
	}
	if update.TokenURL != "" {
		existing.TokenURL = update.TokenURL
	}
	if update.UserInfoURL != "" {
		existing.UserInfoURL = update.UserInfoURL
	}
	if update.TenantTokenURL != "" {
		existing.TenantTokenURL = update.TenantTokenURL
	}
	if update.ContactBaseURL != "" {
		existing.ContactBaseURL = update.ContactBaseURL
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
	existing.DisableMissingUsers = update.DisableMissingUsers
	existing.DeactivateMissingData = update.DeactivateMissingData
	return withSourceDefaults(existing)
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
