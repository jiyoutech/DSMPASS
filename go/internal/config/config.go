package config

import (
	"os"
	"strings"
)

const defaultAccessHost = "127.0.0.1"

type BackendConfig struct {
	Listen                     string
	IDPListen                  string
	DatabaseURL                string
	DataDir                    string
	TLSEnabled                 bool
	TLSCertFile                string
	TLSKeyFile                 string
	AdminAuthEnabled           bool
	AdminUsername              string
	AdminPassword              string
	AdminJWTSecret             string
	AdminSetupRequired         bool
	LoginDiagnosticsEnabled    bool
	AccessHost                 string
	AccessScheme               string
	PublicBaseURL              string
	FrontendDistDir            string
	DSMRedirectURL             string
	DSMCookieName              string
	DSMCookieSecure            bool
	DSMCookieHTTPOnly          bool
	DSMCookieSameSite          string
	DSMLoginMode               string
	DSMBrowserLoginTTLSeconds  int
	HelperDSMLoginAPI          string
	RelayMode                  string
	RelayHelperSocket          string
	RelayHelperHMACSecret      string
	RelayHelperTimeoutSeconds  int
	FeishuEnabled              bool
	FeishuClientID             string
	FeishuClientSecret         string
	FeishuAuthorizeURL         string
	FeishuTokenURL             string
	FeishuUserInfoURL          string
	FeishuTenantTokenURL       string
	FeishuContactBaseURL       string
	FeishuDirectoryPageSize    int
	UsernameReadableDelimiter  string
	UsernameReadableSuffixSize int
}

type HelperConfig struct {
	DatabaseURL               string
	DataDir                   string
	LoginDiagnosticsEnabled   bool
	SocketPath                string
	HMACSecret                string
	TimestampSkewSeconds      int64
	DSMLoginAPI               string
	DSMSession                string
	DSMFormat                 string
	DSMOTPCode                string
	DSMEnableDeviceToken      string
	DSMDeviceName             string
	DSMDeviceID               string
	DSMTLSSkipVerify          bool
	DSMTimeoutSeconds         int
	DSMBrowserLoginTTLSeconds int
	ShadowPath                string
	ShadowLockPath            string
	LockDir                   string
	JournalDir                string
	TempPasswordLength        int
	InitialPasswordLength     int
	SynoUserPath              string
	SynoGroupPath             string
}

func LoadBackend() BackendConfig {
	accessHost := env("DSMPASS_ACCESS_HOST", defaultAccessHost)
	dataDir := env("DSMPASS_DATA_DIR", "/volume1/docker/dsmpass/data")
	listen := env("DSMPASS_GO_LISTEN", "0.0.0.0:25000")
	idpListen := env("DSMPASS_IDP_LISTEN", "")
	publicPort := listenPort(listen)
	if publicPort == "" {
		publicPort = "25000"
	}
	tlsEnabled := envBool("DSMPASS_TLS_ENABLED", true)
	scheme := "https"
	if !tlsEnabled {
		scheme = "http"
	}
	return BackendConfig{
		Listen:                     listen,
		IDPListen:                  idpListen,
		DatabaseURL:                env("DSMPASS_DATABASE_URL", "sqlite:///volume1/docker/dsmpass/dsmpass.db"),
		DataDir:                    dataDir,
		TLSEnabled:                 tlsEnabled,
		TLSCertFile:                env("DSMPASS_TLS_CERT_FILE", dataDir+"/tls/server.crt"),
		TLSKeyFile:                 env("DSMPASS_TLS_KEY_FILE", dataDir+"/tls/server.key"),
		AdminAuthEnabled:           envBool("DSMPASS_ADMIN_AUTH_ENABLED", true),
		AdminUsername:              env("DSMPASS_ADMIN_USERNAME", "admin"),
		AdminPassword:              env("DSMPASS_ADMIN_PASSWORD", ""),
		AdminJWTSecret:             env("DSMPASS_ADMIN_JWT_SECRET", ""),
		LoginDiagnosticsEnabled:    envBool("DSMPASS_LOGIN_DIAGNOSTICS", false),
		AccessHost:                 accessHost,
		AccessScheme:               scheme,
		PublicBaseURL:              env("DSMPASS_PUBLIC_BASE_URL", scheme+"://"+accessHost+":"+publicPort),
		FrontendDistDir:            env("DSMPASS_FRONTEND_DIST_DIR", "/volume1/docker/dsmpass/frontend/dist"),
		DSMRedirectURL:             env("DSMPASS_DSM_REDIRECT_URL", defaultDSMRedirectURL(accessHost, scheme)),
		DSMCookieName:              "id",
		DSMCookieSecure:            false,
		DSMCookieHTTPOnly:          true,
		DSMCookieSameSite:          "Lax",
		DSMLoginMode:               env("DSMPASS_DSM_LOGIN_MODE", "browser"),
		DSMBrowserLoginTTLSeconds:  envInt("DSMPASS_DSM_BROWSER_LOGIN_TTL_SECONDS", 30),
		HelperDSMLoginAPI:          env("DSMPASS_DSM_LOGIN_API", defaultDSMLoginAPI(accessHost, scheme)),
		RelayMode:                  "socket",
		RelayHelperSocket:          env("DSMPASS_HELPER_SOCKET", "/run/dsmpass/helper.sock"),
		RelayHelperHMACSecret:      env("DSMPASS_HELPER_HMAC_SECRET", ""),
		RelayHelperTimeoutSeconds:  5,
		FeishuEnabled:              false,
		FeishuClientID:             "",
		FeishuClientSecret:         "",
		FeishuAuthorizeURL:         "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		FeishuTokenURL:             "https://open.feishu.cn/open-apis/authen/v2/oauth/token",
		FeishuUserInfoURL:          "https://open.feishu.cn/open-apis/authen/v1/user_info",
		FeishuTenantTokenURL:       "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
		FeishuContactBaseURL:       "https://open.feishu.cn/open-apis/contact/v3",
		FeishuDirectoryPageSize:    50,
		UsernameReadableDelimiter:  "_",
		UsernameReadableSuffixSize: 4,
	}
}

func LoadHelper() HelperConfig {
	accessHost := env("DSMPASS_ACCESS_HOST", defaultAccessHost)
	dataDir := env("DSMPASS_DATA_DIR", "/volume1/docker/dsmpass/data")
	return HelperConfig{
		DatabaseURL:               env("DSMPASS_DATABASE_URL", "sqlite:///volume1/docker/dsmpass/dsmpass.db"),
		DataDir:                   dataDir,
		LoginDiagnosticsEnabled:   envBool("DSMPASS_LOGIN_DIAGNOSTICS", false),
		SocketPath:                env("DSMPASS_HELPER_SOCKET", "/run/dsmpass/helper.sock"),
		HMACSecret:                env("DSMPASS_HELPER_HMAC_SECRET", ""),
		TimestampSkewSeconds:      60,
		DSMLoginAPI:               env("DSMPASS_DSM_LOGIN_API", defaultDSMLoginAPI(accessHost, "https")),
		DSMSession:                env("DSMPASS_DSM_SESSION", "webui"),
		DSMFormat:                 env("DSMPASS_DSM_FORMAT", ""),
		DSMOTPCode:                env("DSMPASS_DSM_OTP_CODE", ""),
		DSMEnableDeviceToken:      env("DSMPASS_DSM_ENABLE_DEVICE_TOKEN", ""),
		DSMDeviceName:             env("DSMPASS_DSM_DEVICE_NAME", ""),
		DSMDeviceID:               env("DSMPASS_DSM_DEVICE_ID", ""),
		DSMTLSSkipVerify:          envBool("DSMPASS_DSM_TLS_SKIP_VERIFY", true),
		DSMTimeoutSeconds:         10,
		DSMBrowserLoginTTLSeconds: envInt("DSMPASS_DSM_BROWSER_LOGIN_TTL_SECONDS", 30),
		ShadowPath:                "/etc/shadow",
		ShadowLockPath:            "/run/dsmpass/locks/shadow.lock",
		LockDir:                   "/run/dsmpass/locks",
		JournalDir:                "/var/lib/dsmpass/journal",
		TempPasswordLength:        64,
		InitialPasswordLength:     32,
		SynoUserPath:              env("DSMPASS_SYNOUSER_PATH", "/usr/syno/sbin/synouser"),
		SynoGroupPath:             env("DSMPASS_SYNOGROUP_PATH", "/usr/syno/sbin/synogroup"),
	}
}

func listenPort(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if strings.HasPrefix(address, "[") {
		if end := strings.LastIndex(address, "]:"); end >= 0 {
			return address[end+2:]
		}
		return ""
	}
	if colon := strings.LastIndex(address, ":"); colon >= 0 {
		return address[colon+1:]
	}
	return ""
}

func defaultDSMRedirectURL(accessHost, scheme string) string {
	if scheme == "http" {
		return "http://" + accessHost + ":5000/"
	}
	return "https://" + accessHost + ":5001/"
}

func defaultDSMLoginAPI(accessHost, scheme string) string {
	return strings.TrimRight(defaultDSMRedirectURL(accessHost, scheme), "/") + "/webapi/entry.cgi"
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	var parsed int
	for _, r := range value {
		if r < '0' || r > '9' {
			return fallback
		}
		parsed = parsed*10 + int(r-'0')
	}
	if parsed <= 0 {
		return fallback
	}
	return parsed
}
