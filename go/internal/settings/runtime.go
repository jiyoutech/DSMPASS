package settings

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

const helperHMACSecretSettingKey = "relay_helper_hmac_secret"

func EnsureHelperHMACSecret(ctx context.Context, q *db.Queries, current string) (string, bool, error) {
	current = strings.TrimSpace(current)
	if current != "" {
		return current, false, nil
	}
	if q == nil {
		return "", false, nil
	}
	if existing, err := runtimeStringSetting(ctx, q, helperHMACSecretSettingKey); err == nil && strings.TrimSpace(existing) != "" {
		return existing, false, nil
	} else if err != nil && !errorsIsNoRows(err) {
		return "", false, err
	}
	generated, err := randomHex(32)
	if err != nil {
		return "", false, err
	}
	raw, err := json.Marshal(generated)
	if err != nil {
		return "", false, err
	}
	_, err = q.DBTX().ExecContext(ctx, `
	INSERT INTO runtime_settings (key, value_json, updated_at)
	VALUES (?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(key) DO UPDATE SET
		value_json = CASE
			WHEN runtime_settings.value_json = '""' THEN excluded.value_json
			ELSE runtime_settings.value_json
		END,
		updated_at = CASE
			WHEN runtime_settings.value_json = '""' THEN excluded.updated_at
			ELSE runtime_settings.updated_at
		END
	`, helperHMACSecretSettingKey, string(raw))
	if err != nil {
		return "", false, err
	}
	actual, err := runtimeStringSetting(ctx, q, helperHMACSecretSettingKey)
	if err != nil {
		return "", false, err
	}
	return actual, actual == generated, nil
}

func ApplyHelperRuntime(ctx context.Context, cfg config.HelperConfig, q *db.Queries) config.HelperConfig {
	if q == nil {
		return cfg
	}
	rows, err := q.ListRuntimeSettings(ctx)
	if err != nil {
		return cfg
	}
	accessScheme := "https"
	for _, row := range rows {
		if row.Key != "access_scheme" {
			continue
		}
		var value any
		if json.Unmarshal([]byte(row.ValueJson), &value) == nil {
			accessScheme = normalizedAccessScheme(asString(value, accessScheme))
		}
	}
	for _, row := range rows {
		var value any
		if json.Unmarshal([]byte(row.ValueJson), &value) != nil {
			continue
		}
		switch row.Key {
		case "access_scheme":
			continue
		case "access_host":
			host := normalizeAccessHost(asString(value, ""))
			if host != "" {
				if accessScheme == "http" {
					cfg.DSMLoginAPI = "http://" + host + ":5000/webapi/entry.cgi"
				} else {
					cfg.DSMLoginAPI = "https://" + host + ":5001/webapi/entry.cgi"
				}
			}
		case "relay_helper_hmac_secret":
			cfg.HMACSecret = asString(value, cfg.HMACSecret)
		case "helper_dsm_login_api":
			cfg.DSMLoginAPI = normalizeDSMAPIURL(asString(value, cfg.DSMLoginAPI))
		case "helper_dsm_session":
			cfg.DSMSession = asString(value, cfg.DSMSession)
		case "helper_dsm_format":
			cfg.DSMFormat = asStringAllowEmpty(value, cfg.DSMFormat)
		case "helper_dsm_otp_code":
			cfg.DSMOTPCode = asStringAllowEmpty(value, cfg.DSMOTPCode)
		case "helper_dsm_enable_device_token":
			cfg.DSMEnableDeviceToken = asStringAllowEmpty(value, cfg.DSMEnableDeviceToken)
		case "helper_dsm_device_name":
			cfg.DSMDeviceName = asStringAllowEmpty(value, cfg.DSMDeviceName)
		case "helper_dsm_device_id":
			cfg.DSMDeviceID = asStringAllowEmpty(value, cfg.DSMDeviceID)
		case "helper_dsm_tls_skip_verify":
			cfg.DSMTLSSkipVerify = asBool(value, cfg.DSMTLSSkipVerify)
		case "helper_dsm_timeout_seconds":
			cfg.DSMTimeoutSeconds = asInt(value, cfg.DSMTimeoutSeconds)
		case "helper_dsm_browser_login_ttl_seconds":
			cfg.DSMBrowserLoginTTLSeconds = asInt(value, cfg.DSMBrowserLoginTTLSeconds)
		}
	}
	return cfg
}

func runtimeStringSetting(ctx context.Context, q *db.Queries, key string) (string, error) {
	row, err := q.GetRuntimeSetting(ctx, key)
	if err != nil {
		return "", err
	}
	var value string
	if err := json.Unmarshal([]byte(row.ValueJson), &value); err != nil {
		return "", err
	}
	return value, nil
}

func randomHex(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func errorsIsNoRows(err error) bool {
	return err == sql.ErrNoRows
}

func normalizedAccessScheme(value string) string {
	if strings.ToLower(strings.TrimSpace(value)) == "http" {
		return "http"
	}
	return "https"
}

func asBool(value any, fallback bool) bool {
	if typed, ok := value.(bool); ok {
		return typed
	}
	return fallback
}

func normalizeDSMAPIURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "//webapi/", "/webapi/")
	return strings.TrimRight(value, "/")
}

func asString(value any, fallback string) string {
	if typed, ok := value.(string); ok && typed != "" {
		return typed
	}
	return fallback
}

func asStringAllowEmpty(value any, fallback string) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return fallback
}

func asInt(value any, fallback int) int {
	switch typed := value.(type) {
	case float64:
		if typed > 0 {
			return int(typed)
		}
	case int:
		if typed > 0 {
			return typed
		}
	case string:
		if parsed, err := strconv.Atoi(typed); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func normalizeAccessHost(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if index := strings.Index(value, "/"); index >= 0 {
		value = value[:index]
	}
	if index := strings.Index(value, ":"); index >= 0 {
		value = value[:index]
	}
	return strings.Trim(value, "[] ")
}
