package db

import (
	"context"
	"database/sql"
)

const getRuntimeSetting = `-- name: GetRuntimeSetting :one
SELECT key, value_json, updated_at
FROM runtime_settings
WHERE key = ?
`

func (q *Queries) GetRuntimeSetting(ctx context.Context, key string) (RuntimeSetting, error) {
	row := q.db.QueryRowContext(ctx, getRuntimeSetting, key)
	var item RuntimeSetting
	err := row.Scan(&item.Key, &item.ValueJson, &item.UpdatedAt)
	return item, err
}

const listRuntimeSettings = `-- name: ListRuntimeSettings :many
SELECT key, value_json, updated_at
FROM runtime_settings
ORDER BY key
`

func (q *Queries) ListRuntimeSettings(ctx context.Context) ([]RuntimeSetting, error) {
	rows, err := q.db.QueryContext(ctx, listRuntimeSettings)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []RuntimeSetting
	for rows.Next() {
		var item RuntimeSetting
		if err := rows.Scan(&item.Key, &item.ValueJson, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type UpsertRuntimeSettingParams struct {
	Key       string `json:"key"`
	ValueJson string `json:"value_json"`
}

const upsertRuntimeSetting = `-- name: UpsertRuntimeSetting :exec
INSERT INTO runtime_settings (key, value_json, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET
    value_json = excluded.value_json,
    updated_at = excluded.updated_at
`

func (q *Queries) UpsertRuntimeSetting(ctx context.Context, arg UpsertRuntimeSettingParams) error {
	_, err := q.db.ExecContext(ctx, upsertRuntimeSetting, arg.Key, arg.ValueJson)
	return err
}

const getDeploymentSettings = `-- name: GetDeploymentSettings :one
SELECT id, mode, access_host, access_scheme, idp_port, public_base_url, dsm_redirect_url, helper_dsm_login_api, created_at, updated_at
FROM deployment_settings
WHERE id = 1
`

func (q *Queries) GetDeploymentSettings(ctx context.Context) (DeploymentSetting, error) {
	row := q.db.QueryRowContext(ctx, getDeploymentSettings)
	var item DeploymentSetting
	err := row.Scan(
		&item.ID,
		&item.Mode,
		&item.AccessHost,
		&item.AccessScheme,
		&item.IDPPort,
		&item.PublicBaseURL,
		&item.DSMRedirectURL,
		&item.HelperDSMLoginAPI,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	return item, err
}

type UpsertDeploymentSettingsParams struct {
	Mode              string `json:"mode"`
	AccessHost        string `json:"access_host"`
	AccessScheme      string `json:"access_scheme"`
	IDPPort           int64  `json:"idp_port"`
	PublicBaseURL     string `json:"public_base_url"`
	DSMRedirectURL    string `json:"dsm_redirect_url"`
	HelperDSMLoginAPI string `json:"helper_dsm_login_api"`
}

const upsertDeploymentSettings = `-- name: UpsertDeploymentSettings :exec
INSERT INTO deployment_settings (
    id,
    mode,
    access_host,
    access_scheme,
    idp_port,
    public_base_url,
    dsm_redirect_url,
    helper_dsm_login_api,
    updated_at
) VALUES (1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(id) DO UPDATE SET
    mode = excluded.mode,
    access_host = excluded.access_host,
    access_scheme = excluded.access_scheme,
    idp_port = excluded.idp_port,
    public_base_url = excluded.public_base_url,
    dsm_redirect_url = excluded.dsm_redirect_url,
    helper_dsm_login_api = excluded.helper_dsm_login_api,
    updated_at = excluded.updated_at
`

func (q *Queries) UpsertDeploymentSettings(ctx context.Context, arg UpsertDeploymentSettingsParams) error {
	_, err := q.db.ExecContext(ctx, upsertDeploymentSettings,
		arg.Mode,
		arg.AccessHost,
		arg.AccessScheme,
		arg.IDPPort,
		arg.PublicBaseURL,
		arg.DSMRedirectURL,
		arg.HelperDSMLoginAPI,
	)
	return err
}

type CreateLoginAuditLogParams struct {
	ID                string         `json:"id"`
	RequestID         string         `json:"request_id"`
	ProviderSlug      string         `json:"provider_slug"`
	ExternalAccountID sql.NullString `json:"external_account_id"`
	AppIdentityID     sql.NullString `json:"app_identity_id"`
	DSMUsername       sql.NullString `json:"dsm_username"`
	Result            string         `json:"result"`
	ErrorCode         sql.NullString `json:"error_code"`
	IPAddress         sql.NullString `json:"ip_address"`
	IPHash            sql.NullString `json:"ip_hash"`
	UserAgentHash     sql.NullString `json:"user_agent_hash"`
	DurationMs        sql.NullInt64  `json:"duration_ms"`
}

const createLoginAuditLog = `-- name: CreateLoginAuditLog :exec
INSERT INTO login_audit_logs (
    id,
    request_id,
    provider_slug,
    external_account_id,
    app_identity_id,
    dsm_username,
    result,
    error_code,
    ip_address,
    ip_hash,
    user_agent_hash,
    duration_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

func (q *Queries) CreateLoginAuditLog(ctx context.Context, arg CreateLoginAuditLogParams) error {
	_, err := q.db.ExecContext(ctx, createLoginAuditLog,
		arg.ID,
		arg.RequestID,
		arg.ProviderSlug,
		arg.ExternalAccountID,
		arg.AppIdentityID,
		arg.DSMUsername,
		arg.Result,
		arg.ErrorCode,
		arg.IPAddress,
		arg.IPHash,
		arg.UserAgentHash,
		arg.DurationMs,
	)
	return err
}

const listLoginAuditLogs = `-- name: ListLoginAuditLogs :many
SELECT id, request_id, provider_slug, external_account_id, app_identity_id, dsm_username, result, error_code, ip_address, ip_hash, user_agent_hash, duration_ms, created_at
FROM login_audit_logs
ORDER BY created_at DESC
LIMIT ?
`

func (q *Queries) ListLoginAuditLogs(ctx context.Context, limit int64) ([]LoginAuditLog, error) {
	rows, err := q.db.QueryContext(ctx, listLoginAuditLogs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []LoginAuditLog
	for rows.Next() {
		var item LoginAuditLog
		if err := rows.Scan(
			&item.ID,
			&item.RequestID,
			&item.ProviderSlug,
			&item.ExternalAccountID,
			&item.AppIdentityID,
			&item.DSMUsername,
			&item.Result,
			&item.ErrorCode,
			&item.IPAddress,
			&item.IPHash,
			&item.UserAgentHash,
			&item.DurationMs,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
