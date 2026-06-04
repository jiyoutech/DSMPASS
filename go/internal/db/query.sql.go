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
