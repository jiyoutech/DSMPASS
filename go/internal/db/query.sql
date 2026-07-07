-- name: GetRuntimeSetting :one
SELECT key, value_json, updated_at
FROM runtime_settings
WHERE key = ?;

-- name: ListRuntimeSettings :many
SELECT key, value_json, updated_at
FROM runtime_settings
ORDER BY key;

-- name: UpsertRuntimeSetting :exec
INSERT INTO runtime_settings (key, value_json, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(key) DO UPDATE SET
    value_json = excluded.value_json,
    updated_at = excluded.updated_at;

-- name: GetDeploymentSettings :one
SELECT id, mode, access_host, access_scheme, idp_port, public_base_url, dsm_redirect_url, helper_dsm_login_api, created_at, updated_at
FROM deployment_settings
WHERE id = 1;

-- name: UpsertDeploymentSettings :exec
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
    updated_at = excluded.updated_at;

-- name: CreateLoginAuditLog :exec
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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListLoginAuditLogs :many
SELECT id, request_id, provider_slug, external_account_id, app_identity_id, dsm_username, result, error_code, ip_address, ip_hash, user_agent_hash, duration_ms, created_at
FROM login_audit_logs
ORDER BY created_at DESC
LIMIT ?;
