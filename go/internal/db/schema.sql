CREATE TABLE IF NOT EXISTS runtime_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deployment_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    mode TEXT NOT NULL DEFAULT 'direct',
    access_host TEXT NOT NULL DEFAULT '',
    access_scheme TEXT NOT NULL DEFAULT 'https',
    idp_port INTEGER NOT NULL DEFAULT 26000,
    public_base_url TEXT NOT NULL DEFAULT '',
    dsm_redirect_url TEXT NOT NULL DEFAULT '',
    helper_dsm_login_api TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS identity_sources (
    slug TEXT PRIMARY KEY,
    provider_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    login_enabled INTEGER NOT NULL DEFAULT 1,
    directory_sync_enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS external_accounts (
    id TEXT PRIMARY KEY,
    provider_slug TEXT NOT NULL,
    subject TEXT NOT NULL,
    subject_norm TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    app_identity_id TEXT,
    display_name TEXT,
    email TEXT,
    email_norm TEXT,
    email_verified INTEGER,
    mobile_masked TEXT,
    avatar_url TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    last_login_at TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_slug, subject_norm)
);

CREATE TABLE IF NOT EXISTS app_identities (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    primary_email TEXT,
    primary_email_norm TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dsm_accounts (
    id TEXT PRIMARY KEY,
    app_identity_id TEXT NOT NULL UNIQUE,
    dsm_username TEXT NOT NULL,
    dsm_username_norm TEXT NOT NULL UNIQUE,
    managed INTEGER NOT NULL DEFAULT 1,
    provision_status TEXT NOT NULL DEFAULT 'pending',
    conflict_reason TEXT,
    allow_login INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS provider_groups (
    id TEXT PRIMARY KEY,
    provider_slug TEXT NOT NULL,
    subject TEXT NOT NULL,
    subject_norm TEXT NOT NULL,
    parent_subject TEXT,
    name TEXT NOT NULL,
    path TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_slug, subject_norm)
);

CREATE TABLE IF NOT EXISTS dsm_groups (
    id TEXT PRIMARY KEY,
    dsm_groupname TEXT NOT NULL,
    dsm_groupname_norm TEXT NOT NULL UNIQUE,
    managed INTEGER NOT NULL DEFAULT 1,
    provision_status TEXT NOT NULL DEFAULT 'pending',
    conflict_reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_links (
    id TEXT PRIMARY KEY,
    provider_group_id TEXT NOT NULL,
    dsm_group_id TEXT NOT NULL,
    link_mode TEXT NOT NULL DEFAULT 'managed',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_group_id, dsm_group_id)
);

CREATE TABLE IF NOT EXISTS group_members (
    id TEXT PRIMARY KEY,
    dsm_group_id TEXT NOT NULL,
    dsm_account_id TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    provision_status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(dsm_group_id, dsm_account_id)
);

CREATE TABLE IF NOT EXISTS dsm_mapping_entries (
    id TEXT PRIMARY KEY,
    mapping_type TEXT NOT NULL,
    provider_slug TEXT NOT NULL,
    external_account_id TEXT NOT NULL DEFAULT '',
    provider_group_id TEXT NOT NULL DEFAULT '',
    dsm_account_id TEXT,
    dsm_group_id TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(mapping_type, provider_slug, external_account_id, provider_group_id)
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id TEXT PRIMARY KEY,
    source_slug TEXT NOT NULL,
    dry_run INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS sync_operation_logs (
    id TEXT PRIMARY KEY,
    sync_run_id TEXT NOT NULL,
    source_slug TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_key TEXT NOT NULL,
    dsm_name TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    before_state TEXT,
    after_state TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_audit_logs (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    provider_slug TEXT NOT NULL,
    external_account_id TEXT,
    app_identity_id TEXT,
    dsm_username TEXT,
    result TEXT NOT NULL,
    error_code TEXT,
    ip_address TEXT,
    ip_hash TEXT,
    user_agent_hash TEXT,
    duration_ms INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operation_runs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    source_slug TEXT,
    status TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    current INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS operation_events (
    id TEXT PRIMARY KEY,
    operation_run_id TEXT NOT NULL,
    source_slug TEXT,
    kind TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    current INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_identity_sources_sync_enabled
    ON identity_sources(enabled, directory_sync_enabled);

CREATE INDEX IF NOT EXISTS idx_external_accounts_provider_active_seen
    ON external_accounts(provider_slug, active, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_external_accounts_app_identity
    ON external_accounts(app_identity_id);

CREATE INDEX IF NOT EXISTS idx_dsm_accounts_status
    ON dsm_accounts(provision_status);

CREATE INDEX IF NOT EXISTS idx_dsm_accounts_allow_status
    ON dsm_accounts(allow_login, provision_status);

CREATE INDEX IF NOT EXISTS idx_provider_groups_provider_active_updated
    ON provider_groups(provider_slug, active, updated_at);

CREATE INDEX IF NOT EXISTS idx_dsm_groups_status
    ON dsm_groups(provision_status);

CREATE INDEX IF NOT EXISTS idx_group_links_dsm_group
    ON group_links(dsm_group_id);

CREATE INDEX IF NOT EXISTS idx_group_members_account
    ON group_members(dsm_account_id);

CREATE INDEX IF NOT EXISTS idx_group_members_active_status_updated
    ON group_members(active, provision_status, updated_at);

CREATE INDEX IF NOT EXISTS idx_dsm_mapping_entries_target
    ON dsm_mapping_entries(mapping_type, active, dsm_account_id, dsm_group_id);

CREATE INDEX IF NOT EXISTS idx_dsm_mapping_entries_source_updated
    ON dsm_mapping_entries(provider_slug, active, updated_at);

CREATE INDEX IF NOT EXISTS idx_sync_runs_source_started
    ON sync_runs(source_slug, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_sync_operation_logs_source_created
    ON sync_operation_logs(source_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_audit_logs_provider_created
    ON login_audit_logs(provider_slug, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_audit_logs_created
    ON login_audit_logs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_operation_runs_source_started
    ON operation_runs(source_slug, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_operation_events_run_created
    ON operation_events(operation_run_id, created_at DESC);
