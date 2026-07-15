package db

import "database/sql"

type RuntimeSetting struct {
	Key       string `json:"key"`
	ValueJson string `json:"value_json"`
	UpdatedAt string `json:"updated_at"`
}

type DeploymentSetting struct {
	ID                int64  `json:"id"`
	Mode              string `json:"mode"`
	AccessHost        string `json:"access_host"`
	AccessScheme      string `json:"access_scheme"`
	IDPPort           int64  `json:"idp_port"`
	PublicBaseURL     string `json:"public_base_url"`
	DSMRedirectURL    string `json:"dsm_redirect_url"`
	HelperDSMLoginAPI string `json:"helper_dsm_login_api"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type IdentitySource struct {
	Slug                 string `json:"slug"`
	ProviderType         string `json:"provider_type"`
	DisplayName          string `json:"display_name"`
	Enabled              int64  `json:"enabled"`
	LoginEnabled         int64  `json:"login_enabled"`
	DirectorySyncEnabled int64  `json:"directory_sync_enabled"`
	ConfigJSON           string `json:"config_json"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
}

type ExternalAccount struct {
	ID            string         `json:"id"`
	ProviderSlug  string         `json:"provider_slug"`
	Subject       string         `json:"subject"`
	SubjectNorm   string         `json:"subject_norm"`
	SubjectType   string         `json:"subject_type"`
	AppIdentityID sql.NullString `json:"app_identity_id"`
	DisplayName   sql.NullString `json:"display_name"`
	Email         sql.NullString `json:"email"`
	EmailNorm     sql.NullString `json:"email_norm"`
	EmailVerified sql.NullInt64  `json:"email_verified"`
	MobileMasked  sql.NullString `json:"mobile_masked"`
	AvatarURL     sql.NullString `json:"avatar_url"`
	Active        int64          `json:"active"`
	LastLoginAt   sql.NullString `json:"last_login_at"`
	LastSeenAt    sql.NullString `json:"last_seen_at"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at"`
}

type AppIdentity struct {
	ID               string         `json:"id"`
	DisplayName      sql.NullString `json:"display_name"`
	PrimaryEmail     sql.NullString `json:"primary_email"`
	PrimaryEmailNorm sql.NullString `json:"primary_email_norm"`
	Status           string         `json:"status"`
	CreatedBy        string         `json:"created_by"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
}

type DSMAccount struct {
	ID              string         `json:"id"`
	AppIdentityID   string         `json:"app_identity_id"`
	DSMUsername     string         `json:"dsm_username"`
	DSMUsernameNorm string         `json:"dsm_username_norm"`
	Managed         int64          `json:"managed"`
	ProvisionStatus string         `json:"provision_status"`
	ConflictReason  sql.NullString `json:"conflict_reason"`
	AllowLogin      int64          `json:"allow_login"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
}

type ProviderGroup struct {
	ID            string         `json:"id"`
	ProviderSlug  string         `json:"provider_slug"`
	Subject       string         `json:"subject"`
	SubjectNorm   string         `json:"subject_norm"`
	ParentSubject sql.NullString `json:"parent_subject"`
	Name          string         `json:"name"`
	Path          sql.NullString `json:"path"`
	Active        int64          `json:"active"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at"`
}

type DSMGroup struct {
	ID               string         `json:"id"`
	DSMGroupname     string         `json:"dsm_groupname"`
	DSMGroupnameNorm string         `json:"dsm_groupname_norm"`
	Managed          int64          `json:"managed"`
	ProvisionStatus  string         `json:"provision_status"`
	ConflictReason   sql.NullString `json:"conflict_reason"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
}

type GroupLink struct {
	ID              string `json:"id"`
	ProviderGroupID string `json:"provider_group_id"`
	DSMGroupID      string `json:"dsm_group_id"`
	LinkMode        string `json:"link_mode"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type GroupMember struct {
	ID              string `json:"id"`
	DSMGroupID      string `json:"dsm_group_id"`
	DSMAccountID    string `json:"dsm_account_id"`
	Active          int64  `json:"active"`
	ProvisionStatus string `json:"provision_status"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type LoginAuditLog struct {
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
	CreatedAt         string         `json:"created_at"`
}
