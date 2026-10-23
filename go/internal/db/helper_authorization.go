package db

import (
	"context"
	"errors"
)

// HelperAuthorizationQuery is a fixed query protocol, never a SQL interface.
// The root Helper runs it in a process with the package account's OS identity.
type HelperAuthorizationQuery struct {
	DatabasePath string `json:"database_path"`
	Action       string `json:"action"`
	Username     string `json:"username"`
	IdentityID   string `json:"identity_id,omitempty"`
	SourceSlug   string `json:"source_slug,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
}

type HelperAuthorizationResult struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

func HelperAccountAllowed(ctx context.Context, q *Queries, request HelperAuthorizationQuery) (bool, error) {
	if q == nil || request.Username == "" {
		return false, errors.New("account authorization requires a database and username")
	}
	if request.Action == "password_reset" {
		if request.SourceSlug == "" || request.AccountID == "" {
			return false, errors.New("missing password reset identity")
		}
		return SyncedPasswordResetAllowed(ctx, q, request.SourceSlug, request.AccountID, request.Username)
	}
	if request.Action != "login" && request.Action != "provision" && request.Action != "mapped" {
		return false, errors.New("unsupported account authorization action")
	}
	var allowed bool
	if request.Action == "login" {
		if request.IdentityID == "" || request.SourceSlug == "" {
			return false, errors.New("missing login identity or source")
		}
		err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a
 JOIN app_identities i ON i.id = a.app_identity_id
 JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id AND me.mapping_type = 'user' AND me.active = 1
 JOIN external_accounts e ON e.id = me.external_account_id AND e.app_identity_id = i.id
 JOIN identity_sources src ON src.slug = me.provider_slug
 WHERE a.dsm_username = ? AND i.id = ? AND me.provider_slug = ?
   AND e.provider_slug = me.provider_slug AND e.active = 1 AND i.status = 'active'
   AND src.enabled = 1 AND src.login_enabled = 1 AND a.allow_login = 1
   AND a.provision_status IN ('created', 'linked_existing')
)`, request.Username, request.IdentityID, request.SourceSlug).Scan(&allowed)
		return allowed, err
	}
	// Provisioning may precede final DSM mapping creation; it still requires a
	// synchronized identity. Disabling uses historical mapping, including users
	// whose provider identity has just become inactive.
	if request.Action == "provision" {
		err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a
 JOIN app_identities i ON i.id = a.app_identity_id
 JOIN external_accounts e ON e.app_identity_id = i.id
 JOIN identity_sources src ON src.slug = e.provider_slug
 WHERE a.dsm_username = ? AND i.status = 'active' AND e.active = 1
   AND src.enabled = 1 AND src.directory_sync_enabled = 1
)`, request.Username).Scan(&allowed)
		return allowed, err
	}
	err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a
 JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id AND me.mapping_type = 'user'
 WHERE a.dsm_username = ?
)`, request.Username).Scan(&allowed)
	return allowed, err
}
