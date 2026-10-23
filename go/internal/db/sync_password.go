package db

import "context"

// SyncedPasswordResetAllowed is checked by both the backend and privileged Helper.
// A username supplied by an administrator is not sufficient proof of membership.
func SyncedPasswordResetAllowed(ctx context.Context, q *Queries, sourceSlug, accountID, username string) (bool, error) {
	var allowed bool
	err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a
 JOIN app_identities i ON i.id = a.app_identity_id
 JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id AND me.mapping_type = 'user' AND me.active = 1
 JOIN external_accounts e ON e.id = me.external_account_id AND e.app_identity_id = a.app_identity_id
 JOIN identity_sources src ON src.slug = me.provider_slug
 WHERE a.id = ? AND a.dsm_username = ? AND a.managed = 1
   AND a.provision_status IN ('created', 'linked_existing')
   AND i.status = 'active' AND e.active = 1
   AND me.provider_slug = ? AND e.provider_slug = me.provider_slug
   AND src.enabled = 1 AND src.directory_sync_enabled = 1
)`, accountID, username, sourceSlug).Scan(&allowed)
	return allowed, err
}
