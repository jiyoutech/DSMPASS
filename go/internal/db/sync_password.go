package db

import (
	"context"
	"errors"
)

var ErrSyncedPasswordSourceConflict = errors.New("同一 DSM 账号关联了多个有效同步身份源，无法确定统一密码归属；请先解决映射冲突")

// SyncedPasswordResetAllowed is checked by both the backend and privileged Helper.
// A username supplied by an administrator is not sufficient proof of membership.
// The managed flag controls username generation, not synchronization membership.
func SyncedPasswordResetAllowed(ctx context.Context, q *Queries, sourceSlug, accountID, username string) (bool, error) {
	var allowed bool
	err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a
 JOIN app_identities i ON i.id = a.app_identity_id
 JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id AND me.mapping_type = 'user' AND me.active = 1
 JOIN external_accounts e ON e.id = me.external_account_id AND e.app_identity_id = a.app_identity_id
 JOIN identity_sources src ON src.slug = me.provider_slug
 WHERE a.id = ? AND a.dsm_username = ?
   AND a.provision_status IN ('created', 'linked_existing')
   AND i.status = 'active' AND e.active = 1
   AND me.provider_slug = ? AND e.provider_slug = me.provider_slug
   AND src.enabled = 1 AND src.directory_sync_enabled = 1
)`, accountID, username, sourceSlug).Scan(&allowed)
	if err != nil || !allowed {
		return allowed, err
	}
	var conflict bool
	err = q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_mapping_entries me
 JOIN dsm_accounts a ON a.id = me.dsm_account_id
 JOIN external_accounts e ON e.id = me.external_account_id AND e.app_identity_id = a.app_identity_id
 JOIN identity_sources src ON src.slug = me.provider_slug
 WHERE me.dsm_account_id = ? AND me.mapping_type = 'user' AND me.active = 1
   AND me.provider_slug <> ? AND e.provider_slug = me.provider_slug AND e.active = 1
   AND src.enabled = 1 AND src.directory_sync_enabled = 1
)`, accountID, sourceSlug).Scan(&conflict)
	if err == nil && conflict {
		return false, ErrSyncedPasswordSourceConflict
	}
	return allowed, err
}
