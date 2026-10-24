package db

import (
	"context"
	"errors"
)

// This snapshot is trusted only during the administrator's one-time install
// migration. Runtime RPC authorization must never use it to grant enrollment.
type HelperEnrollmentSnapshot struct {
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
}

func HelperEnrollmentCandidates(ctx context.Context, q *Queries) (*HelperEnrollmentSnapshot, error) {
	if q == nil {
		return nil, errors.New("enrollment migration requires a database")
	}
	// A single statement gives both lists the same SQLite read snapshot. UNION
	// also deduplicates accounts mapped through more than one identity source.
	rows, err := q.DBTX().QueryContext(ctx, `
SELECT 'user' AS kind, a.dsm_username AS name FROM dsm_accounts a
JOIN app_identities i ON i.id = a.app_identity_id
JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id AND me.mapping_type = 'user' AND me.active = 1
JOIN external_accounts e ON e.id = me.external_account_id AND e.app_identity_id = i.id AND e.provider_slug = me.provider_slug
JOIN identity_sources src ON src.slug = me.provider_slug
WHERE a.provision_status IN ('created', 'linked_existing') AND i.status = 'active' AND e.active = 1
  AND src.enabled = 1 AND (src.login_enabled = 1 OR src.directory_sync_enabled = 1)
UNION
SELECT 'group' AS kind, g.dsm_groupname AS name FROM dsm_groups g
JOIN dsm_mapping_entries me ON me.dsm_group_id = g.id AND me.mapping_type = 'group' AND me.active = 1
JOIN provider_groups pg ON pg.id = me.provider_group_id AND pg.provider_slug = me.provider_slug
JOIN identity_sources src ON src.slug = me.provider_slug
WHERE g.provision_status IN ('created', 'linked_existing') AND pg.active = 1
  AND src.enabled = 1 AND src.directory_sync_enabled = 1
ORDER BY kind, name LIMIT 10001`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &HelperEnrollmentSnapshot{Users: []string{}, Groups: []string{}}
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return nil, err
		}
		if len(result.Users)+len(result.Groups) >= 10000 {
			return nil, errors.New("too many enrollment candidates; migration was not applied")
		}
		if kind == "user" {
			result.Users = append(result.Users, name)
		} else {
			result.Groups = append(result.Groups, name)
		}
	}
	return result, rows.Err()
}
