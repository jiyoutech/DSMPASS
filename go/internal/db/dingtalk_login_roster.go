package db

import (
	"context"
	"errors"
	"strings"
)

// DingTalkLoginRoster lists active one-to-one mappings in a single read snapshot.
// These rows alone do not authorize access to any DSM account.
func DingTalkLoginRoster(ctx context.Context, q *Queries, source string) (map[string]string, error) {
	if q == nil || source == "" {
		return nil, errors.New("missing DingTalk source")
	}
	rows, err := q.DBTX().QueryContext(ctx, `
WITH eligible AS (
SELECT e.id, a.dsm_username FROM dsm_accounts a
JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
JOIN dsm_mapping_entries m ON m.dsm_account_id=a.id AND m.mapping_type='user' AND m.active=1
JOIN external_accounts e ON e.id=m.external_account_id AND e.app_identity_id=i.id AND e.provider_slug=m.provider_slug AND e.active=1
JOIN identity_sources src ON src.slug=m.provider_slug AND src.enabled=1 AND src.directory_sync_enabled=1 AND src.login_enabled=1
WHERE src.slug=? AND src.provider_type='dingtalk' AND e.subject<>''
AND a.allow_login=1 AND a.manual_login_blocked=0 AND coalesce(a.conflict_reason,'')=''
AND a.provision_status IN ('created','linked_existing')
AND NOT EXISTS (SELECT 1 FROM external_accounts alias
 WHERE alias.provider_slug=e.provider_slug AND alias.active=1 AND alias.subject=e.subject AND alias.id<>e.id)
AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries other
 WHERE other.mapping_type='user' AND other.active=1 AND other.id<>m.id
 AND (other.dsm_account_id=a.id OR other.external_account_id=e.id))
)
SELECT coalesce(e.display_name,''),e.subject,coalesce(ok.dsm_username,'') FROM external_accounts e
LEFT JOIN eligible ok ON ok.id=e.id
WHERE e.provider_slug=? AND e.active=1 LIMIT 10001`, source, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roster := make(map[string]string)
	seen := make(map[string]string)
	count := 0
	for rows.Next() {
		var displayName, subject, name string
		if err := rows.Scan(&displayName, &subject, &name); err != nil {
			return nil, err
		}
		count++
		if count > 10000 {
			return nil, errors.New("too many DingTalk directory users")
		}
		displayName = strings.TrimSpace(displayName)
		key := strings.ToLower(displayName)
		if previous, exists := seen[key]; exists {
			delete(roster, previous)
			continue
		}
		seen[key] = name
		if name != "" && displayName == name && subject != "" {
			roster[name] = subject
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roster, nil
}
