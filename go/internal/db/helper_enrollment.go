package db

import (
	"context"
	"database/sql"
	"errors"
)

type DingTalkUserBinding struct {
	SourceSlug string `json:"source_slug"`
	Subject    string `json:"subject"`
}

// CredentialIdentity is a stable directory principal captured by the root installer.
type CredentialIdentity struct {
	Username   string `json:"username"`
	SourceSlug string `json:"source_slug"`
	Subject    string `json:"subject"`
}

// This snapshot is consumed only by the explicit root installer.
type HelperEnrollmentSnapshot struct {
	VerifiedEmails  map[string]CredentialIdentity  `json:"verified_emails,omitempty"`
	DingTalkSources []string                       `json:"dingtalk_sources,omitempty"`
	DingTalkUsers   map[string]DingTalkUserBinding `json:"dingtalk_users,omitempty"`
	Users           []string                       `json:"users"`
	Groups          []string                       `json:"groups"`
	// RetryUsers need additional evidence from DSM before enrollment.
	RetryUsers  map[string]string   `json:"retry_users,omitempty"`
	Departments map[string][]string `json:"departments,omitempty"`
}

// The member writer stores the provider department subject. Older/manual
// entries can instead contain its internal ID. Both must resolve to the same
// department as the active group mapping in this source.
const memberDepartmentMatch = `(pg.subject = mm.provider_group_id OR pg.id = mm.provider_group_id)
 AND NOT EXISTS (SELECT 1 FROM provider_groups alt WHERE alt.provider_slug=pg.provider_slug
 AND alt.id<>pg.id AND (alt.id=mm.provider_group_id OR alt.subject=mm.provider_group_id))`

const unresolvedDingTalkNamesake = `src.provider_type='dingtalk' AND trim(coalesce(e.display_name,''))=a.dsm_username COLLATE dsmpass_name
 AND EXISTS (SELECT 1 FROM external_accounts other WHERE other.provider_slug=e.provider_slug
 AND other.active=1 AND other.id<>e.id AND trim(other.display_name)=a.dsm_username COLLATE dsmpass_name)`

const uniqueDingTalkName = `src.provider_type='dingtalk' AND trim(e.display_name)=a.dsm_username COLLATE dsmpass_name AND trim(e.subject)<>''
 AND NOT (` + unresolvedDingTalkNamesake + `)`

const dingTalkBindings = `SELECT a.dsm_username AS name, MIN(src.slug) AS source, MIN(e.subject) AS subject
FROM dsm_accounts a JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
JOIN dsm_mapping_entries um ON um.mapping_type='user' AND um.active=1 AND um.dsm_account_id=a.id
JOIN external_accounts e ON e.id=um.external_account_id AND e.app_identity_id=i.id AND e.active=1 AND e.provider_slug=um.provider_slug
JOIN identity_sources src ON src.slug=um.provider_slug AND src.enabled=1 AND src.directory_sync_enabled=1
WHERE a.provision_status IN ('pending','failed','created','linked_existing') AND COALESCE(a.conflict_reason,'')=''
AND ` + uniqueDingTalkName + `
GROUP BY a.id, a.dsm_username HAVING COUNT(DISTINCT e.id)=1`

const directoryMembershipScope = `
FROM group_members m
JOIN dsm_accounts a ON a.id = m.dsm_account_id
JOIN app_identities i ON i.id = a.app_identity_id AND i.status = 'active'
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN dsm_mapping_entries mm ON mm.mapping_type = 'member' AND mm.active = 1 AND mm.dsm_account_id = a.id AND mm.dsm_group_id = g.id
JOIN identity_sources src ON src.slug = mm.provider_slug AND src.enabled = 1 AND src.directory_sync_enabled = 1
JOIN dsm_mapping_entries um ON um.mapping_type = 'user' AND um.active = 1 AND um.dsm_account_id = a.id AND um.provider_slug = mm.provider_slug
JOIN external_accounts e ON e.id = um.external_account_id AND e.provider_slug = src.slug AND e.app_identity_id = a.app_identity_id AND e.active = 1 AND e.id = mm.external_account_id
JOIN dsm_mapping_entries gm ON gm.mapping_type = 'group' AND gm.active = 1 AND gm.dsm_group_id = g.id AND gm.provider_slug = mm.provider_slug
JOIN provider_groups pg ON pg.id = gm.provider_group_id AND pg.provider_slug = src.slug AND pg.active = 1 AND ` + memberDepartmentMatch + `
WHERE m.active = 1 AND a.provision_status IN ('pending','failed','created','linked_existing') AND COALESCE(a.conflict_reason, '') = '' AND g.provision_status IN ('pending','failed','created','linked_existing')`

func HelperEnrollmentCandidates(ctx context.Context, q *Queries) (*HelperEnrollmentSnapshot, error) {
	if q == nil {
		return nil, errors.New("enrollment migration requires a database")
	}
	// A single statement gives both lists the same SQLite read snapshot. UNION
	// also deduplicates accounts mapped through more than one identity source.
	rows, err := q.DBTX().QueryContext(ctx, `
WITH successful AS (
 SELECT l.source_slug, l.object_key, l.dsm_name, MAX(l.created_at) AS last_success
 FROM sync_operation_logs l JOIN sync_runs r ON r.id = l.sync_run_id AND r.source_slug = l.source_slug
 WHERE r.dry_run = 0 AND l.object_type = 'user' AND l.action = 'create_or_update'
   AND l.status = 'success' AND l.after_state IN ('created', 'linked_existing')
 GROUP BY l.source_slug, l.object_key, l.dsm_name
), unique_mail AS (
 SELECT email_norm, MIN(app_identity_id) AS identity_id FROM external_accounts
 WHERE active = 1 AND email_norm <> '' AND app_identity_id IS NOT NULL
 GROUP BY email_norm HAVING COUNT(DISTINCT app_identity_id) = 1
)
-- A successful DingTalk reconciliation can be based only on a matching name.
-- Check the root creation receipt or verified email before granting credentials.
SELECT CASE WHEN MAX(src.provider_type <> 'dingtalk' AND
            (a.provision_status IN ('created', 'linked_existing') OR COALESCE(h.last_success >= me.created_at, 0)))
            THEN 'user' ELSE 'retry_user' END AS kind, a.dsm_username AS name,
       CASE WHEN COUNT(DISTINCT e.email_norm) = 1 THEN COALESCE(MAX(mail.email_norm), '') ELSE '' END AS email, '' AS subject, '' AS target
FROM dsm_accounts a
JOIN app_identities i ON i.id = a.app_identity_id
JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id AND me.mapping_type = 'user' AND me.active = 1
JOIN external_accounts e ON e.id = me.external_account_id AND e.app_identity_id = i.id AND e.provider_slug = me.provider_slug
JOIN identity_sources src ON src.slug = me.provider_slug
LEFT JOIN successful h ON h.object_key = a.id AND h.dsm_name = a.dsm_username AND h.source_slug = me.provider_slug
LEFT JOIN unique_mail mail ON mail.identity_id = i.id AND mail.email_norm = e.email_norm AND e.email_verified = 1 AND NOT (`+unresolvedDingTalkNamesake+`)
WHERE i.status = 'active' AND e.active = 1 AND src.enabled = 1
  AND COALESCE(a.conflict_reason, '') = ''
  AND ((a.provision_status IN ('created', 'linked_existing') AND (src.login_enabled = 1 OR src.directory_sync_enabled = 1))
    OR (a.provision_status IN ('pending', 'failed') AND src.directory_sync_enabled = 1))
GROUP BY a.id, a.dsm_username
UNION
SELECT 'group' AS kind, g.dsm_groupname AS name, '' AS email, '' AS subject, '' AS target FROM dsm_groups g
JOIN dsm_mapping_entries me ON me.dsm_group_id = g.id AND me.mapping_type = 'group' AND me.active = 1
JOIN provider_groups pg ON pg.id = me.provider_group_id AND pg.provider_slug = me.provider_slug
JOIN identity_sources src ON src.slug = me.provider_slug
WHERE g.provision_status IN ('created', 'linked_existing') AND pg.active = 1
  AND src.enabled = 1 AND src.directory_sync_enabled = 1
UNION
SELECT 'member', a.dsm_username, g.dsm_groupname, '', ''
`+directoryMembershipScope+`
UNION
SELECT 'dingtalk', name, source, subject, '' FROM (`+dingTalkBindings+`)
UNION
SELECT 'verified_email', e.email_norm, src.slug, e.subject, a.dsm_username FROM external_accounts e
JOIN app_identities i ON i.id=e.app_identity_id AND i.status='active'
JOIN identity_sources src ON src.slug=e.provider_slug AND src.enabled=1 AND src.directory_sync_enabled=1
JOIN dsm_mapping_entries um ON um.mapping_type='user' AND um.active=1 AND um.external_account_id=e.id AND um.provider_slug=src.slug
JOIN dsm_accounts a ON a.id=um.dsm_account_id AND a.app_identity_id=i.id
WHERE NOT (`+unresolvedDingTalkNamesake+`) AND COALESCE(a.conflict_reason,'')='' AND a.provision_status IN ('created','linked_existing','pending','failed')
AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries other JOIN external_accounts x ON x.id=other.external_account_id AND x.active=1
 JOIN identity_sources s ON s.slug=other.provider_slug AND s.enabled=1
 WHERE other.mapping_type='user' AND other.active=1 AND other.dsm_account_id=a.id AND other.id<>um.id)
AND e.active=1 AND e.email_verified=1 AND e.email_norm<>'' AND e.subject<>''
AND NOT EXISTS (SELECT 1 FROM external_accounts other WHERE other.active=1 AND other.email_norm=e.email_norm AND other.id<>e.id)
UNION SELECT 'source', slug, '', '', '' FROM identity_sources WHERE provider_type='dingtalk' AND enabled=1 AND directory_sync_enabled=1
ORDER BY kind, name LIMIT 131001`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &HelperEnrollmentSnapshot{Users: []string{}, Groups: []string{}}
	memberCount := 0
	for rows.Next() {
		var kind, name, detail, subject, target string
		if err := rows.Scan(&kind, &name, &detail, &subject, &target); err != nil {
			return nil, err
		}
		if kind != "verified_email" && kind != "member" && kind != "dingtalk" && kind != "source" && len(result.Users)+len(result.Groups)+len(result.RetryUsers) >= 10000 {
			return nil, errors.New("too many enrollment candidates; migration was not applied")
		}
		switch kind {
		case "verified_email":
			if len(result.VerifiedEmails) >= 10000 {
				return nil, errors.New("too many verified directory identities")
			}
			if result.VerifiedEmails == nil {
				result.VerifiedEmails = map[string]CredentialIdentity{}
			}
			result.VerifiedEmails[name] = CredentialIdentity{Username: target, SourceSlug: detail, Subject: subject}
		case "source":
			if len(result.DingTalkSources) >= 1000 {
				return nil, errors.New("too many DingTalk sources")
			}
			result.DingTalkSources = append(result.DingTalkSources, name)
		case "dingtalk":
			if len(result.DingTalkUsers) >= 10000 {
				return nil, errors.New("too many DingTalk bindings")
			}
			if result.DingTalkUsers == nil {
				result.DingTalkUsers = make(map[string]DingTalkUserBinding)
			}
			result.DingTalkUsers[name] = DingTalkUserBinding{SourceSlug: detail, Subject: subject}
		case "user":
			result.Users = append(result.Users, name)
		case "member":
			memberCount++
			if memberCount > 100000 {
				return nil, errors.New("too many enrollment memberships")
			}
			if result.Departments == nil {
				result.Departments = make(map[string][]string)
			}
			result.Departments[name] = append(result.Departments[name], detail)
		case "retry_user":
			if result.RetryUsers == nil {
				result.RetryUsers = make(map[string]string)
			}
			result.RetryUsers[name] = detail
		default:
			result.Groups = append(result.Groups, name)
		}
	}
	return result, rows.Err()
}

// A partial or ambiguous match cannot establish a directory-only identity.
func DingTalkBindingForName(ctx context.Context, q *Queries, name string) (*DingTalkUserBinding, error) {
	if q == nil || name == "" {
		return nil, errors.New("DingTalk binding requires a store and username")
	}
	var binding DingTalkUserBinding
	err := q.DBTX().QueryRowContext(ctx, `SELECT source,subject FROM (`+dingTalkBindings+`) WHERE name=?`, name).Scan(&binding.SourceSlug, &binding.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

type DingTalkLoginMatch struct {
	DingTalkUserBinding
	Selected bool `json:"selected,omitempty"`
}

// DingTalkLoginBinding checks the synchronized directory and the administrator's
// saved choice in one read. The caller independently reads the native DSM UID.
func DingTalkLoginBinding(ctx context.Context, q *Queries, name string, uid int) (*DingTalkLoginMatch, error) {
	if q == nil || name == "" || uid < 1024 || uid >= 65536 {
		return nil, nil
	}
	var binding DingTalkLoginMatch
	err := q.DBTX().QueryRowContext(ctx, `SELECT src.slug,e.subject,c.account_id IS NOT NULL
FROM dsm_accounts a
JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
JOIN dsm_mapping_entries m ON m.dsm_account_id=a.id AND m.mapping_type='user' AND m.active=1
JOIN external_accounts e ON e.id=m.external_account_id AND e.app_identity_id=i.id AND e.provider_slug=m.provider_slug AND e.active=1
JOIN identity_sources src ON src.slug=e.provider_slug AND src.provider_type='dingtalk'
LEFT JOIN directory_owner_choices c ON c.account_id=a.id
WHERE a.dsm_username=? AND src.enabled=1 AND src.directory_sync_enabled=1 AND src.login_enabled=1
AND a.allow_login=1 AND a.manual_login_blocked=0 AND coalesce(a.conflict_reason,'')=''
AND a.provision_status IN ('pending','failed','created','linked_existing') AND trim(e.subject)<>''
AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries x WHERE x.mapping_type='user' AND x.active=1 AND x.id<>m.id
 AND (x.dsm_account_id=a.id OR x.external_account_id=e.id))
AND NOT EXISTS (SELECT 1 FROM external_accounts x WHERE x.provider_slug=src.slug AND x.subject=e.subject AND x.active=1 AND x.id<>e.id)
AND ((c.external_id=e.id AND c.source_slug=src.slug AND c.subject=e.subject AND c.username=a.dsm_username AND c.uid=? AND a.managed=0)
 OR (c.account_id IS NULL AND `+uniqueDingTalkName+`))`, name, uid).Scan(&binding.SourceSlug, &binding.Subject, &binding.Selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &binding, nil
}
