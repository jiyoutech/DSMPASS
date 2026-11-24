package db

import (
	"context"
	"encoding/json"
	"errors"
)

const MaxGroupMembers = 200
const MaxProvisionUsers = 200

// These constraints are populated from the Helper's local UID/GID policy.
type HelperMemberScope struct {
	Username   string               `json:"username"`
	DingTalk   *DingTalkUserBinding `json:"dingtalk,omitempty"`
	OtherGroup bool                 `json:"other_group,omitempty"`
}

// HelperAuthorizationQuery is a fixed query protocol, never a SQL interface.
// The root Helper runs it in a process with the package account's OS identity.
type HelperAuthorizationQuery struct {
	LocalUID        int                 `json:"local_uid,omitempty"`
	Usernames       []string            `json:"usernames,omitempty"`
	Members         []HelperMemberScope `json:"members,omitempty"`
	CredentialOwner *CredentialIdentity `json:"credential_owner,omitempty"`
	VerifiedEmail   string              `json:"verified_email,omitempty"`
	DatabasePath    string              `json:"database_path"`
	Action          string              `json:"action"`
	RunID           string              `json:"run_id,omitempty"`
	Subject         string              `json:"subject,omitempty"`
	Username        string              `json:"username"`
	Groupname       string              `json:"groupname,omitempty"`
	IdentityID      string              `json:"identity_id,omitempty"`
	SourceSlug      string              `json:"source_slug,omitempty"`
	AccountID       string              `json:"account_id,omitempty"`
}

type HelperAuthorizationResult struct {
	DingTalkLoginMatch *DingTalkLoginMatch       `json:"dingtalk_login_match,omitempty"`
	LoginRoster        map[string]string         `json:"login_roster,omitempty"`
	DingTalkBinding    *DingTalkUserBinding      `json:"dingtalk_binding,omitempty"`
	Allowed            bool                      `json:"allowed"`
	Error              string                    `json:"error,omitempty"`
	Enrollment         *HelperEnrollmentSnapshot `json:"enrollment,omitempty"`
}

const provisionIdentityScope = `
 FROM dsm_accounts a
 JOIN app_identities i ON i.id=a.app_identity_id
 JOIN external_accounts e ON e.app_identity_id=i.id
 JOIN identity_sources src ON src.slug=e.provider_slug
 WHERE i.status='active' AND e.active=1 AND src.enabled=1 AND src.directory_sync_enabled=1`

func HelperAccountAllowed(ctx context.Context, q *Queries, request HelperAuthorizationQuery) (bool, error) {
	if request.Action == "directory_account_match" {
		if request.LocalUID < 1024 || request.LocalUID >= 65536 || request.Username == "" || q == nil {
			return false, nil
		}
		var ok bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dsm_accounts a
 JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
 JOIN dsm_mapping_entries m ON m.dsm_account_id=a.id AND m.mapping_type='user' AND m.active=1
 JOIN external_accounts e ON e.id=m.external_account_id AND e.app_identity_id=i.id AND e.provider_slug=m.provider_slug AND e.active=1
 JOIN identity_sources s ON s.slug=e.provider_slug AND s.enabled=1 AND s.directory_sync_enabled=1
 LEFT JOIN directory_owner_choices c ON c.account_id=a.id
 WHERE a.dsm_username=? AND a.provision_status IN ('pending','failed','created','linked_existing') AND COALESCE(a.conflict_reason,'')=''
 AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries x WHERE x.mapping_type='user' AND x.active=1 AND x.dsm_account_id=a.id AND x.id<>m.id)
 AND ((c.external_id=e.id AND c.source_slug=s.slug AND c.subject=e.subject AND c.username=a.dsm_username AND c.uid=? AND a.managed=0)
 OR (c.account_id IS NULL AND s.provider_type IN ('feishu','wecom') AND a.managed=1 AND trim(e.display_name)=a.dsm_username AND e.subject<>''
 AND NOT EXISTS (SELECT 1 FROM external_accounts other WHERE other.provider_slug=s.slug AND other.active=1 AND trim(other.display_name)=trim(e.display_name) AND other.id<>e.id))))`, request.Username, request.LocalUID).Scan(&ok)
		return ok, err
	}
	if request.Action == "provision_users" {
		if q == nil || len(request.Usernames) == 0 || len(request.Usernames) > MaxProvisionUsers {
			return false, errors.New("invalid account provisioning authorization batch")
		}
		names, err := json.Marshal(request.Usernames)
		if err != nil {
			return false, err
		}
		// All candidates were checked against the root-owned policy under the
		// writer lock. Apply the same live identity scope as individual provisioning.
		var allowed bool
		err = q.DBTX().QueryRowContext(ctx, `SELECT NOT EXISTS (
 SELECT 1 FROM json_each(?) AS requested WHERE NOT EXISTS (
 SELECT 1 `+provisionIdentityScope+` AND a.dsm_username=requested.value))`, string(names)).Scan(&allowed)
		return allowed, err
	}
	if request.Action == "directory_member_batch" {
		if q == nil || request.Groupname == "" || len(request.Members) == 0 || len(request.Members) > MaxGroupMembers {
			return false, errors.New("invalid directory membership query")
		}
		for _, m := range request.Members {
			if m.Username == "" || (m.DingTalk == nil && !m.OtherGroup) || (m.DingTalk != nil && (m.DingTalk.SourceSlug == "" || m.DingTalk.Subject == "")) {
				return false, errors.New("invalid directory membership constraint")
			}
		}
		members, err := json.Marshal(request.Members)
		if err != nil {
			return false, err
		}
		var allowed bool
		err = q.DBTX().QueryRowContext(ctx, `
WITH wanted AS (
 SELECT json_extract(value,'$.username') AS username, json_extract(value,'$.dingtalk.source_slug') AS slug,
        json_extract(value,'$.dingtalk.subject') AS subject, json_extract(value,'$.other_group') AS other_group
 FROM json_each(?)
)
SELECT NOT EXISTS (
 SELECT 1 FROM wanted w WHERE NOT EXISTS (
   SELECT 1 `+directoryMembershipScope+` AND a.dsm_username=w.username AND g.dsm_groupname=?
   AND ((src.provider_type <> 'dingtalk' AND w.other_group=1)
     OR ((`+uniqueDingTalkName+`) AND (w.slug IS NULL OR (src.slug=w.slug AND e.subject=w.subject))))
 )
)`, string(members), request.Groupname).Scan(&allowed)
		return allowed, err
	}
	if owner := request.CredentialOwner; owner != nil {
		if q == nil || request.Username != owner.Username || owner.Username == "" || owner.SourceSlug == "" || owner.Subject == "" || (request.SourceSlug != "" && request.SourceSlug != owner.SourceSlug) || (request.Subject != "" && request.Subject != owner.Subject) {
			return false, nil
		}
		switch request.Action {
		case "login", "password_reset":
			if request.SourceSlug != owner.SourceSlug {
				return false, nil
			}
			return verifiedOwnerAllowed(ctx, q, request, *owner)
		case "verify_existing_owner":
			if request.VerifiedEmail == "" {
				return false, nil
			}
			return verifiedOwnerAllowed(ctx, q, request, *owner)
		case "provision", "mapped":
			valid, err := verifiedOwnerAllowed(ctx, q, request, *owner)
			if err != nil || !valid {
				return false, err
			}
		}
		// Offboarding separately checks the historical source/subject and completed directory evidence.
	}

	if q != nil && (request.Action == "cleanup_user" || request.Action == "cleanup_absent" || request.Action == "cleanup_conflict") {
		subject := ""
		if request.CredentialOwner != nil {
			subject = request.CredentialOwner.Subject
		}
		var ok bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM source_cleanup_targets t JOIN dsm_accounts a ON a.id=t.account_id AND a.dsm_username=t.username
WHERE t.source_slug=? AND t.request_id=? AND t.account_id=? AND t.username=?
AND EXISTS (SELECT 1 FROM external_accounts e WHERE e.app_identity_id=a.app_identity_id AND e.provider_slug=t.source_slug)
AND NOT EXISTS(SELECT 1 FROM external_accounts x WHERE x.app_identity_id=a.app_identity_id AND x.provider_slug<>t.source_slug)
AND ((? AND a.provision_status IN ('pending','failed','disabled','conflict'))
 OR (? AND a.provision_status='conflict' AND NOT EXISTS(SELECT 1 FROM dsm_mapping_entries m WHERE m.mapping_type='user' AND m.dsm_account_id=a.id))
 OR (? AND EXISTS(SELECT 1 FROM dsm_mapping_entries m JOIN external_accounts e ON e.id=m.external_account_id
 WHERE m.mapping_type='user' AND m.dsm_account_id=a.id AND m.provider_slug=t.source_slug AND e.provider_slug=t.source_slug AND e.app_identity_id=a.app_identity_id AND (?='' OR e.subject=?)))))`,
			request.SourceSlug, request.RunID, request.AccountID, request.Username, request.Action == "cleanup_absent", request.Action == "cleanup_conflict", request.Action == "cleanup_user", subject, subject).Scan(&ok)
		return ok, err
	}
	if q != nil && (request.Action == "restore_sync_disable" || request.Action == "disable_missing_user") {
		var allowed bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dsm_accounts a
JOIN app_identities i ON i.id=a.app_identity_id
JOIN dsm_mapping_entries m ON m.mapping_type='user' AND m.dsm_account_id=a.id
JOIN external_accounts e ON e.id=m.external_account_id AND e.provider_slug=m.provider_slug AND e.app_identity_id=i.id
JOIN identity_sources s ON s.slug=m.provider_slug AND s.enabled=1 AND s.directory_sync_enabled=1
WHERE a.id=? AND a.dsm_username=? AND s.slug=? AND e.subject=? AND e.subject<>'' AND COALESCE(a.conflict_reason,'')=''
AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries other WHERE other.mapping_type='user' AND other.dsm_account_id=a.id AND other.active=1 AND other.id<>m.id)
AND ((? AND m.active=1 AND e.active=1 AND i.status='active' AND a.manual_login_blocked=0
 AND a.provision_status IN ('disabled','pending','failed','created','linked_existing'))
 OR (? AND m.active=0 AND s.provider_type<>'dingtalk' AND COALESCE(json_extract(s.config_json,'$.disable_missing_users'),1)=1
 AND EXISTS (SELECT 1 FROM sync_runs r WHERE r.id=? AND r.source_slug=s.slug AND r.status='running' AND r.dry_run=0))))`,
			request.AccountID, request.Username, request.SourceSlug, request.Subject, request.Action == "restore_sync_disable", request.Action == "disable_missing_user", request.RunID).Scan(&allowed)
		return allowed, err
	}
	if q != nil && (request.Action == "dingtalk_offboard" || request.Action == "dingtalk_offboard_absent") {
		var allowed bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 `+dingTalkOffboardingScope+`
        JOIN dingtalk_offboarding d ON d.source_slug=s.slug AND d.account_id=a.id AND d.subject=e.subject
        JOIN sync_runs r ON r.id=d.run_id AND r.source_slug=s.slug AND r.dry_run=0 AND r.status='running'
        AND r.rowid=(SELECT MAX(latest.rowid) FROM sync_runs latest WHERE latest.source_slug=s.slug AND latest.dry_run=0)
        WHERE `+dingTalkOffboardingEligible+` AND (NOT ? OR a.provision_status IN ('pending','failed'))
        AND (? OR NOT EXISTS (SELECT 1 FROM external_accounts live WHERE live.provider_slug=s.slug AND live.active=1 AND lower(trim(live.display_name))=a.dsm_username_norm))
        AND d.run_id=? AND s.slug=? AND a.id=? AND a.dsm_username=? AND e.subject=?)`,
			request.Action == "dingtalk_offboard_absent", request.CredentialOwner != nil || request.Action == "dingtalk_offboard_absent", request.RunID, request.SourceSlug, request.AccountID, request.Username, request.Subject).Scan(&allowed)
		return allowed, err
	}
	if q != nil && request.Action == "dingtalk_member" {
		var allowed bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 `+directoryMembershipScope+`
		 AND `+uniqueDingTalkName+` AND a.dsm_username=? AND g.dsm_groupname=? AND src.slug=? AND e.subject=?)`,
			request.Username, request.Groupname, request.SourceSlug, request.Subject).Scan(&allowed)
		return allowed, err
	}
	if q != nil && (request.Action == "directory_member" || request.Action == "other_directory_member") && request.Username != "" && request.Groupname != "" {
		var mapped bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 `+directoryMembershipScope+` AND a.dsm_username = ? AND g.dsm_groupname = ? AND (src.provider_type<>'dingtalk' OR (? AND `+uniqueDingTalkName+`)))`, request.Username, request.Groupname, request.Action == "directory_member").Scan(&mapped)
		return mapped, err
	}
	if q != nil && request.Action == "directory_group" && request.Groupname != "" {
		var mapped bool
		err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_groups g
 JOIN dsm_mapping_entries me ON me.dsm_group_id = g.id AND me.mapping_type = 'group' AND me.active = 1
 JOIN provider_groups pg ON pg.id = me.provider_group_id AND pg.provider_slug = me.provider_slug
 JOIN identity_sources src ON src.slug = me.provider_slug
 WHERE g.dsm_groupname = ? AND g.provision_status IN ('pending','failed','created','linked_existing')
   AND pg.active = 1 AND src.enabled = 1 AND src.directory_sync_enabled = 1
)`, request.Groupname).Scan(&mapped)
		return mapped, err
	}
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
 SELECT 1 `+provisionIdentityScope+` AND a.dsm_username=?
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

func verifiedOwnerAllowed(ctx context.Context, q *Queries, request HelperAuthorizationQuery, owner CredentialIdentity) (bool, error) {
	var valid bool
	err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
 JOIN dsm_mapping_entries m ON m.dsm_account_id=a.id AND m.mapping_type='user' AND m.active=1
 JOIN external_accounts e ON e.id=m.external_account_id AND e.app_identity_id=i.id AND e.provider_slug=m.provider_slug AND e.active=1
 JOIN identity_sources src ON src.slug=m.provider_slug AND src.enabled=1
 WHERE a.dsm_username=? AND COALESCE(a.conflict_reason,'')='' AND (a.provision_status IN ('created','linked_existing','pending','failed') OR (a.provision_status='disabled' AND ?='provision'))
 AND m.provider_slug=? AND e.subject=? AND (?='' OR (src.directory_sync_enabled=1 AND NOT (`+unresolvedDingTalkNamesake+`) AND e.email_verified=1 AND e.email_norm=?
 AND NOT EXISTS (SELECT 1 FROM external_accounts x WHERE x.active=1 AND x.email_norm=e.email_norm AND x.id<>e.id)))
 AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries other JOIN external_accounts x ON x.id=other.external_account_id AND x.active=1
 JOIN identity_sources other_src ON other_src.slug=other.provider_slug AND other_src.enabled=1
 WHERE other.mapping_type='user' AND other.active=1 AND other.dsm_account_id=a.id AND other.id<>m.id)
  AND (? <> 'login' OR (src.login_enabled=1 AND i.id=? AND a.allow_login=1 AND a.manual_login_blocked=0 AND a.provision_status IN ('created','linked_existing')))
 AND (? <> 'password_reset' OR (src.directory_sync_enabled=1 AND a.id=? AND a.provision_status IN ('created','linked_existing')))
 )`, request.Username, request.Action, owner.SourceSlug, owner.Subject, request.VerifiedEmail, request.VerifiedEmail, request.Action, request.IdentityID, request.Action, request.AccountID).Scan(&valid)
	return valid, err
}
