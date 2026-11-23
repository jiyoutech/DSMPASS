package db

import (
	"context"
	"encoding/json"
	"errors"
)

const MaxGroupMembers = 200

// These constraints are populated from the Helper's local UID/GID policy.
type HelperMemberScope struct {
	Username   string               `json:"username"`
	DingTalk   *DingTalkUserBinding `json:"dingtalk,omitempty"`
	OtherGroup bool                 `json:"other_group,omitempty"`
}

// HelperAuthorizationQuery is a fixed query protocol, never a SQL interface.
// The root Helper runs it in a process with the package account's OS identity.
type HelperAuthorizationQuery struct {
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
	DingTalkBinding *DingTalkUserBinding      `json:"dingtalk_binding,omitempty"`
	Allowed         bool                      `json:"allowed"`
	Error           string                    `json:"error,omitempty"`
	Enrollment      *HelperEnrollmentSnapshot `json:"enrollment,omitempty"`
}

func HelperAccountAllowed(ctx context.Context, q *Queries, request HelperAuthorizationQuery) (bool, error) {
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

	if q != nil && request.Action == "dingtalk_offboard" {
		var allowed bool
		err := q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 `+dingTalkOffboardingScope+`
        JOIN dingtalk_offboarding d ON d.source_slug=s.slug AND d.account_id=a.id AND d.subject=e.subject
        JOIN sync_runs r ON r.id=d.run_id AND r.source_slug=s.slug AND r.dry_run=0 AND r.status='running'
        AND r.rowid=(SELECT MAX(latest.rowid) FROM sync_runs latest WHERE latest.source_slug=s.slug AND latest.dry_run=0)
        WHERE `+dingTalkOffboardingEligible+` AND d.run_id=? AND s.slug=? AND a.id=? AND a.dsm_username=? AND e.subject=?)`,
			request.RunID, request.SourceSlug, request.AccountID, request.Username, request.Subject).Scan(&allowed)
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

func verifiedOwnerAllowed(ctx context.Context, q *Queries, request HelperAuthorizationQuery, owner CredentialIdentity) (bool, error) {
	var valid bool
	err := q.DBTX().QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM dsm_accounts a JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
 JOIN dsm_mapping_entries m ON m.dsm_account_id=a.id AND m.mapping_type='user' AND m.active=1
 JOIN external_accounts e ON e.id=m.external_account_id AND e.app_identity_id=i.id AND e.provider_slug=m.provider_slug AND e.active=1
 JOIN identity_sources s ON s.slug=m.provider_slug AND s.enabled=1
 WHERE a.dsm_username=? AND COALESCE(a.conflict_reason,'')='' AND a.provision_status IN ('created','linked_existing','pending','failed')
 AND m.provider_slug=? AND e.subject=? AND (?='' OR (s.directory_sync_enabled=1 AND e.email_verified=1 AND e.email_norm=?
 AND NOT EXISTS (SELECT 1 FROM external_accounts x WHERE x.active=1 AND x.email_norm=e.email_norm AND x.id<>e.id)))
 AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries other JOIN external_accounts x ON x.id=other.external_account_id AND x.active=1
 JOIN identity_sources src ON src.slug=other.provider_slug AND src.enabled=1
 WHERE other.mapping_type='user' AND other.active=1 AND other.dsm_account_id=a.id AND other.id<>m.id)
  AND (? <> 'login' OR (s.login_enabled=1 AND i.id=? AND a.allow_login=1 AND a.provision_status IN ('created','linked_existing')))
 AND (? <> 'password_reset' OR (s.directory_sync_enabled=1 AND a.id=? AND a.provision_status IN ('created','linked_existing')))
 )`, request.Username, owner.SourceSlug, owner.Subject, request.VerifiedEmail, request.VerifiedEmail, request.Action, request.IdentityID, request.Action, request.AccountID).Scan(&valid)
	return valid, err
}
