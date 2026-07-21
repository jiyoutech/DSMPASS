package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

type ExternalProfile struct {
	ProviderSlug  string
	Subject       string
	SubjectType   string
	DisplayName   string
	Email         string
	EmailVerified *bool
	Mobile        string
	AvatarURL     string
	Active        *bool
}

type Service struct {
	cfg config.BackendConfig
	q   *db.Queries
}

func NewService(cfg config.BackendConfig, q *db.Queries) *Service {
	return &Service{cfg: cfg, q: q}
}

func (s *Service) UpsertProfile(ctx context.Context, profile ExternalProfile) (db.ExternalAccount, error) {
	subjectNorm := Normalize(profile.Subject)
	emailNorm := Normalize(profile.Email)
	existing, err := s.getExternalBySubject(ctx, profile.ProviderSlug, subjectNorm)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return db.ExternalAccount{}, err
	}
	id := existing.ID
	if id == "" {
		id = uuid.NewString()
	}
	emailVerified := sql.NullInt64{}
	if profile.EmailVerified != nil {
		emailVerified = sql.NullInt64{Int64: boolInt(*profile.EmailVerified), Valid: true}
	}
	active := int64(1)
	if profile.Active != nil {
		active = boolInt(*profile.Active)
	}
	_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO external_accounts (
	id, provider_slug, subject, subject_norm, subject_type, app_identity_id,
	display_name, email, email_norm, email_verified, mobile_masked, avatar_url,
	active, last_seen_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(provider_slug, subject_norm) DO UPDATE SET
	subject = excluded.subject,
	subject_type = excluded.subject_type,
	display_name = excluded.display_name,
	email = excluded.email,
	email_norm = excluded.email_norm,
	email_verified = excluded.email_verified,
	mobile_masked = excluded.mobile_masked,
	avatar_url = excluded.avatar_url,
	active = excluded.active,
	last_seen_at = CURRENT_TIMESTAMP,
	updated_at = CURRENT_TIMESTAMP
`,
		id,
		profile.ProviderSlug,
		profile.Subject,
		subjectNorm,
		profile.SubjectType,
		existing.AppIdentityID,
		nullString(profile.DisplayName),
		nullString(profile.Email),
		nullString(emailNorm),
		emailVerified,
		nullString(maskMobile(profile.Mobile)),
		nullString(profile.AvatarURL),
		active,
	)
	if err != nil {
		return db.ExternalAccount{}, err
	}
	return s.getExternalBySubject(ctx, profile.ProviderSlug, subjectNorm)
}

func (s *Service) ResolveOrCreateIdentity(ctx context.Context, external db.ExternalAccount) (db.AppIdentity, error) {
	identity, _, err := s.ResolveOrCreateIdentityWithLinkedExisting(ctx, external)
	return identity, err
}

func (s *Service) ResolveOrCreateIdentityWithLinkedExisting(ctx context.Context, external db.ExternalAccount) (db.AppIdentity, bool, error) {
	if external.AppIdentityID.Valid {
		identity, err := s.getIdentity(ctx, external.AppIdentityID.String)
		if err == nil {
			return identity, false, nil
		}
	}
	if username, err := s.allocateUsernameForDisplayName(external.DisplayName); err == nil {
		existing, existingErr := s.getDSMAccountByNorm(ctx, Normalize(username))
		if existingErr == nil {
			hasSameProvider, err := s.identityHasProvider(ctx, existing.AppIdentityID, external.ProviderSlug)
			if err != nil {
				return db.AppIdentity{}, false, err
			}
			hasDifferentProvider, err := s.identityHasDifferentProvider(ctx, existing.AppIdentityID, external.ProviderSlug)
			if err != nil {
				return db.AppIdentity{}, false, err
			}
			if hasDifferentProvider && !hasSameProvider {
				if err := s.linkExternalToIdentity(ctx, external.ID, existing.AppIdentityID); err != nil {
					return db.AppIdentity{}, false, err
				}
				identity, err := s.getIdentity(ctx, existing.AppIdentityID)
				return identity, true, err
			}
		} else if !errors.Is(existingErr, sql.ErrNoRows) {
			return db.AppIdentity{}, false, existingErr
		}
	}
	id := uuid.NewString()
	_, err := s.q.DBTX().ExecContext(ctx, `
	INSERT INTO app_identities (id, display_name, primary_email, primary_email_norm, status, created_by, created_at, updated_at)
	VALUES (?, ?, ?, ?, 'active', 'system', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, id, external.DisplayName, external.Email, external.EmailNorm)
	if err != nil {
		return db.AppIdentity{}, false, err
	}
	if err := s.linkExternalToIdentity(ctx, external.ID, id); err != nil {
		return db.AppIdentity{}, false, err
	}
	identity, err := s.getIdentity(ctx, id)
	return identity, false, err
}

func (s *Service) EnsureDSMAccount(ctx context.Context, identity db.AppIdentity) (db.DSMAccount, error) {
	account, _, err := s.EnsureDSMAccountWithCreated(ctx, identity)
	return account, err
}

func (s *Service) EnsureDSMAccountWithCreated(ctx context.Context, identity db.AppIdentity) (db.DSMAccount, bool, error) {
	account, err := s.getDSMAccountByIdentity(ctx, identity.ID)
	if err == nil {
		return account, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.DSMAccount{}, false, err
	}
	username, err := s.allocateUsername(ctx, identity)
	if err != nil {
		return db.DSMAccount{}, false, err
	}
	status := "pending"
	allowLogin := 1
	conflictReason := sql.NullString{}
	if existing, existingErr := s.getDSMAccountByNorm(ctx, Normalize(username)); existingErr == nil && existing.AppIdentityID != identity.ID {
		providerName := s.providerDisplayNameForIdentity(ctx, identity.ID)
		status = "conflict"
		allowLogin = 0
		conflictReason = sql.NullString{String: fmt.Sprintf("冲突类型：DSM Pass 内已有身份占用 DSM 用户名 %q。请根据%s身份信息手动指定最终 DSM 用户名", username, providerName), Valid: true}
		username = conflictUsername(username, identity.ID)
	} else if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return db.DSMAccount{}, false, existingErr
	}
	id := uuid.NewString()
	_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, conflict_reason, allow_login, created_at, updated_at)
VALUES (?, ?, ?, ?, 1, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, id, identity.ID, username, Normalize(username), status, conflictReason, allowLogin)
	if err != nil {
		return db.DSMAccount{}, false, err
	}
	account, err = s.getDSMAccount(ctx, id)
	return account, true, err
}

func (s *Service) MarkDSMAccountConflict(ctx context.Context, id, reason string) (db.DSMAccount, error) {
	_, err := s.q.DBTX().ExecContext(ctx, `
UPDATE dsm_accounts SET provision_status = 'conflict', conflict_reason = ?, allow_login = 0, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND (provision_status <> 'conflict' OR conflict_reason IS NULL OR conflict_reason <> ? OR allow_login <> 0)
`, reason, id, reason)
	if err != nil {
		return db.DSMAccount{}, err
	}
	return s.getDSMAccount(ctx, id)
}

func (s *Service) ResolveAuthorizedLogin(ctx context.Context, providerSlug, subject string) (db.ExternalAccount, db.AppIdentity, db.DSMAccount, error) {
	external, err := s.getExternalBySubject(ctx, providerSlug, Normalize(subject))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.ExternalAccount{}, db.AppIdentity{}, db.DSMAccount{}, errors.New("identity not synchronized")
		}
		return db.ExternalAccount{}, db.AppIdentity{}, db.DSMAccount{}, err
	}
	if external.Active == 0 {
		return external, db.AppIdentity{}, db.DSMAccount{}, errors.New("external account inactive")
	}
	if !external.AppIdentityID.Valid || strings.TrimSpace(external.AppIdentityID.String) == "" {
		return external, db.AppIdentity{}, db.DSMAccount{}, errors.New("identity not linked")
	}
	appIdentity, err := s.getIdentity(ctx, external.AppIdentityID.String)
	if err != nil {
		return external, db.AppIdentity{}, db.DSMAccount{}, err
	}
	if appIdentity.Status != "active" {
		return external, appIdentity, db.DSMAccount{}, errors.New("identity inactive")
	}
	account, err := s.getDSMAccountByIdentity(ctx, appIdentity.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return external, appIdentity, db.DSMAccount{}, errors.New("DSM account not synchronized")
		}
		return external, appIdentity, db.DSMAccount{}, err
	}
	if account.AllowLogin == 0 {
		return external, appIdentity, account, errors.New("login not allowed")
	}
	if account.ProvisionStatus != "created" && account.ProvisionStatus != "linked_existing" {
		return external, appIdentity, account, errors.New("DSM account not provisioned")
	}
	return external, appIdentity, account, nil
}

func (s *Service) EnsureProviderGroup(ctx context.Context, providerSlug, subject, parentSubject, name, path string) (db.ProviderGroup, error) {
	subjectNorm := Normalize(subject)
	existing, err := s.getProviderGroupBySubject(ctx, providerSlug, subjectNorm)
	id := ""
	if err == nil {
		id = existing.ID
	} else if !errors.Is(err, sql.ErrNoRows) {
		return db.ProviderGroup{}, err
	}
	if id == "" {
		id = uuid.NewString()
	}
	_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO provider_groups (id, provider_slug, subject, subject_norm, parent_subject, name, path, active, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(provider_slug, subject_norm) DO UPDATE SET
	parent_subject = excluded.parent_subject,
	name = excluded.name,
	path = excluded.path,
	active = 1,
	updated_at = CURRENT_TIMESTAMP
`, id, providerSlug, subject, subjectNorm, nullString(parentSubject), name, nullString(path))
	if err != nil {
		return db.ProviderGroup{}, err
	}
	return s.getProviderGroupBySubject(ctx, providerSlug, subjectNorm)
}

func (s *Service) EnsureDSMGroup(ctx context.Context, providerGroup db.ProviderGroup) (db.DSMGroup, error) {
	group, _, err := s.EnsureDSMGroupWithLinkedExisting(ctx, providerGroup)
	return group, err
}

func (s *Service) EnsureDSMGroupWithLinkedExisting(ctx context.Context, providerGroup db.ProviderGroup) (db.DSMGroup, bool, error) {
	groupName, err := SanitizeGroupName(providerGroup.Name)
	if err != nil {
		return db.DSMGroup{}, false, err
	}
	groupNorm := Normalize(groupName)
	linked, err := s.getDSMGroupByProviderGroup(ctx, providerGroup.ID)
	if err == nil {
		if linked.Managed == 1 && linked.DSMGroupnameNorm != groupNorm {
			existing, existingErr := s.getDSMGroupByNorm(ctx, groupNorm)
			if existingErr == nil && existing.ID != linked.ID {
				canLink, err := s.canLinkGroupToDifferentProvider(ctx, existing.ID, providerGroup.ProviderSlug)
				if err != nil {
					return db.DSMGroup{}, false, err
				}
				if canLink {
					if err := s.relinkProviderGroup(ctx, providerGroup.ID, linked.ID, existing.ID); err != nil {
						return db.DSMGroup{}, false, err
					}
					return existing, true, nil
				}
				_, _ = s.q.DBTX().ExecContext(ctx, `
	UPDATE dsm_groups SET provision_status = 'conflict', conflict_reason = 'provider group name maps to existing DSM group', updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, linked.ID)
				group, err := s.getDSMGroup(ctx, linked.ID)
				return group, false, err
			}
			if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
				return db.DSMGroup{}, false, existingErr
			}
			linkCount, err := s.countGroupLinks(ctx, linked.ID)
			if err != nil {
				return db.DSMGroup{}, false, err
			}
			if linkCount > 1 {
				id := uuid.NewString()
				_, err = s.q.DBTX().ExecContext(ctx, `
	INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, managed, provision_status, created_at, updated_at)
	VALUES (?, ?, ?, 1, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, id, groupName, groupNorm)
				if err != nil {
					return db.DSMGroup{}, false, err
				}
				_, err = s.q.DBTX().ExecContext(ctx, `
	UPDATE group_links SET dsm_group_id = ?, updated_at = CURRENT_TIMESTAMP WHERE provider_group_id = ? AND dsm_group_id = ?
	`, id, providerGroup.ID, linked.ID)
				if err != nil {
					return db.DSMGroup{}, false, err
				}
				group, err := s.getDSMGroup(ctx, id)
				return group, false, err
			}
			_, err = s.q.DBTX().ExecContext(ctx, `
	UPDATE dsm_groups
	SET dsm_groupname = ?, dsm_groupname_norm = ?, provision_status = 'pending', conflict_reason = NULL, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?
	`, groupName, groupNorm, linked.ID)
			if err != nil {
				return db.DSMGroup{}, false, err
			}
			group, err := s.getDSMGroup(ctx, linked.ID)
			return group, false, err
		}
		return linked, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.DSMGroup{}, false, err
	}
	existing, err := s.getDSMGroupByNorm(ctx, groupNorm)
	if err == nil {
		canLink, linkErr := s.canLinkGroupToDifferentProvider(ctx, existing.ID, providerGroup.ProviderSlug)
		if linkErr != nil {
			return db.DSMGroup{}, false, linkErr
		}
		if canLink {
			return existing, true, nil
		}
		_, _ = s.q.DBTX().ExecContext(ctx, `
	UPDATE dsm_groups SET provision_status = 'conflict', conflict_reason = 'provider group name maps to existing DSM group', updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, existing.ID)
		group, err := s.getDSMGroup(ctx, existing.ID)
		return group, false, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.DSMGroup{}, false, err
	}
	id := uuid.NewString()
	_, err = s.q.DBTX().ExecContext(ctx, `
	INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, managed, provision_status, created_at, updated_at)
	VALUES (?, ?, ?, 1, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, id, groupName, groupNorm)
	if err != nil {
		return db.DSMGroup{}, false, err
	}
	group, err := s.getDSMGroup(ctx, id)
	return group, false, err
}

func (s *Service) MarkDSMGroupConflict(ctx context.Context, id, reason string) (db.DSMGroup, error) {
	_, err := s.q.DBTX().ExecContext(ctx, `
UPDATE dsm_groups SET provision_status = 'conflict', conflict_reason = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND (provision_status <> 'conflict' OR conflict_reason IS NULL OR conflict_reason <> ?)
`, reason, id, reason)
	if err != nil {
		return db.DSMGroup{}, err
	}
	return s.getDSMGroup(ctx, id)
}

func (s *Service) EnsureGroupLink(ctx context.Context, providerGroupID, dsmGroupID string) error {
	_, err := s.q.DBTX().ExecContext(ctx, `
	INSERT OR IGNORE INTO group_links (id, provider_group_id, dsm_group_id, link_mode, created_at, updated_at)
	VALUES (?, ?, ?, 'managed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, uuid.NewString(), providerGroupID, dsmGroupID)
	return err
}

func (s *Service) EnsureDSMUserMapping(ctx context.Context, providerSlug, externalAccountID, dsmAccountID string) error {
	return s.ensureDSMMapping(ctx, "user", providerSlug, externalAccountID, "", dsmAccountID, "")
}

func (s *Service) EnsureDSMGroupMapping(ctx context.Context, providerSlug, providerGroupID, dsmGroupID string) error {
	return s.ensureDSMMapping(ctx, "group", providerSlug, "", providerGroupID, "", dsmGroupID)
}

func (s *Service) EnsureDSMMemberMapping(ctx context.Context, providerSlug, providerGroupID, memberSubject, dsmGroupID, dsmAccountID string) error {
	externalID, err := s.externalIDBySubject(ctx, providerSlug, Normalize(memberSubject))
	if err != nil {
		return err
	}
	return s.ensureDSMMapping(ctx, "member", providerSlug, externalID, providerGroupID, dsmAccountID, dsmGroupID)
}

func (s *Service) ensureDSMMapping(ctx context.Context, mappingType, providerSlug, externalAccountID, providerGroupID, dsmAccountID, dsmGroupID string) error {
	_, err := s.q.DBTX().ExecContext(ctx, `
INSERT INTO dsm_mapping_entries (
	id, mapping_type, provider_slug, external_account_id, provider_group_id,
	dsm_account_id, dsm_group_id, active, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(mapping_type, provider_slug, external_account_id, provider_group_id) DO UPDATE SET
	dsm_account_id = excluded.dsm_account_id,
	dsm_group_id = excluded.dsm_group_id,
	active = 1,
	updated_at = CURRENT_TIMESTAMP
`, uuid.NewString(), mappingType, providerSlug, externalAccountID, providerGroupID, nullString(dsmAccountID), nullString(dsmGroupID))
	return err
}

func (s *Service) DeactivateStaleMappings(ctx context.Context, providerSlug, syncStart string, mappingTypes ...string) error {
	if strings.TrimSpace(syncStart) == "" {
		return nil
	}
	if len(mappingTypes) > 0 {
		for _, mappingType := range mappingTypes {
			if strings.TrimSpace(mappingType) == "" {
				continue
			}
			if _, err := s.q.DBTX().ExecContext(ctx, `
	UPDATE dsm_mapping_entries
	SET active = 0, updated_at = CURRENT_TIMESTAMP
	WHERE provider_slug = ? AND mapping_type = ? AND active = 1 AND updated_at < ?`, providerSlug, mappingType, syncStart); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := s.q.DBTX().ExecContext(ctx, `
UPDATE dsm_mapping_entries
SET active = 0, updated_at = CURRENT_TIMESTAMP
WHERE provider_slug = ? AND active = 1 AND updated_at < ?`, providerSlug, syncStart)
	return err
}

func (s *Service) ReconcileFinalGroupMembers(ctx context.Context) error {
	_, err := s.q.DBTX().ExecContext(ctx, `
UPDATE group_members
SET active = 0,
	provision_status = CASE
		WHEN provision_status IN ('removed') THEN provision_status
		ELSE 'disabled'
	END,
	updated_at = CURRENT_TIMESTAMP
WHERE active = 1
  AND NOT EXISTS (
	SELECT 1
	FROM dsm_mapping_entries me
	WHERE me.mapping_type = 'member'
	  AND me.active = 1
	  AND me.dsm_group_id = group_members.dsm_group_id
	  AND me.dsm_account_id = group_members.dsm_account_id
  )`)
	if err != nil {
		return err
	}
	_, err = s.q.DBTX().ExecContext(ctx, `
UPDATE group_members
SET active = 1,
	provision_status = CASE
		WHEN provision_status IN ('disabled', 'remove_pending', 'remove_failed', 'removed') THEN 'pending'
		ELSE provision_status
	END,
	updated_at = CURRENT_TIMESTAMP
WHERE active = 0
  AND EXISTS (
	SELECT 1
	FROM dsm_mapping_entries me
	WHERE me.mapping_type = 'member'
	  AND me.active = 1
	  AND me.dsm_group_id = group_members.dsm_group_id
	  AND me.dsm_account_id = group_members.dsm_account_id
  )`)
	return err
}

func (s *Service) EnsureGroupMember(ctx context.Context, dsmGroupID, dsmAccountID string) (db.GroupMember, error) {
	existing, err := s.getGroupMember(ctx, dsmGroupID, dsmAccountID)
	if err == nil {
		_, err = s.q.DBTX().ExecContext(ctx, `
UPDATE group_members
SET active = 1,
	provision_status = CASE
		WHEN provision_status IN ('disabled', 'remove_pending', 'remove_failed', 'removed') THEN 'pending'
		ELSE provision_status
	END,
	updated_at = CURRENT_TIMESTAMP
WHERE id = ?
`, existing.ID)
		if err != nil {
			return db.GroupMember{}, err
		}
		return s.getGroupMemberByID(ctx, existing.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.GroupMember{}, err
	}
	id := uuid.NewString()
	_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO group_members (id, dsm_group_id, dsm_account_id, provision_status, created_at, updated_at)
VALUES (?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(dsm_group_id, dsm_account_id) DO UPDATE SET
	active = 1,
	provision_status = CASE
		WHEN provision_status IN ('disabled', 'remove_pending', 'remove_failed', 'removed') THEN 'pending'
		ELSE provision_status
	END,
	updated_at = CURRENT_TIMESTAMP
`, id, dsmGroupID, dsmAccountID)
	if err != nil {
		return db.GroupMember{}, err
	}
	return s.getGroupMemberByID(ctx, id)
}

func (s *Service) ExternalToDSMAccounts(ctx context.Context, providerSlug string) (map[string]db.DSMAccount, error) {
	rows, err := s.q.DBTX().QueryContext(ctx, `
SELECT e.subject, a.id, a.app_identity_id, a.dsm_username, a.dsm_username_norm, a.managed, a.provision_status, a.conflict_reason, a.allow_login, a.created_at, a.updated_at
FROM external_accounts e
JOIN dsm_accounts a ON a.app_identity_id = e.app_identity_id
WHERE e.provider_slug = ?
`, providerSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]db.DSMAccount{}
	for rows.Next() {
		var subject string
		var account db.DSMAccount
		if err := rows.Scan(&subject, &account.ID, &account.AppIdentityID, &account.DSMUsername, &account.DSMUsernameNorm, &account.Managed, &account.ProvisionStatus, &account.ConflictReason, &account.AllowLogin, &account.CreatedAt, &account.UpdatedAt); err != nil {
			return nil, err
		}
		result[subject] = account
	}
	return result, rows.Err()
}

func (s *Service) ProviderGroupsToDSMGroups(ctx context.Context, providerSlug string) (map[string]db.DSMGroup, error) {
	rows, err := s.q.DBTX().QueryContext(ctx, `
SELECT p.subject, g.id, g.dsm_groupname, g.dsm_groupname_norm, g.managed, g.provision_status, g.conflict_reason, g.created_at, g.updated_at
FROM provider_groups p
JOIN group_links l ON l.provider_group_id = p.id
JOIN dsm_groups g ON g.id = l.dsm_group_id
WHERE p.provider_slug = ?
`, providerSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]db.DSMGroup{}
	for rows.Next() {
		var subject string
		var group db.DSMGroup
		if err := rows.Scan(&subject, &group.ID, &group.DSMGroupname, &group.DSMGroupnameNorm, &group.Managed, &group.ProvisionStatus, &group.ConflictReason, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		result[subject] = group
	}
	return result, rows.Err()
}

func (s *Service) allocateUsername(ctx context.Context, identity db.AppIdentity) (string, error) {
	username, err := s.allocateUsernameForDisplayName(identity.DisplayName)
	if err != nil {
		displayName := ""
		if identity.DisplayName.Valid {
			displayName = identity.DisplayName.String
		}
		providerName := s.providerDisplayNameForIdentity(ctx, identity.ID)
		return "", fmt.Errorf("DSM 用户名不可用：用户姓名 %q 清洗后为空，请确认%s返回真实姓名并且姓名包含 DSM 支持的字符", displayName, providerName)
	}
	return username, nil
}

func (s *Service) providerDisplayNameForIdentity(ctx context.Context, identityID string) string {
	var providerType, providerSlug string
	err := s.q.DBTX().QueryRowContext(ctx, `
SELECT COALESCE(i.provider_type, ''), e.provider_slug
FROM external_accounts e
LEFT JOIN identity_sources i ON i.slug = e.provider_slug
WHERE e.app_identity_id = ?
ORDER BY e.created_at
LIMIT 1`, identityID).Scan(&providerType, &providerSlug)
	if err != nil {
		return "身份源"
	}
	if strings.TrimSpace(providerType) == "" {
		providerType = providerSlug
	}
	return providerDisplayName(providerType)
}

func providerDisplayName(providerType string) string {
	providerType = strings.TrimSpace(providerType)
	switch providerType {
	case "feishu":
		return "飞书"
	case "wecom":
		return "企业微信"
	case "dingtalk":
		return "钉钉"
	default:
		if strings.HasPrefix(providerType, "feishu") {
			return "飞书"
		}
		if strings.HasPrefix(providerType, "wecom") {
			return "企业微信"
		}
		if strings.HasPrefix(providerType, "dingtalk") {
			return "钉钉"
		}
		return "身份源"
	}
}

func (s *Service) allocateUsernameForDisplayName(displayName sql.NullString) (string, error) {
	value := ""
	if displayName.Valid {
		value = displayName.String
	}
	return GenerateRequiredSequentialReadableUsername(value, s.cfg.UsernameReadableDelimiter, 1, DSMUsernameMaxLength)
}

func conflictUsername(username, identityID string) string {
	suffixSource := strings.ReplaceAll(identityID, "-", "")
	if len(suffixSource) > 8 {
		suffixSource = suffixSource[:8]
	}
	if suffixSource == "" {
		suffixSource = "manual"
	}
	suffix := "_conflict_" + suffixSource
	runes := []rune(strings.Trim(username, "._-"))
	baseLimit := DSMUsernameMaxLength - len([]rune(suffix))
	if baseLimit < 1 {
		baseLimit = 1
	}
	if len(runes) > baseLimit {
		runes = runes[:baseLimit]
	}
	base := strings.Trim(string(runes), "._-")
	if base == "" {
		base = "user"
	}
	return base + suffix
}

func (s *Service) getExternalBySubject(ctx context.Context, providerSlug, subjectNorm string) (db.ExternalAccount, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `
SELECT id, provider_slug, subject, subject_norm, subject_type, app_identity_id, display_name, email, email_norm, email_verified, mobile_masked, avatar_url, active, last_login_at, last_seen_at, created_at, updated_at
FROM external_accounts WHERE provider_slug = ? AND subject_norm = ?
`, providerSlug, subjectNorm)
	var item db.ExternalAccount
	err := row.Scan(&item.ID, &item.ProviderSlug, &item.Subject, &item.SubjectNorm, &item.SubjectType, &item.AppIdentityID, &item.DisplayName, &item.Email, &item.EmailNorm, &item.EmailVerified, &item.MobileMasked, &item.AvatarURL, &item.Active, &item.LastLoginAt, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) externalIDBySubject(ctx context.Context, providerSlug, subjectNorm string) (string, error) {
	var id string
	err := s.q.DBTX().QueryRowContext(ctx, `SELECT id FROM external_accounts WHERE provider_slug = ? AND subject_norm = ?`, providerSlug, subjectNorm).Scan(&id)
	return id, err
}

func (s *Service) getIdentity(ctx context.Context, id string) (db.AppIdentity, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, display_name, primary_email, primary_email_norm, status, created_by, created_at, updated_at FROM app_identities WHERE id = ?`, id)
	var item db.AppIdentity
	err := row.Scan(&item.ID, &item.DisplayName, &item.PrimaryEmail, &item.PrimaryEmailNorm, &item.Status, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) linkExternalToIdentity(ctx context.Context, externalID, identityID string) error {
	_, err := s.q.DBTX().ExecContext(ctx, `
	UPDATE external_accounts SET app_identity_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, identityID, externalID)
	return err
}

func (s *Service) identityHasProvider(ctx context.Context, identityID, providerSlug string) (bool, error) {
	var count int
	err := s.q.DBTX().QueryRowContext(ctx, `SELECT COUNT(*) FROM external_accounts WHERE app_identity_id = ? AND provider_slug = ?`, identityID, providerSlug).Scan(&count)
	return count > 0, err
}

func (s *Service) identityHasDifferentProvider(ctx context.Context, identityID, providerSlug string) (bool, error) {
	var count int
	err := s.q.DBTX().QueryRowContext(ctx, `SELECT COUNT(*) FROM external_accounts WHERE app_identity_id = ? AND provider_slug <> ?`, identityID, providerSlug).Scan(&count)
	return count > 0, err
}

func (s *Service) getDSMAccount(ctx context.Context, id string) (db.DSMAccount, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, conflict_reason, allow_login, created_at, updated_at FROM dsm_accounts WHERE id = ?`, id)
	var item db.DSMAccount
	err := row.Scan(&item.ID, &item.AppIdentityID, &item.DSMUsername, &item.DSMUsernameNorm, &item.Managed, &item.ProvisionStatus, &item.ConflictReason, &item.AllowLogin, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getDSMAccountByIdentity(ctx context.Context, identityID string) (db.DSMAccount, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, conflict_reason, allow_login, created_at, updated_at FROM dsm_accounts WHERE app_identity_id = ?`, identityID)
	var item db.DSMAccount
	err := row.Scan(&item.ID, &item.AppIdentityID, &item.DSMUsername, &item.DSMUsernameNorm, &item.Managed, &item.ProvisionStatus, &item.ConflictReason, &item.AllowLogin, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getDSMAccountByNorm(ctx context.Context, norm string) (db.DSMAccount, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, app_identity_id, dsm_username, dsm_username_norm, managed, provision_status, conflict_reason, allow_login, created_at, updated_at FROM dsm_accounts WHERE dsm_username_norm = ?`, norm)
	var item db.DSMAccount
	err := row.Scan(&item.ID, &item.AppIdentityID, &item.DSMUsername, &item.DSMUsernameNorm, &item.Managed, &item.ProvisionStatus, &item.ConflictReason, &item.AllowLogin, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getProviderGroupBySubject(ctx context.Context, providerSlug, subjectNorm string) (db.ProviderGroup, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, provider_slug, subject, subject_norm, parent_subject, name, path, active, created_at, updated_at FROM provider_groups WHERE provider_slug = ? AND subject_norm = ?`, providerSlug, subjectNorm)
	var item db.ProviderGroup
	err := row.Scan(&item.ID, &item.ProviderSlug, &item.Subject, &item.SubjectNorm, &item.ParentSubject, &item.Name, &item.Path, &item.Active, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) countGroupLinks(ctx context.Context, dsmGroupID string) (int, error) {
	var count int
	err := s.q.DBTX().QueryRowContext(ctx, `SELECT COUNT(*) FROM group_links WHERE dsm_group_id = ?`, dsmGroupID).Scan(&count)
	return count, err
}

func (s *Service) canLinkGroupToDifferentProvider(ctx context.Context, dsmGroupID, providerSlug string) (bool, error) {
	var sameProviderLinks, differentProviderLinks int
	err := s.q.DBTX().QueryRowContext(ctx, `
SELECT
	COUNT(CASE WHEN p.provider_slug = ? THEN 1 END),
	COUNT(CASE WHEN p.provider_slug <> ? THEN 1 END)
FROM group_links l
JOIN provider_groups p ON p.id = l.provider_group_id
WHERE l.dsm_group_id = ?`, providerSlug, providerSlug, dsmGroupID).Scan(&sameProviderLinks, &differentProviderLinks)
	if err != nil {
		return false, err
	}
	return differentProviderLinks > 0 && sameProviderLinks == 0, nil
}

func (s *Service) relinkProviderGroup(ctx context.Context, providerGroupID, oldDSMGroupID, newDSMGroupID string) error {
	_, err := s.q.DBTX().ExecContext(ctx, `
UPDATE group_links SET dsm_group_id = ?, updated_at = CURRENT_TIMESTAMP
WHERE provider_group_id = ? AND dsm_group_id = ?`, newDSMGroupID, providerGroupID, oldDSMGroupID)
	return err
}

func (s *Service) getDSMGroup(ctx context.Context, id string) (db.DSMGroup, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, dsm_groupname, dsm_groupname_norm, managed, provision_status, conflict_reason, created_at, updated_at FROM dsm_groups WHERE id = ?`, id)
	var item db.DSMGroup
	err := row.Scan(&item.ID, &item.DSMGroupname, &item.DSMGroupnameNorm, &item.Managed, &item.ProvisionStatus, &item.ConflictReason, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getDSMGroupByNorm(ctx context.Context, norm string) (db.DSMGroup, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, dsm_groupname, dsm_groupname_norm, managed, provision_status, conflict_reason, created_at, updated_at FROM dsm_groups WHERE dsm_groupname_norm = ?`, norm)
	var item db.DSMGroup
	err := row.Scan(&item.ID, &item.DSMGroupname, &item.DSMGroupnameNorm, &item.Managed, &item.ProvisionStatus, &item.ConflictReason, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getDSMGroupByProviderGroup(ctx context.Context, providerGroupID string) (db.DSMGroup, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `
SELECT g.id, g.dsm_groupname, g.dsm_groupname_norm, g.managed, g.provision_status, g.conflict_reason, g.created_at, g.updated_at
FROM group_links l JOIN dsm_groups g ON g.id = l.dsm_group_id WHERE l.provider_group_id = ?
`, providerGroupID)
	var item db.DSMGroup
	err := row.Scan(&item.ID, &item.DSMGroupname, &item.DSMGroupnameNorm, &item.Managed, &item.ProvisionStatus, &item.ConflictReason, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getGroupMember(ctx context.Context, groupID, accountID string) (db.GroupMember, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, dsm_group_id, dsm_account_id, active, provision_status, created_at, updated_at FROM group_members WHERE dsm_group_id = ? AND dsm_account_id = ?`, groupID, accountID)
	var item db.GroupMember
	err := row.Scan(&item.ID, &item.DSMGroupID, &item.DSMAccountID, &item.Active, &item.ProvisionStatus, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Service) getGroupMemberByID(ctx context.Context, id string) (db.GroupMember, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, dsm_group_id, dsm_account_id, active, provision_status, created_at, updated_at FROM group_members WHERE id = ?`, id)
	var item db.GroupMember
	err := row.Scan(&item.ID, &item.DSMGroupID, &item.DSMAccountID, &item.Active, &item.ProvisionStatus, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func nullString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func maskMobile(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= 4 {
		return "****"
	}
	return string(runes[:2]) + "****" + string(runes[len(runes)-2:])
}
