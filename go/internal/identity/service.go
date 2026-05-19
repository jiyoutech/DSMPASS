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
	_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO external_accounts (
	id, provider_slug, subject, subject_norm, subject_type, app_identity_id,
	display_name, email, email_norm, email_verified, mobile_masked, avatar_url,
	active, last_seen_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(provider_slug, subject_norm) DO UPDATE SET
	subject = excluded.subject,
	subject_type = excluded.subject_type,
	display_name = excluded.display_name,
	email = excluded.email,
	email_norm = excluded.email_norm,
	email_verified = excluded.email_verified,
	mobile_masked = excluded.mobile_masked,
	avatar_url = excluded.avatar_url,
	active = 1,
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
	)
	if err != nil {
		return db.ExternalAccount{}, err
	}
	return s.getExternalBySubject(ctx, profile.ProviderSlug, subjectNorm)
}

func (s *Service) ResolveOrCreateIdentity(ctx context.Context, external db.ExternalAccount) (db.AppIdentity, error) {
	if external.AppIdentityID.Valid {
		identity, err := s.getIdentity(ctx, external.AppIdentityID.String)
		if err == nil {
			return identity, nil
		}
	}
	id := uuid.NewString()
	_, err := s.q.DBTX().ExecContext(ctx, `
INSERT INTO app_identities (id, display_name, primary_email, primary_email_norm, status, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, 'active', 'system', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, id, external.DisplayName, external.Email, external.EmailNorm)
	if err != nil {
		return db.AppIdentity{}, err
	}
	_, err = s.q.DBTX().ExecContext(ctx, `
UPDATE external_accounts SET app_identity_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
`, id, external.ID)
	if err != nil {
		return db.AppIdentity{}, err
	}
	return s.getIdentity(ctx, id)
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
		status = "conflict"
		allowLogin = 0
		conflictReason = sql.NullString{String: fmt.Sprintf("冲突类型：DSM Pass 内已有身份占用 DSM 用户名 %q。请根据飞书信息手动指定最终 DSM 用户名", username), Valid: true}
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
WHERE id = ? AND managed = 1 AND (provision_status <> 'conflict' OR conflict_reason IS NULL OR conflict_reason <> ? OR allow_login <> 0)
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
	groupName, err := SanitizeGroupName(providerGroup.Name)
	if err != nil {
		return db.DSMGroup{}, err
	}
	groupNorm := Normalize(groupName)
	linked, err := s.getDSMGroupByProviderGroup(ctx, providerGroup.ID)
	if err == nil {
		if linked.Managed == 1 && linked.DSMGroupnameNorm != groupNorm {
			existing, existingErr := s.getDSMGroupByNorm(ctx, groupNorm)
			if existingErr == nil && existing.ID != linked.ID {
				_, _ = s.q.DBTX().ExecContext(ctx, `
UPDATE dsm_groups SET provision_status = 'conflict', conflict_reason = 'provider group name maps to existing DSM group', updated_at = CURRENT_TIMESTAMP WHERE id = ?
`, linked.ID)
				return s.getDSMGroup(ctx, linked.ID)
			}
			if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
				return db.DSMGroup{}, existingErr
			}
			linkCount, err := s.countGroupLinks(ctx, linked.ID)
			if err != nil {
				return db.DSMGroup{}, err
			}
			if linkCount > 1 {
				id := uuid.NewString()
				_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, managed, provision_status, created_at, updated_at)
VALUES (?, ?, ?, 1, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, id, groupName, groupNorm)
				if err != nil {
					return db.DSMGroup{}, err
				}
				_, err = s.q.DBTX().ExecContext(ctx, `
UPDATE group_links SET dsm_group_id = ?, updated_at = CURRENT_TIMESTAMP WHERE provider_group_id = ? AND dsm_group_id = ?
`, id, providerGroup.ID, linked.ID)
				if err != nil {
					return db.DSMGroup{}, err
				}
				return s.getDSMGroup(ctx, id)
			}
			_, err = s.q.DBTX().ExecContext(ctx, `
UPDATE dsm_groups
SET dsm_groupname = ?, dsm_groupname_norm = ?, provision_status = 'pending', conflict_reason = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
`, groupName, groupNorm, linked.ID)
			if err != nil {
				return db.DSMGroup{}, err
			}
			return s.getDSMGroup(ctx, linked.ID)
		}
		return linked, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.DSMGroup{}, err
	}
	existing, err := s.getDSMGroupByNorm(ctx, groupNorm)
	if err == nil {
		_, _ = s.q.DBTX().ExecContext(ctx, `
UPDATE dsm_groups SET provision_status = 'conflict', conflict_reason = 'provider group name maps to existing DSM group', updated_at = CURRENT_TIMESTAMP WHERE id = ?
`, existing.ID)
		return s.getDSMGroup(ctx, existing.ID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return db.DSMGroup{}, err
	}
	id := uuid.NewString()
	_, err = s.q.DBTX().ExecContext(ctx, `
INSERT INTO dsm_groups (id, dsm_groupname, dsm_groupname_norm, managed, provision_status, created_at, updated_at)
VALUES (?, ?, ?, 1, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, id, groupName, groupNorm)
	if err != nil {
		return db.DSMGroup{}, err
	}
	return s.getDSMGroup(ctx, id)
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

func (s *Service) EnsureGroupMember(ctx context.Context, dsmGroupID, dsmAccountID string) (db.GroupMember, error) {
	existing, err := s.getGroupMember(ctx, dsmGroupID, dsmAccountID)
	if err == nil {
		_, err = s.q.DBTX().ExecContext(ctx, `
UPDATE group_members SET active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?
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
ON CONFLICT(dsm_group_id, dsm_account_id) DO UPDATE SET active = 1, updated_at = CURRENT_TIMESTAMP
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
	displayName := ""
	if identity.DisplayName.Valid {
		displayName = identity.DisplayName.String
	}
	username, err := GenerateRequiredSequentialReadableUsername(displayName, s.cfg.UsernameReadableDelimiter, 1, 32)
	if err != nil {
		return "", fmt.Errorf("DSM 用户名不可用：用户姓名 %q 清洗后为空，请确认飞书返回真实姓名并且姓名包含 DSM 支持的字符", displayName)
	}
	return username, nil
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
	baseLimit := 32 - len([]rune(suffix))
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

func (s *Service) getIdentity(ctx context.Context, id string) (db.AppIdentity, error) {
	row := s.q.DBTX().QueryRowContext(ctx, `SELECT id, display_name, primary_email, primary_email_norm, status, created_by, created_at, updated_at FROM app_identities WHERE id = ?`, id)
	var item db.AppIdentity
	err := row.Scan(&item.ID, &item.DisplayName, &item.PrimaryEmail, &item.PrimaryEmailNorm, &item.Status, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt)
	return item, err
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
