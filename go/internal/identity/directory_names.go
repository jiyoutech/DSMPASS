package identity

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

const OwnerChoicePrefix = "多个员工对应已有 DSM 账号，请选择归属员工："

// LegacyDuplicateReason identifies unresolved namesakes created by older versions.
func LegacyDuplicateReason(provider string) string {
	return "冲突类型：" + provider + "通讯录内用户姓名重名。请根据邮箱、手机号、身份 ID 和部门手动指定最终 DSM 用户名"
}

// AssignDirectoryName receives a free name from the directory plan.
// Resolve by external identity only: a namesake cannot claim an existing login.
func (s *Service) AssignDirectoryName(ctx context.Context, external db.ExternalAccount, username, choice, provider string) (db.DSMAccount, error) {
	owner := external.AppIdentityID.String
	if !external.AppIdentityID.Valid {
		created, err := s.createIdentity(ctx, external)
		if err != nil {
			return db.DSMAccount{}, err
		}
		owner = created.ID
	}
	status := "pending"
	var reason any
	if choice != "" {
		status, reason = "conflict", choice
		username = conflictUsername(external.DisplayName.String, owner)
	}
	result, err := s.q.DBTX().ExecContext(ctx, `
INSERT INTO dsm_accounts (id, app_identity_id, dsm_username, dsm_username_norm, provision_status, conflict_reason, allow_login)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(app_identity_id) DO UPDATE SET
 dsm_username=excluded.dsm_username, dsm_username_norm=excluded.dsm_username_norm,
 provision_status=excluded.provision_status, conflict_reason=excluded.conflict_reason, allow_login=(manual_login_blocked=0 AND excluded.allow_login=1), updated_at=CURRENT_TIMESTAMP
WHERE managed=1 AND provision_status='conflict' AND (conflict_reason IN (?,?) OR instr(conflict_reason,?)=1)
 AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries m WHERE m.dsm_account_id=dsm_accounts.id AND m.mapping_type='user')
 AND NOT EXISTS (SELECT 1 FROM external_accounts x WHERE x.app_identity_id=dsm_accounts.app_identity_id AND x.id<>?)`,
		uuid.NewString(), owner, username, Normalize(username), status, reason, status == "pending", LegacyDuplicateReason(provider), provider+"用户姓名重名", OwnerChoicePrefix, external.ID)
	if err != nil {
		return db.DSMAccount{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return db.DSMAccount{}, err
	}
	if n != 1 {
		return db.DSMAccount{}, fmt.Errorf("重名账号映射已变更，请重新同步")
	}
	return s.getDSMAccountByIdentity(ctx, owner)
}
