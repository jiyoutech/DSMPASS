package syncsvc

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/identity"
)

// ChooseDirectoryOwner runs in the caller's write transaction. The browser
// identifies a staged candidate; the live source record and NAS determine the target.
func (e *Engine) ChooseDirectoryOwner(ctx context.Context, source, accountID, subject, reason string) error {
	if subject == "" || !strings.HasPrefix(reason, identity.OwnerChoicePrefix) {
		return errors.New("请选择当前列表中的员工")
	}
	var externalID, display, username, status, currentReason string
	var managed int
	err := e.q.DBTX().QueryRowContext(ctx, `
SELECT e.id, e.display_name, a.dsm_username, a.provision_status, COALESCE(a.conflict_reason,''), a.managed
FROM dsm_accounts a JOIN app_identities i ON i.id=a.app_identity_id AND i.status='active'
JOIN external_accounts e ON e.app_identity_id=i.id AND e.active=1
JOIN identity_sources src ON src.slug=e.provider_slug AND src.enabled=1 AND src.directory_sync_enabled=1
WHERE a.id=? AND e.provider_slug=? AND e.subject=?
AND NOT EXISTS (SELECT 1 FROM external_accounts other WHERE other.app_identity_id=i.id AND other.id<>e.id)`,
		accountID, source, subject).Scan(&externalID, &display, &username, &status, &currentReason, &managed)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("该员工已离开通讯录或对应关系已变化")
	}
	if err != nil {
		return err
	}
	native, err := nativeDirectoryUsers(e.localPasswd, e.localGroup)
	if err != nil {
		return err
	}
	target, exists := native[userNameKey(display, e.cfg)]
	if !exists || !target.ordinary || identity.IsReservedDSMUsername(target.name) || target.choiceReason() != reason {
		return errors.New("DSM 账号或 UID 已变化，请刷新同步结果")
	}
	if username == target.name && managed == 0 && currentReason == "" {
		var linked bool
		err := e.q.DBTX().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM directory_owner_choices c
JOIN dsm_mapping_entries m ON m.external_account_id=c.external_id AND m.dsm_account_id=c.account_id AND m.provider_slug=c.source_slug
WHERE m.mapping_type='user' AND m.active=1 AND c.source_slug=? AND c.external_id=? AND c.account_id=? AND c.subject=? AND c.username=? AND c.uid=?)`,
			source, externalID, accountID, subject, target.name, target.uid).Scan(&linked)
		if err != nil || linked {
			return err
		}
	}
	if status != "conflict" || managed != 1 || currentReason != reason {
		return errors.New("该候选关系已变化，请刷新")
	}
	result, err := e.q.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET dsm_username=?, dsm_username_norm=?, managed=0,
	 provision_status='pending', conflict_reason=NULL, allow_login=(manual_login_blocked=0), updated_at=CURRENT_TIMESTAMP
WHERE id=? AND provision_status='conflict' AND conflict_reason=? AND managed=1
AND NOT EXISTS (SELECT 1 FROM dsm_accounts other WHERE other.dsm_username_norm=? AND other.id<>?)
AND NOT EXISTS (SELECT 1 FROM dsm_mapping_entries m WHERE m.dsm_account_id=? AND m.mapping_type='user')`,
		target.name, identity.Normalize(target.name), accountID, reason, identity.Normalize(target.name), accountID, accountID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("已有其他员工绑定此账号，请刷新")
	}
	if err := identity.NewService(e.cfg, e.q).EnsureDSMUserMapping(ctx, source, externalID, accountID); err != nil {
		return err
	}
	_, err = e.q.DBTX().ExecContext(ctx, `INSERT INTO directory_owner_choices(account_id,external_id,source_slug,subject,username,uid) VALUES(?,?,?,?,?,?)`, accountID, externalID, source, subject, target.name, target.uid)
	return err
}
