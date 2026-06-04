package backend

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) resetProviderSyncData(c *gin.Context) {
	slug := c.Param("slug")
	result, status, err := s.runProviderCleanup(c.Request.Context(), slug, nil)
	if err != nil {
		c.JSON(status, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) startProviderCleanupRun(c *gin.Context) {
	slug := c.Param("slug")
	if _, err := s.loadIdentitySource(c.Request.Context(), slug); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		}
		return
	}
	progress, err := s.createOperationRun(c.Request.Context(), "cleanup", slug, "等待开始", "清理任务已创建", 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	go func() {
		ctx := context.Background()
		_, _, err := s.runProviderCleanup(ctx, slug, progress)
		if err != nil {
			progress.fail(ctx, err)
			return
		}
		progress.complete(ctx, "清理完成")
	}()
	c.JSON(http.StatusAccepted, gin.H{"run_id": progress.id})
}

func (s *Server) runProviderCleanup(ctx context.Context, slug string, progress *operationProgress) (gin.H, int, error) {
	if _, err := s.loadIdentitySource(ctx, slug); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, http.StatusNotFound, errors.New("identity source not found")
		}
		return nil, http.StatusInternalServerError, err
	}
	if s.database == nil {
		return nil, http.StatusInternalServerError, errors.New("database handle is not available")
	}
	if !s.beginSourceSync(slug) {
		return nil, http.StatusConflict, errSyncAlreadyRunning
	}
	defer s.endSourceSync(slug)
	if progress != nil {
		progress.message(ctx, "分析清理范围", "正在分析需要清理的数据")
	}
	exclusiveIdentityIDs, providerGroupIDs, exclusiveGroupIDs, err := sourceOwnedIDs(ctx, s.store.DBTX(), slug)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	exclusiveAccountIDs, err := accountIDsForIdentities(ctx, s.store.DBTX(), exclusiveIdentityIDs)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	exclusiveAccountUsernames := []string{}
	if len(exclusiveAccountIDs) > 0 {
		exclusiveAccountUsernames, err = queryStringIDs(ctx, s.store.DBTX(), `
SELECT dsm_username FROM dsm_accounts
WHERE id IN (`+placeholders(len(exclusiveAccountIDs))+`)`, anySlice(exclusiveAccountIDs)...)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	disabledDSMUsers := int64(0)
	if progress != nil {
		progress.setTotal(ctx, "禁用 DSM 用户", "正在禁用 DSM 用户", len(exclusiveAccountUsernames))
	}
	for _, username := range exclusiveAccountUsernames {
		if _, err := s.helper.DisableUser(ctx, "reset_disable_"+randomHex(8), username); err != nil {
			return nil, http.StatusBadGateway, errors.New("清理同步数据前禁用 DSM 用户失败：" + err.Error())
		}
		disabledDSMUsers++
		if progress != nil {
			progress.step(ctx, "禁用 DSM 用户", username)
		}
	}
	if progress != nil {
		progress.setTotal(ctx, "清理本地数据", "正在删除本地同步数据", 1)
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := deleteIdentitySourceDataWithIDs(ctx, tx, slug, exclusiveIdentityIDs, exclusiveAccountIDs, providerGroupIDs, exclusiveGroupIDs)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if err := tx.Commit(); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if progress != nil {
		progress.step(ctx, "清理本地数据", "本地同步数据已删除")
	}
	deletedSyncRuns, deletedSyncLogs, deletedAuditLogs, err := s.deleteSourceLogs(ctx, slug)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	result["deleted_sync_runs"] = int64Value(result, "deleted_sync_runs") + deletedSyncRuns
	result["deleted_sync_logs"] = int64Value(result, "deleted_sync_logs") + deletedSyncLogs
	result["deleted_login_audit"] = int64Value(result, "deleted_login_audit") + deletedAuditLogs
	result["slug"] = slug
	result["disabled_dsm_users"] = disabledDSMUsers
	result["detail"] = "已禁用 DSM 中对应用户，并清理该身份源的同步映射数据；如需彻底删除这些 DSM 用户，请到 DSM 手动删除；下次同步遇到同名 DSM 用户会重新启用并复用"
	return result, http.StatusOK, nil
}

func (s *Server) deleteSourceLogs(ctx context.Context, slug string) (int64, int64, int64, error) {
	logs := s.logs().DBTX()
	syncLogsResult, err := logs.ExecContext(ctx, `DELETE FROM sync_operation_logs WHERE source_slug = ?`, slug)
	if err != nil {
		return 0, 0, 0, err
	}
	deletedSyncLogs, _ := syncLogsResult.RowsAffected()
	syncRunsResult, err := logs.ExecContext(ctx, `DELETE FROM sync_runs WHERE source_slug = ?`, slug)
	if err != nil {
		return 0, deletedSyncLogs, 0, err
	}
	deletedSyncRuns, _ := syncRunsResult.RowsAffected()
	auditResult, err := logs.ExecContext(ctx, `DELETE FROM login_audit_logs WHERE provider_slug = ?`, slug)
	if err != nil {
		return deletedSyncRuns, deletedSyncLogs, 0, err
	}
	deletedAuditLogs, _ := auditResult.RowsAffected()
	return deletedSyncRuns, deletedSyncLogs, deletedAuditLogs, nil
}

func int64Value(values gin.H, key string) int64 {
	switch value := values[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	default:
		return 0
	}
}

func sourceOwnedIDs(ctx context.Context, tx db.DBTX, slug string) (exclusiveIdentityIDs []string, providerGroupIDs []string, exclusiveGroupIDs []string, err error) {
	exclusiveIdentityIDs, err = queryStringIDs(ctx, tx, `
SELECT DISTINCT e.app_identity_id
FROM external_accounts e
WHERE e.provider_slug = ? AND e.app_identity_id IS NOT NULL
AND NOT EXISTS (
	SELECT 1 FROM external_accounts other
	WHERE other.app_identity_id = e.app_identity_id AND other.provider_slug <> ?
)`, slug, slug)
	if err != nil {
		return
	}
	providerGroupIDs, err = queryStringIDs(ctx, tx, `SELECT id FROM provider_groups WHERE provider_slug = ?`, slug)
	if err != nil {
		return
	}
	exclusiveGroupIDs, err = queryStringIDs(ctx, tx, `
SELECT DISTINCT gl.dsm_group_id
FROM group_links gl
JOIN provider_groups pg ON pg.id = gl.provider_group_id
WHERE pg.provider_slug = ?
AND NOT EXISTS (
	SELECT 1
	FROM group_links gl2
	JOIN provider_groups pg2 ON pg2.id = gl2.provider_group_id
	WHERE gl2.dsm_group_id = gl.dsm_group_id AND pg2.provider_slug <> ?
)`, slug, slug)
	return
}

func accountIDsForIdentities(ctx context.Context, tx db.DBTX, identityIDs []string) ([]string, error) {
	if len(identityIDs) == 0 {
		return []string{}, nil
	}
	return queryStringIDs(ctx, tx, `
SELECT id FROM dsm_accounts
WHERE app_identity_id IN (`+placeholders(len(identityIDs))+`)`, anySlice(identityIDs)...)
}

func deleteIdentitySourceData(ctx context.Context, tx db.DBTX, slug string) (gin.H, error) {
	exclusiveIdentityIDs, providerGroupIDs, exclusiveGroupIDs, err := sourceOwnedIDs(ctx, tx, slug)
	if err != nil {
		return nil, err
	}
	exclusiveAccountIDs, err := accountIDsForIdentities(ctx, tx, exclusiveIdentityIDs)
	if err != nil {
		return nil, err
	}
	return deleteIdentitySourceDataWithIDs(ctx, tx, slug, exclusiveIdentityIDs, exclusiveAccountIDs, providerGroupIDs, exclusiveGroupIDs)
}

func deleteIdentitySourceDataWithIDs(ctx context.Context, tx db.DBTX, slug string, exclusiveIdentityIDs, exclusiveAccountIDs, providerGroupIDs, exclusiveGroupIDs []string) (gin.H, error) {
	mappingResult, err := tx.ExecContext(ctx, `DELETE FROM dsm_mapping_entries WHERE provider_slug = ?`, slug)
	if err != nil {
		return nil, err
	}
	deletedMappings, _ := mappingResult.RowsAffected()
	if _, err := tx.ExecContext(ctx, `
UPDATE group_members
SET active = 0, provision_status = 'remove_pending', updated_at = CURRENT_TIMESTAMP
WHERE active = 1
  AND NOT EXISTS (
	SELECT 1
	FROM dsm_mapping_entries me
	WHERE me.mapping_type = 'member'
	  AND me.active = 1
	  AND me.dsm_group_id = group_members.dsm_group_id
	  AND me.dsm_account_id = group_members.dsm_account_id
  )`); err != nil {
		return nil, err
	}
	deletedMembersFromAccounts, err := deleteByIDs(ctx, tx, "group_members", "dsm_account_id", exclusiveAccountIDs)
	if err != nil {
		return nil, err
	}
	deletedMembersFromGroups, err := deleteByIDs(ctx, tx, "group_members", "dsm_group_id", exclusiveGroupIDs)
	if err != nil {
		return nil, err
	}
	deletedLinks, err := deleteByIDs(ctx, tx, "group_links", "provider_group_id", providerGroupIDs)
	if err != nil {
		return nil, err
	}
	deletedProviderGroups, err := deleteByIDs(ctx, tx, "provider_groups", "id", providerGroupIDs)
	if err != nil {
		return nil, err
	}
	deletedGroups, err := deleteByIDs(ctx, tx, "dsm_groups", "id", exclusiveGroupIDs)
	if err != nil {
		return nil, err
	}
	deletedAccounts, err := deleteByIDs(ctx, tx, "dsm_accounts", "id", exclusiveAccountIDs)
	if err != nil {
		return nil, err
	}
	externalResult, err := tx.ExecContext(ctx, `DELETE FROM external_accounts WHERE provider_slug = ?`, slug)
	if err != nil {
		return nil, err
	}
	deletedExternal, _ := externalResult.RowsAffected()
	deletedIdentities, err := deleteByIDs(ctx, tx, "app_identities", "id", exclusiveIdentityIDs)
	if err != nil {
		return nil, err
	}
	syncLogsResult, err := tx.ExecContext(ctx, `DELETE FROM sync_operation_logs WHERE source_slug = ?`, slug)
	if err != nil {
		return nil, err
	}
	deletedSyncLogs, _ := syncLogsResult.RowsAffected()
	syncRunsResult, err := tx.ExecContext(ctx, `DELETE FROM sync_runs WHERE source_slug = ?`, slug)
	if err != nil {
		return nil, err
	}
	deletedSyncRuns, _ := syncRunsResult.RowsAffected()
	auditResult, err := tx.ExecContext(ctx, `DELETE FROM login_audit_logs WHERE provider_slug = ?`, slug)
	if err != nil {
		return nil, err
	}
	deletedAuditLogs, _ := auditResult.RowsAffected()
	return gin.H{
		"slug":                    slug,
		"deleted_external":        deletedExternal,
		"deleted_identities":      deletedIdentities,
		"deleted_dsm_accounts":    deletedAccounts,
		"deleted_provider_groups": deletedProviderGroups,
		"deleted_dsm_groups":      deletedGroups,
		"deleted_group_links":     deletedLinks,
		"deleted_group_members":   deletedMembersFromAccounts + deletedMembersFromGroups,
		"deleted_dsm_mappings":    deletedMappings,
		"deleted_sync_runs":       deletedSyncRuns,
		"deleted_sync_logs":       deletedSyncLogs,
		"deleted_login_audit":     deletedAuditLogs,
	}, nil
}
