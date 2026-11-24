package backend

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

func (s *Server) resetProviderSyncData(c *gin.Context) {
	slug := c.Param("slug")
	result, status, err := s.runProviderCleanup(c.Request.Context(), slug, false, nil)
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
		_, _, err := s.runProviderCleanup(ctx, slug, false, progress)
		if err != nil {
			progress.fail(ctx, err)
			return
		}
		progress.complete(ctx, "清理完成")
	}()
	c.JSON(http.StatusAccepted, gin.H{"run_id": progress.id})
}

func (s *Server) runProviderCleanup(ctx context.Context, slug string, remove bool, progress *operationProgress) (gin.H, int, error) {
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
	targets, err := s.prepareCleanupTargets(ctx, slug)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if progress != nil {
		progress.setTotal(ctx, "禁用 DSM 用户", "正在核对 DSM 用户", len(targets))
	}
	var disabledDSMUsers int64
	var cleanupErrors []error
	for _, target := range targets {
		var outcome string
		if client, ok := s.helper.(helperclient.CleanupClient); ok {
			outcome, err = client.CleanupUser(ctx, target.RequestID, slug, target.ID, target.Name)
		} else {
			var disabled bool
			disabled, err = s.helper.DisableUser(ctx, target.RequestID, target.Name)
			if err == nil && !disabled {
				err = errors.New("Helper 未确认账号停用")
			}
			outcome = "disabled"
		}
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("清理 %s 失败，映射已保留，可重试：%w", target.Name, err))
			continue
		}
		if err = saveObjectState(ctx, s.store.DBTX(), target.Name, `UPDATE source_cleanup_targets SET outcome=? WHERE request_id=?`, outcome, target.RequestID); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		if outcome == "disabled" {
			disabledDSMUsers++
		}
		if progress != nil {
			progress.step(ctx, "核对 DSM 用户", target.Name)
		}
	}
	if len(cleanupErrors) > 0 {
		return nil, http.StatusBadGateway, errors.Join(cleanupErrors...)
	}
	var deletedSyncRuns, deletedSyncLogs, deletedAuditLogs int64
	if s.logs() != s.store {
		deletedSyncRuns, deletedSyncLogs, deletedAuditLogs, err = s.deleteSourceLogs(ctx, slug)
		if err != nil {
			return nil, http.StatusInternalServerError, err
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
	current, err := cleanupTargets(ctx, tx, slug)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !slices.Equal(current, targets) {
		return nil, http.StatusConflict, errors.New("清理期间账号范围已变化，请重试")
	}
	result, err := deleteIdentitySourceData(ctx, tx, slug)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM source_cleanup_targets WHERE source_slug=?", slug); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if remove {
		if _, err := tx.ExecContext(ctx, "DELETE FROM source_initial_password_secrets WHERE source_slug=?", slug); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		if err := saveObjectState(ctx, tx, slug, "DELETE FROM identity_sources WHERE slug=?", slug); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		result["deleted_sources"] = 1
	}
	if err := tx.Commit(); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if progress != nil {
		progress.step(ctx, "清理本地数据", "本地同步数据已删除")
	}
	result["deleted_sync_runs"] = int64Value(result, "deleted_sync_runs") + deletedSyncRuns
	result["deleted_sync_logs"] = int64Value(result, "deleted_sync_logs") + deletedSyncLogs
	result["deleted_login_audit"] = int64Value(result, "deleted_login_audit") + deletedAuditLogs
	result["slug"] = slug
	result["disabled_dsm_users"] = disabledDSMUsers
	result["detail"] = "已清理身份源同步数据。已停用的 DSM 用户保留在 NAS 上。"
	return result, http.StatusOK, nil
}

type cleanupTarget struct{ ID, Name, RequestID string }

const cleanupAccountScope = `FROM dsm_accounts a WHERE EXISTS (SELECT 1 FROM external_accounts e WHERE e.app_identity_id=a.app_identity_id AND e.provider_slug=?)
 AND NOT EXISTS (SELECT 1 FROM external_accounts e WHERE e.app_identity_id=a.app_identity_id AND e.provider_slug<>?)`

func cleanupTargets(ctx context.Context, q db.DBTX, slug string) ([]cleanupTarget, error) {
	rows, err := q.QueryContext(ctx, `SELECT a.id,a.dsm_username,COALESCE((SELECT request_id FROM source_cleanup_targets t WHERE t.source_slug=? AND t.account_id=a.id AND t.username=a.dsm_username),'') `+cleanupAccountScope+" ORDER BY a.id", slug, slug, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []cleanupTarget
	for rows.Next() {
		var target cleanupTarget
		if err := rows.Scan(&target.ID, &target.Name, &target.RequestID); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *Server) prepareCleanupTargets(ctx context.Context, slug string) ([]cleanupTarget, error) {
	var targets []cleanupTarget
	err := s.withSyncTransaction(ctx, func(tx db.DBTX) error {
		var err error
		targets, err = cleanupTargets(ctx, tx, slug)
		if err != nil {
			return err
		}
		for i, t := range targets {
			if t.RequestID != "" {
				continue
			}
			id := "cleanup_" + randomHex(16)
			_, err := tx.ExecContext(ctx, `INSERT INTO source_cleanup_targets(source_slug,account_id,username,request_id) VALUES(?,?,?,?)
ON CONFLICT(source_slug,account_id) DO UPDATE SET username=excluded.username,request_id=excluded.request_id,outcome='pending'`, slug, t.ID, t.Name, id)
			if err != nil {
				return err
			}
			targets[i].RequestID = id
		}
		return nil
	})
	return targets, err
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
	if _, err := tx.ExecContext(ctx, "DELETE FROM dingtalk_offboarding WHERE source_slug=?", slug); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM directory_owner_choices WHERE source_slug = ?`, slug); err != nil {
		return nil, err
	}
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
