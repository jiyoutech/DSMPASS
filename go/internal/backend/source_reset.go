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
	if _, err := s.loadIdentitySource(c.Request.Context(), slug); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"detail": "identity source not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if s.database == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": "database handle is not available"})
		return
	}
	tx, err := s.database.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	defer func() { _ = tx.Rollback() }()

	exclusiveIdentityIDs, providerGroupIDs, exclusiveGroupIDs, err := sourceOwnedIDs(c.Request.Context(), tx, slug)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	exclusiveAccountIDs, err := accountIDsForIdentities(c.Request.Context(), tx, exclusiveIdentityIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	exclusiveAccountUsernames := []string{}
	if len(exclusiveAccountIDs) > 0 {
		exclusiveAccountUsernames, err = queryStringIDs(c.Request.Context(), tx, `
SELECT dsm_username FROM dsm_accounts
WHERE id IN (`+placeholders(len(exclusiveAccountIDs))+`)`, anySlice(exclusiveAccountIDs)...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
			return
		}
	}

	disabledDSMUsers := int64(0)
	for _, username := range exclusiveAccountUsernames {
		if _, err := s.helper.DisableUser(c.Request.Context(), "reset_disable_"+randomHex(8), username); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"detail": "清理同步数据前禁用 DSM 用户失败：" + err.Error()})
			return
		}
		disabledDSMUsers++
	}

	result, err := deleteIdentitySourceDataWithIDs(c.Request.Context(), tx, slug, exclusiveIdentityIDs, exclusiveAccountIDs, providerGroupIDs, exclusiveGroupIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	result["slug"] = slug
	result["disabled_dsm_users"] = disabledDSMUsers
	result["detail"] = "已禁用 DSM 中对应用户，并清理该身份源的同步映射数据；下次同步遇到同名 DSM 用户会重新启用并复用"
	c.JSON(http.StatusOK, result)
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
		"deleted_sync_runs":       deletedSyncRuns,
		"deleted_sync_logs":       deletedSyncLogs,
		"deleted_login_audit":     deletedAuditLogs,
	}, nil
}
