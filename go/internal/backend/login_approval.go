package backend

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"github.com/gin-gonic/gin"
)

// The browser selects an audit event. Resolve its specific external identity
// against the live mapping, so an old failure cannot approve a replacement.
func (s *Server) webLoginApproval(c *gin.Context) {
	if !s.cfg.AdminAuthEnabled || !s.validAdminSession(c) {
		c.JSON(http.StatusForbidden, gin.H{"detail": "请登录 DSMPASS 管理页面核实账号归属"})
		return
	}
	var input struct {
		Verify *bool `json:"verify"`
	}
	if c.ContentType() != "application/json" || c.ShouldBindJSON(&input) != nil || input.Verify == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "无效的账号核实请求"})
		return
	}
	ctx := c.Request.Context()
	source := c.Param("slug")
	var externalID, identityID, name string
	err := s.logs().DBTX().QueryRowContext(ctx, `SELECT external_account_id,app_identity_id,dsm_username FROM login_audit_logs
		WHERE id=? AND provider_slug=? AND result='failed' AND external_account_id IS NOT NULL AND app_identity_id IS NOT NULL AND dsm_username IS NOT NULL`, c.Param("id"), source).Scan(&externalID, &identityID, &name)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "找不到该身份源的登录失败记录"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	owner := db.CredentialIdentity{Username: name, SourceSlug: source}
	err = s.store.DBTX().QueryRowContext(ctx, `SELECT e.subject FROM external_accounts e
		JOIN identity_sources s ON s.slug=e.provider_slug AND s.provider_type='dingtalk'
		JOIN dsm_mapping_entries m ON m.external_account_id=e.id AND m.provider_slug=s.slug AND m.mapping_type='user' AND m.active=1
		JOIN dsm_accounts a ON a.id=m.dsm_account_id AND a.app_identity_id=e.app_identity_id
		WHERE e.id=? AND e.provider_slug=? AND e.app_identity_id=? AND a.dsm_username=?`, externalID, source, identityID, name).Scan(&owner.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusConflict, gin.H{"detail": "原有登录映射已变化，请查看最新的登录记录"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	client, ok := s.helper.(helperclient.LoginApprovalClient)
	if !ok {
		c.JSON(http.StatusServiceUnavailable, gin.H{"detail": "当前 Helper 不支持归属核实，请检查 Helper 更新状态"})
		return
	}
	result, err := client.WebLoginApproval(ctx, "login_approval_"+randomHex(8), owner, identityID, *input.Verify)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"detail": err.Error()})
		return
	}
	result["subject"] = owner.Subject
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}
