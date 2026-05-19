package backend

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) dsmAccounts(c *gin.Context) {
	providerSlug := c.Query("provider")
	where := ""
	args := []any{}
	if providerSlug != "" {
		where = `WHERE EXISTS (
    SELECT 1 FROM external_accounts e
    WHERE e.app_identity_id = a.app_identity_id AND e.provider_slug = ?
)`
		args = append(args, providerSlug)
	}
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT a.id,
       COALESCE((SELECT e.provider_slug FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id ORDER BY e.created_at LIMIT 1), '') AS provider_slug,
       a.app_identity_id, a.dsm_username, a.provision_status, a.allow_login
FROM dsm_accounts a
`+where+`
ORDER BY a.created_at`, args...)
	writeItems(c, rows, err)
}

func (s *Server) setDSMAccountLogin(c *gin.Context) {
	var payload struct {
		AllowLogin *bool `json:"allow_login"`
	}
	if err := c.BindJSON(&payload); err != nil || payload.AllowLogin == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "missing id"})
		return
	}
	if _, err := s.store.DBTX().ExecContext(c.Request.Context(), `UPDATE dsm_accounts SET allow_login = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, boolToInt(*payload.AllowLogin), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	rows, err := s.dsmAccountRows(c.Request.Context(), []string{id})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if len(rows) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "account not found"})
		return
	}
	c.JSON(http.StatusOK, rows[0])
}

func (s *Server) setDSMAccountsLogin(c *gin.Context) {
	var payload struct {
		IDs        []string `json:"ids"`
		AllowLogin *bool    `json:"allow_login"`
	}
	if err := c.BindJSON(&payload); err != nil || payload.AllowLogin == nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	ids := compactStringIDs(payload.IDs)
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "missing ids"})
		return
	}
	if len(ids) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "too many ids"})
		return
	}
	for _, id := range ids {
		if _, err := s.store.DBTX().ExecContext(c.Request.Context(), `UPDATE dsm_accounts SET allow_login = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, boolToInt(*payload.AllowLogin), id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
			return
		}
	}
	rows, err := s.dsmAccountRows(c.Request.Context(), ids)
	writeItems(c, rows, err)
}

func (s *Server) dsmAccountRows(ctx context.Context, ids []string) ([]map[string]any, error) {
	ids = compactStringIDs(ids)
	if len(ids) == 0 {
		return []map[string]any{}, nil
	}
	return queryJSON(ctx, s.store, `
SELECT a.id,
       COALESCE((SELECT e.provider_slug FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id ORDER BY e.created_at LIMIT 1), '') AS provider_slug,
       a.app_identity_id, a.dsm_username, a.provision_status, a.allow_login
FROM dsm_accounts a
WHERE a.id IN (`+placeholders(len(ids))+`)
ORDER BY a.created_at`, anySlice(ids)...)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func compactStringIDs(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (s *Server) dsmGroups(c *gin.Context) {
	providerSlug := c.Query("provider")
	where := ""
	args := []any{}
	if providerSlug != "" {
		where = `WHERE EXISTS (
    SELECT 1 FROM group_links l
    JOIN provider_groups pg ON pg.id = l.provider_group_id
    WHERE l.dsm_group_id = g.id AND pg.provider_slug = ?
)`
		args = append(args, providerSlug)
	}
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT g.id,
       COALESCE((SELECT pg.provider_slug FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1), '') AS provider_slug,
       g.dsm_groupname, g.provision_status, g.conflict_reason
FROM dsm_groups g
`+where+`
ORDER BY g.created_at`, args...)
	writeItems(c, rows, err)
}

func (s *Server) groupMembers(c *gin.Context) {
	providerSlug := c.Query("provider")
	where := ""
	args := []any{}
	if providerSlug != "" {
		where = `WHERE pg.provider_slug = ?`
		args = append(args, providerSlug)
	}
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT m.id, pg.provider_slug, g.dsm_groupname, a.dsm_username, m.provision_status
FROM group_members m
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN dsm_accounts a ON a.id = m.dsm_account_id
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups pg ON pg.id = l.provider_group_id
`+where+`
ORDER BY m.created_at`, args...)
	writeItems(c, rows, err)
}

func (s *Server) ensureRealDSMProvisioning(ctx context.Context) error {
	if s.cfg.RelayMode != "socket" {
		return errors.New("系统只支持真实 DSM 模式，请确认辅助程序正常")
	}
	if _, err := s.helper.HealthCheck(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Server) initialPasswordForSource(ctx context.Context, sourceSlug string) string {
	source, err := s.loadIdentitySource(ctx, sourceSlug)
	if err != nil {
		return defaultInitialPassword
	}
	password := strings.TrimSpace(decodeSourceConfig(source.ConfigJSON).InitialPassword)
	if password == "" {
		return defaultInitialPassword
	}
	return password
}

func (s *Server) initialPasswordForAccount(ctx context.Context, accountID string) string {
	var sourceSlug string
	err := s.store.DBTX().QueryRowContext(ctx, `
SELECT e.provider_slug
FROM dsm_accounts a
JOIN external_accounts e ON e.app_identity_id = a.app_identity_id
WHERE a.id = ?
ORDER BY e.updated_at DESC
LIMIT 1`, accountID).Scan(&sourceSlug)
	if err != nil {
		return defaultInitialPassword
	}
	return s.initialPasswordForSource(ctx, sourceSlug)
}

func (s *Server) provisionDSMAccount(c *gin.Context) {
	if err := s.ensureRealDSMProvisioning(c.Request.Context()); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	var id, username, displayName, email string
	err := s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT a.id, a.dsm_username, COALESCE(i.display_name, ''), COALESCE(i.primary_email, '')
FROM dsm_accounts a JOIN app_identities i ON i.id = a.app_identity_id WHERE a.id = ?`, c.Param("id")).Scan(&id, &username, &displayName, &email)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "dsm account not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if _, err := s.helper.ProvisionUser(c.Request.Context(), "provision_"+randomHex(8), username, displayName, email, s.initialPasswordForAccount(c.Request.Context(), id)); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `UPDATE dsm_accounts SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	c.JSON(http.StatusOK, gin.H{"id": id, "dsm_username": username, "provision_status": "created"})
}

func (s *Server) provisionDSMGroup(c *gin.Context) {
	if err := s.ensureRealDSMProvisioning(c.Request.Context()); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	var id, groupname string
	err := s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT id, dsm_groupname FROM dsm_groups WHERE id = ?`, c.Param("id")).Scan(&id, &groupname)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "dsm group not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	created, err := s.helper.ProvisionGroup(c.Request.Context(), "provision_"+randomHex(8), groupname)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	if !created {
		c.JSON(http.StatusOK, gin.H{"id": id, "dsm_groupname": groupname, "provision_status": "pending", "detail": "DSM CLI 无法创建空群组；添加第一个成员时会自动创建"})
		return
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `UPDATE dsm_groups SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	c.JSON(http.StatusOK, gin.H{"id": id, "dsm_groupname": groupname, "provision_status": "created"})
}

func (s *Server) provisionGroupMember(c *gin.Context) {
	if err := s.ensureRealDSMProvisioning(c.Request.Context()); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	var id, groupname, username string
	err := s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT m.id, g.dsm_groupname, a.dsm_username
FROM group_members m
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN dsm_accounts a ON a.id = m.dsm_account_id
WHERE m.id = ?`, c.Param("id")).Scan(&id, &groupname, &username)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "group member not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if _, err := s.helper.AddGroupMember(c.Request.Context(), "provision_"+randomHex(8), groupname, username); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `UPDATE group_members SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	c.JSON(http.StatusOK, gin.H{"id": id, "provision_status": "created"})
}
