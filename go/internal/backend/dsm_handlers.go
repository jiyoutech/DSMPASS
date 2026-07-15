package backend

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/identity"
)

func (s *Server) dsmAccounts(c *gin.Context) {
	providerSlug := c.Query("provider")
	paging := parsePagination(c)
	whereParts := []string{}
	args := []any{}
	if providerSlug != "" {
		whereParts = append(whereParts, `(EXISTS (
	    SELECT 1 FROM dsm_mapping_entries me
	    WHERE me.mapping_type = 'user' AND me.active = 1 AND me.dsm_account_id = a.id AND me.provider_slug = ?
	) OR EXISTS (
	    SELECT 1 FROM external_accounts e
	    WHERE e.app_identity_id = a.app_identity_id AND e.provider_slug = ?
	))`)
		args = append(args, providerSlug, providerSlug)
	}
	switch status := strings.TrimSpace(c.Query("status")); status {
	case "", "all":
	case "disabled_login":
		whereParts = append(whereParts, `a.allow_login = 0`)
	default:
		whereParts = append(whereParts, `a.provision_status = ?`)
		args = append(args, status)
	}
	if q := queryText(c); q != "" {
		pattern := likePattern(q)
		whereParts = append(whereParts, `(
			a.dsm_username LIKE ? ESCAPE '\'
			OR i.display_name LIKE ? ESCAPE '\'
			OR i.primary_email LIKE ? ESCAPE '\'
			OR a.provision_status LIKE ? ESCAPE '\'
			OR a.conflict_reason LIKE ? ESCAPE '\'
			OR EXISTS (
				SELECT 1 FROM external_accounts e
				WHERE e.app_identity_id = a.app_identity_id
				  AND (e.email LIKE ? ESCAPE '\' OR e.mobile_masked LIKE ? ESCAPE '\' OR e.subject LIKE ? ESCAPE '\')
			)
			OR EXISTS (
				SELECT 1 FROM group_members m
				JOIN dsm_groups g ON g.id = m.dsm_group_id
				WHERE m.dsm_account_id = a.id AND m.active = 1 AND g.dsm_groupname LIKE ? ESCAPE '\'
			)
		)`)
		args = append(args, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern)
	}
	where := ""
	if len(whereParts) > 0 {
		where = "WHERE " + strings.Join(whereParts, " AND ")
	}
	total, err := queryCount(c.Request.Context(), s.store, `
SELECT COUNT(*)
FROM dsm_accounts a
JOIN app_identities i ON i.id = a.app_identity_id
`+where, args...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	dataArgs := append(append([]any{}, args...), paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT a.id,
	       COALESCE(
	         (SELECT me.provider_slug FROM dsm_mapping_entries me WHERE me.mapping_type = 'user' AND me.active = 1 AND me.dsm_account_id = a.id ORDER BY me.created_at LIMIT 1),
	         (SELECT e.provider_slug FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id ORDER BY e.created_at LIMIT 1),
	         ''
	       ) AS provider_slug,
       a.app_identity_id, a.dsm_username,
       COALESCE(i.display_name, '') AS display_name,
       COALESCE(i.primary_email, '') AS primary_email,
       COALESCE((SELECT GROUP_CONCAT(e.email, ', ') FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id AND e.email IS NOT NULL AND e.email <> ''), '') AS external_emails,
       COALESCE((SELECT GROUP_CONCAT(e.mobile_masked, ', ') FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id AND e.mobile_masked IS NOT NULL AND e.mobile_masked <> ''), '') AS mobile_masked,
       COALESCE((SELECT GROUP_CONCAT(e.subject, ', ') FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id), '') AS external_subjects,
       a.provision_status, a.conflict_reason, a.allow_login
FROM dsm_accounts a
JOIN app_identities i ON i.id = a.app_identity_id
`+where+`
ORDER BY a.created_at
LIMIT ? OFFSET ?`, dataArgs...)
	writePagedItems(c, rows, total, paging, err)
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
	rows, err := s.runDSMAccountsLogin(c.Request.Context(), []string{id}, *payload.AllowLogin, nil)
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
	rows, err := s.runDSMAccountsLogin(c.Request.Context(), ids, *payload.AllowLogin, nil)
	writeItems(c, rows, err)
}

func (s *Server) startDSMAccountsLoginRun(c *gin.Context) {
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
	kind := "login_disable"
	message := "禁用登录任务已创建"
	if *payload.AllowLogin {
		kind = "login_enable"
		message = "启用登录任务已创建"
	}
	progress, err := s.createOperationRun(c.Request.Context(), kind, "", "等待开始", message, len(ids))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	go func() {
		ctx := context.Background()
		_, err := s.runDSMAccountsLogin(ctx, ids, *payload.AllowLogin, progress)
		if err != nil {
			progress.fail(ctx, err)
			return
		}
		if *payload.AllowLogin {
			progress.complete(ctx, "已允许登录")
		} else {
			progress.complete(ctx, "已禁止登录")
		}
	}()
	c.JSON(http.StatusAccepted, gin.H{"run_id": progress.id})
}

func (s *Server) runDSMAccountsLogin(ctx context.Context, ids []string, allowLogin bool, progress *operationProgress) ([]map[string]any, error) {
	ids = compactStringIDs(ids)
	if progress != nil {
		message := "正在禁止登录"
		if allowLogin {
			message = "正在允许登录"
		}
		progress.setTotal(ctx, "更新登录权限", message, len(ids))
	}
	for _, id := range ids {
		if _, err := s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET allow_login = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, boolToInt(allowLogin), id); err != nil {
			return nil, err
		}
		if progress != nil {
			progress.step(ctx, "更新登录权限", id)
		}
	}
	return s.dsmAccountRows(ctx, ids)
}

func (s *Server) dsmAccountRows(ctx context.Context, ids []string) ([]map[string]any, error) {
	ids = compactStringIDs(ids)
	if len(ids) == 0 {
		return []map[string]any{}, nil
	}
	return queryJSON(ctx, s.store, `
SELECT a.id,
	       COALESCE(
	         (SELECT me.provider_slug FROM dsm_mapping_entries me WHERE me.mapping_type = 'user' AND me.active = 1 AND me.dsm_account_id = a.id ORDER BY me.created_at LIMIT 1),
	         (SELECT e.provider_slug FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id ORDER BY e.created_at LIMIT 1),
	         ''
	       ) AS provider_slug,
       a.app_identity_id, a.dsm_username,
       COALESCE(i.display_name, '') AS display_name,
       COALESCE(i.primary_email, '') AS primary_email,
       COALESCE((SELECT GROUP_CONCAT(e.email, ', ') FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id AND e.email IS NOT NULL AND e.email <> ''), '') AS external_emails,
       COALESCE((SELECT GROUP_CONCAT(e.mobile_masked, ', ') FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id AND e.mobile_masked IS NOT NULL AND e.mobile_masked <> ''), '') AS mobile_masked,
       COALESCE((SELECT GROUP_CONCAT(e.subject, ', ') FROM external_accounts e WHERE e.app_identity_id = a.app_identity_id), '') AS external_subjects,
       a.provision_status, a.conflict_reason, a.allow_login
FROM dsm_accounts a
JOIN app_identities i ON i.id = a.app_identity_id
WHERE a.id IN (`+placeholders(len(ids))+`)
ORDER BY a.created_at`, anySlice(ids)...)
}

func (s *Server) setDSMAccountUsername(c *gin.Context) {
	var payload struct {
		DSMUsername string `json:"dsm_username"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "missing id"})
		return
	}
	username, err := identity.GenerateRequiredSequentialReadableUsername(payload.DSMUsername, "_", 1, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}
	if username != strings.TrimSpace(payload.DSMUsername) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "DSM 用户名包含不支持的字符，请直接填写最终 DSM 用户名"})
		return
	}
	usernameNorm := identity.Normalize(username)
	var currentUsernameNorm string
	err = s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT dsm_username_norm FROM dsm_accounts WHERE id = ?`, id).Scan(&currentUsernameNorm)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "account not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	var existingID string
	err = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT id FROM dsm_accounts WHERE dsm_username_norm = ? AND id <> ?`, usernameNorm, id).Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"detail": "DSM 用户名已被其他身份占用"})
		return
	}
	if err != nil && err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	result, err := s.store.DBTX().ExecContext(c.Request.Context(), `
	UPDATE dsm_accounts
	SET dsm_username = ?, dsm_username_norm = ?, managed = 0, provision_status = 'pending', conflict_reason = NULL, allow_login = 1, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?`, username, usernameNorm, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "account not found"})
		return
	}
	rows, err := s.dsmAccountRows(c.Request.Context(), []string{id})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows[0])
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
	paging := parsePagination(c)
	whereParts := []string{}
	args := []any{}
	if providerSlug != "" {
		whereParts = append(whereParts, `(EXISTS (
	    SELECT 1 FROM dsm_mapping_entries me
	    WHERE me.mapping_type = 'group' AND me.active = 1 AND me.dsm_group_id = g.id AND me.provider_slug = ?
	) OR EXISTS (
	    SELECT 1 FROM group_links l
	    JOIN provider_groups pg ON pg.id = l.provider_group_id
	    WHERE l.dsm_group_id = g.id AND pg.provider_slug = ?
	))`)
		args = append(args, providerSlug, providerSlug)
	}
	switch status := strings.TrimSpace(c.Query("status")); status {
	case "", "all":
	default:
		whereParts = append(whereParts, `g.provision_status = ?`)
		args = append(args, status)
	}
	if q := queryText(c); q != "" {
		pattern := likePattern(q)
		whereParts = append(whereParts, `(
			g.dsm_groupname LIKE ? ESCAPE '\'
			OR g.provision_status LIKE ? ESCAPE '\'
			OR g.conflict_reason LIKE ? ESCAPE '\'
			OR EXISTS (
				SELECT 1 FROM group_links l
				JOIN provider_groups pg ON pg.id = l.provider_group_id
				WHERE l.dsm_group_id = g.id
				  AND (pg.name LIKE ? ESCAPE '\' OR pg.path LIKE ? ESCAPE '\' OR pg.subject LIKE ? ESCAPE '\')
			)
			OR EXISTS (
				SELECT 1 FROM group_members m
				JOIN dsm_accounts a ON a.id = m.dsm_account_id
				JOIN app_identities i ON i.id = a.app_identity_id
				WHERE m.dsm_group_id = g.id AND m.active = 1
				  AND (a.dsm_username LIKE ? ESCAPE '\' OR i.display_name LIKE ? ESCAPE '\' OR i.primary_email LIKE ? ESCAPE '\')
			)
		)`)
		args = append(args, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern)
	}
	where := ""
	if len(whereParts) > 0 {
		where = "WHERE " + strings.Join(whereParts, " AND ")
	}
	total, err := queryCount(c.Request.Context(), s.store, `
SELECT COUNT(*)
FROM dsm_groups g
`+where, args...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	dataArgs := append(append([]any{}, args...), paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT g.id,
	       COALESCE(
	         (SELECT me.provider_slug FROM dsm_mapping_entries me WHERE me.mapping_type = 'group' AND me.active = 1 AND me.dsm_group_id = g.id ORDER BY me.created_at LIMIT 1),
	         (SELECT pg.provider_slug FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1),
	         ''
	       ) AS provider_slug,
       g.dsm_groupname, g.provision_status, g.conflict_reason,
       COALESCE((SELECT pg.name FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1), '') AS provider_group_name,
       COALESCE((SELECT pg.path FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1), '') AS provider_group_path
FROM dsm_groups g
`+where+`
ORDER BY g.created_at
LIMIT ? OFFSET ?`, dataArgs...)
	writePagedItems(c, rows, total, paging, err)
}

func (s *Server) setDSMGroupName(c *gin.Context) {
	var payload struct {
		DSMGroupname string `json:"dsm_groupname"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "missing id"})
		return
	}
	groupname, err := identity.SanitizeGroupName(payload.DSMGroupname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": err.Error()})
		return
	}
	if groupname != strings.TrimSpace(payload.DSMGroupname) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "DSM 部门组名包含不支持的字符，请直接填写最终 DSM 部门组名"})
		return
	}
	var currentID string
	err = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT id FROM dsm_groups WHERE id = ?`, id).Scan(&currentID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "group not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	groupNorm := identity.Normalize(groupname)
	var existingID string
	err = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT id FROM dsm_groups WHERE dsm_groupname_norm = ? AND id <> ?`, groupNorm, id).Scan(&existingID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"detail": "DSM 部门组名已被其他部门占用"})
		return
	}
	if err != nil && err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	result, err := s.store.DBTX().ExecContext(c.Request.Context(), `
UPDATE dsm_groups
SET dsm_groupname = ?, dsm_groupname_norm = ?, managed = 0, provision_status = 'pending', conflict_reason = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, groupname, groupNorm, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "group not found"})
		return
	}
	rows, err := s.dsmGroupRows(c.Request.Context(), []string{id})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows[0])
}

func (s *Server) dsmGroupRows(ctx context.Context, ids []string) ([]map[string]any, error) {
	ids = compactStringIDs(ids)
	if len(ids) == 0 {
		return []map[string]any{}, nil
	}
	return queryJSON(ctx, s.store, `
SELECT g.id,
	       COALESCE(
	         (SELECT me.provider_slug FROM dsm_mapping_entries me WHERE me.mapping_type = 'group' AND me.active = 1 AND me.dsm_group_id = g.id ORDER BY me.created_at LIMIT 1),
	         (SELECT pg.provider_slug FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1),
	         ''
	       ) AS provider_slug,
       g.dsm_groupname, g.provision_status, g.conflict_reason,
       COALESCE((SELECT pg.name FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1), '') AS provider_group_name,
       COALESCE((SELECT pg.path FROM group_links l JOIN provider_groups pg ON pg.id = l.provider_group_id WHERE l.dsm_group_id = g.id ORDER BY pg.created_at LIMIT 1), '') AS provider_group_path
FROM dsm_groups g
WHERE g.id IN (`+placeholders(len(ids))+`)
ORDER BY g.created_at`, anySlice(ids)...)
}

func (s *Server) groupMembers(c *gin.Context) {
	providerSlug := c.Query("provider")
	where := ""
	args := []any{}
	if providerSlug != "" {
		where = `WHERE me.provider_slug = ? AND me.active = 1 AND m.active = 1`
		args = append(args, providerSlug)
	} else {
		where = `WHERE m.active = 1`
	}
	rows, err := queryJSON(c.Request.Context(), s.store, `
	SELECT DISTINCT m.id, me.provider_slug, g.id AS dsm_group_id, a.id AS dsm_account_id, g.dsm_groupname, a.dsm_username, m.provision_status
	FROM group_members m
	JOIN dsm_groups g ON g.id = m.dsm_group_id
	JOIN dsm_accounts a ON a.id = m.dsm_account_id
	JOIN dsm_mapping_entries me ON me.mapping_type = 'member'
		AND me.dsm_group_id = m.dsm_group_id
		AND me.dsm_account_id = m.dsm_account_id
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

func (s *Server) sourceSlugForAccount(ctx context.Context, accountID string) string {
	var sourceSlug string
	err := s.store.DBTX().QueryRowContext(ctx, `
SELECT e.provider_slug
FROM dsm_accounts a
JOIN external_accounts e ON e.app_identity_id = a.app_identity_id
WHERE a.id = ?
ORDER BY e.updated_at DESC
LIMIT 1`, accountID).Scan(&sourceSlug)
	if err != nil {
		return "manual"
	}
	if strings.TrimSpace(sourceSlug) == "" {
		return "manual"
	}
	return sourceSlug
}

func (s *Server) provisionDSMAccount(c *gin.Context) {
	if err := s.ensureRealDSMProvisioning(c.Request.Context()); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	var id, username, displayName, email, status string
	err := s.store.DBTX().QueryRowContext(c.Request.Context(), `
SELECT a.id, a.dsm_username, COALESCE(i.display_name, ''), COALESCE(i.primary_email, ''), a.provision_status
FROM dsm_accounts a JOIN app_identities i ON i.id = a.app_identity_id WHERE a.id = ?`, c.Param("id")).Scan(&id, &username, &displayName, &email, &status)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"detail": "dsm account not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if status == "conflict" {
		c.JSON(http.StatusConflict, gin.H{"detail": "账号存在冲突，请先由管理员修改 DSM 用户名"})
		return
	}
	sourceSlug := s.sourceSlugForAccount(c.Request.Context(), id)
	password, err := s.provisionUserInitialPassword(c.Request.Context(), sourceSlug)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	created, err := s.helper.ProvisionUser(c.Request.Context(), "provision_"+randomHex(8), username, displayName, email, password)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"detail": err.Error()})
		return
	}
	nextStatus := "created"
	if !created {
		nextStatus = "linked_existing"
	}
	_, _ = s.store.DBTX().ExecContext(c.Request.Context(), `UPDATE dsm_accounts SET provision_status = ?, conflict_reason = NULL, allow_login = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, nextStatus, id)
	c.JSON(http.StatusOK, gin.H{"id": id, "dsm_username": username, "provision_status": nextStatus})
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
	WHERE m.id = ? AND m.active = 1`, c.Param("id")).Scan(&id, &groupname, &username)
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
