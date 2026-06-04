package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) loginAuditLogs(c *gin.Context) {
	providerSlug := c.Query("provider")
	paging := parsePagination(c)
	whereParts := []string{}
	args := []any{}
	if providerSlug != "" {
		whereParts = append(whereParts, `provider_slug = ?`)
		args = append(args, providerSlug)
	}
	switch result := strings.TrimSpace(c.Query("result")); result {
	case "", "all":
	default:
		whereParts = append(whereParts, `result = ?`)
		args = append(args, result)
	}
	if q := queryText(c); q != "" {
		pattern := likePattern(q)
		whereParts = append(whereParts, `(request_id LIKE ? ESCAPE '\' OR dsm_username LIKE ? ESCAPE '\' OR result LIKE ? ESCAPE '\' OR error_code LIKE ? ESCAPE '\' OR ip_address LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern, pattern)
	}
	where := ""
	if len(whereParts) > 0 {
		where = "WHERE " + strings.Join(whereParts, " AND ")
	}
	total, err := queryCount(c.Request.Context(), s.logs(), `SELECT COUNT(*) FROM login_audit_logs `+where, args...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	dataArgs := append(append([]any{}, args...), paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.logs(), `
SELECT id, request_id, provider_slug, external_account_id, app_identity_id, dsm_username, result, error_code, ip_address, ip_hash, user_agent_hash, duration_ms, created_at
FROM login_audit_logs
`+where+`
ORDER BY created_at DESC
LIMIT ? OFFSET ?`, dataArgs...)
	writePagedItems(c, rows, total, paging, err)
}

func (s *Server) externalAccounts(c *gin.Context) {
	providerSlug := c.Query("provider")
	paging := parsePagination(c)
	whereParts := []string{}
	args := []any{}
	if providerSlug != "" {
		whereParts = append(whereParts, `provider_slug = ?`)
		args = append(args, providerSlug)
	}
	switch active := strings.TrimSpace(c.Query("active")); active {
	case "", "all":
	case "1", "true":
		whereParts = append(whereParts, `active = 1`)
	case "0", "false":
		whereParts = append(whereParts, `active = 0`)
	}
	if q := queryText(c); q != "" {
		pattern := likePattern(q)
		whereParts = append(whereParts, `(subject LIKE ? ESCAPE '\' OR subject_type LIKE ? ESCAPE '\' OR display_name LIKE ? ESCAPE '\' OR email LIKE ? ESCAPE '\' OR mobile_masked LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern, pattern)
	}
	where := ""
	if len(whereParts) > 0 {
		where = "WHERE " + strings.Join(whereParts, " AND ")
	}
	total, err := queryCount(c.Request.Context(), s.store, `SELECT COUNT(*) FROM external_accounts `+where, args...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	dataArgs := append(append([]any{}, args...), paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT id, provider_slug, subject AS subject_hash, subject_type, display_name, email, email_verified, mobile_masked, active, app_identity_id, last_seen_at, last_login_at
FROM external_accounts
`+where+`
ORDER BY created_at
LIMIT ? OFFSET ?`, dataArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	for _, row := range rows {
		row["subject_hash"] = shortValueHash(row["subject_hash"])
	}
	writePagedItems(c, rows, total, paging, nil)
}

func (s *Server) identities(c *gin.Context) {
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT i.id, i.display_name, i.primary_email, i.status, i.created_by, a.id AS dsm_account_id, a.dsm_username
FROM app_identities i
LEFT JOIN dsm_accounts a ON a.app_identity_id = i.id
ORDER BY i.created_at`)
	writeItems(c, rows, err)
}

func (s *Server) providerGroups(c *gin.Context) {
	providerSlug := c.Query("provider")
	paging := parsePagination(c)
	whereParts := []string{}
	args := []any{}
	if providerSlug != "" {
		whereParts = append(whereParts, `provider_slug = ?`)
		args = append(args, providerSlug)
	}
	switch active := strings.TrimSpace(c.Query("active")); active {
	case "", "all":
	case "1", "true":
		whereParts = append(whereParts, `active = 1`)
	case "0", "false":
		whereParts = append(whereParts, `active = 0`)
	}
	if q := queryText(c); q != "" {
		pattern := likePattern(q)
		whereParts = append(whereParts, `(subject LIKE ? ESCAPE '\' OR parent_subject LIKE ? ESCAPE '\' OR name LIKE ? ESCAPE '\' OR path LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	where := ""
	if len(whereParts) > 0 {
		where = "WHERE " + strings.Join(whereParts, " AND ")
	}
	total, err := queryCount(c.Request.Context(), s.store, `SELECT COUNT(*) FROM provider_groups `+where, args...)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	dataArgs := append(append([]any{}, args...), paging.Limit, paging.Offset)
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT id, provider_slug, subject AS subject_hash, parent_subject AS parent_subject_hash, name, path, active
FROM provider_groups
`+where+`
ORDER BY created_at
LIMIT ? OFFSET ?`, dataArgs...)
	if err != nil {
		writeItems(c, rows, err)
		return
	}
	for _, row := range rows {
		row["subject_hash"] = shortValueHash(row["subject_hash"])
		row["parent_subject_hash"] = shortValueHash(row["parent_subject_hash"])
	}
	writePagedItems(c, rows, total, paging, nil)
}

func (s *Server) groupLinks(c *gin.Context) {
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT l.id, l.provider_group_id, p.name AS provider_group_name, l.dsm_group_id, g.dsm_groupname, l.link_mode
FROM group_links l
JOIN provider_groups p ON p.id = l.provider_group_id
JOIN dsm_groups g ON g.id = l.dsm_group_id
ORDER BY l.created_at`)
	writeItems(c, rows, err)
}

func shortValueHash(value any) any {
	text, ok := value.(string)
	if !ok || text == "" {
		return value
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:16]
}
