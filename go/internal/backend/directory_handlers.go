package backend

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) loginAuditLogs(c *gin.Context) {
	providerSlug := c.Query("provider")
	if providerSlug == "" {
		rows, err := s.store.ListLoginAuditLogs(c.Request.Context(), 200)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
			return
		}
		items := make([]gin.H, 0, len(rows))
		for _, row := range rows {
			items = append(items, gin.H{
				"id":                  row.ID,
				"request_id":          row.RequestID,
				"provider_slug":       row.ProviderSlug,
				"external_account_id": nullableString(row.ExternalAccountID),
				"app_identity_id":     nullableString(row.AppIdentityID),
				"dsm_username":        nullableString(row.DSMUsername),
				"result":              row.Result,
				"error_code":          nullableString(row.ErrorCode),
				"ip_address":          nullableString(row.IPAddress),
				"ip_hash":             nullableString(row.IPHash),
				"user_agent_hash":     nullableString(row.UserAgentHash),
				"duration_ms":         nullableInt64(row.DurationMs),
				"created_at":          row.CreatedAt,
			})
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
		return
	}
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT id, request_id, provider_slug, external_account_id, app_identity_id, dsm_username, result, error_code, ip_address, ip_hash, user_agent_hash, duration_ms, created_at
FROM login_audit_logs
WHERE provider_slug = ?
ORDER BY created_at DESC
LIMIT 200`, providerSlug)
	writeItems(c, rows, err)
}

func (s *Server) externalAccounts(c *gin.Context) {
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT id, provider_slug, substr(hex(sha256(subject)), 1, 16) AS subject_hash, subject_type, display_name, email, email_verified, mobile_masked, active, app_identity_id, last_seen_at, last_login_at
FROM external_accounts ORDER BY created_at`)
	if err != nil {
		rows, err = queryJSON(c.Request.Context(), s.store, `
SELECT id, provider_slug, subject AS subject_hash, subject_type, display_name, email, email_verified, mobile_masked, active, app_identity_id, last_seen_at, last_login_at
FROM external_accounts ORDER BY created_at`)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows})
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
	rows, err := queryJSON(c.Request.Context(), s.store, `
SELECT id, provider_slug, subject AS subject_hash, parent_subject AS parent_subject_hash, name, path, active
FROM provider_groups ORDER BY created_at`)
	writeItems(c, rows, err)
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
