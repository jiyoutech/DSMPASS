package backend

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) securityCheck(c *gin.Context) {
	var pendingAccounts, pendingGroups, conflictAccounts, conflictGroups int64
	_ = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM dsm_accounts WHERE provision_status = 'pending'`).Scan(&pendingAccounts)
	_ = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM dsm_groups WHERE provision_status = 'pending'`).Scan(&pendingGroups)
	_ = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM dsm_accounts WHERE provision_status = 'conflict'`).Scan(&conflictAccounts)
	_ = s.store.DBTX().QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM dsm_groups WHERE provision_status = 'conflict'`).Scan(&conflictGroups)
	items := []gin.H{
		check("source_public_base_url_https", s.identitySourcePublicURLsUseHTTPS(c.Request.Context()), "Enabled identity source public URLs should use HTTPS in production.", false),
		check("cookie_secure", s.cfg.DSMCookieSecure, "DSM cookie must use Secure in production.", false),
		check("helper_secret_configured", s.cfg.RelayHelperHMACSecret != "", "Configure DSMPASS_HELPER_HMAC_SECRET.", false),
		check("pending_provisioning", pendingAccounts+pendingGroups == 0, "Provision pending DSM users and groups.", true),
		check("account_conflicts", conflictAccounts == 0, "Resolve DSM account name conflicts.", false),
		check("group_conflicts", conflictGroups == 0, "Resolve DSM group name conflicts.", false),
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *Server) identitySourcePublicURLsUseHTTPS(ctx context.Context) bool {
	rows, err := s.store.DBTX().QueryContext(ctx, `
SELECT config_json
FROM identity_sources
WHERE enabled = 1 AND login_enabled = 1`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false
		}
		config := decodeSourceConfig(raw)
		publicBaseURL := strings.TrimSpace(config.PublicBaseURL)
		if publicBaseURL == "" {
			publicBaseURL = s.cfg.PublicBaseURL
		}
		if !strings.HasPrefix(publicBaseURL, "https://") {
			return false
		}
	}
	return rows.Err() == nil
}

func (s *Server) relayJournals(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": []gin.H{}})
}

func (s *Server) relayRecover(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true, "recovered": 0})
}

func (s *Server) adminOperationLogs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": []gin.H{}})
}
