package backend

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) Router() *gin.Engine {
	return s.router(true, true)
}

func (s *Server) AdminRouter() *gin.Engine {
	return s.router(true, false)
}

func (s *Server) IDPRouter() *gin.Engine {
	return s.router(false, true)
}

func (s *Server) router(includeAdmin, includeIDP bool) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/healthz", s.health)
	router.GET("/readyz", s.health)

	if includeAdmin {
		adminNetwork := s.adminAccessControl()
		router.GET("/api/admin/auth/status", adminNetwork, s.adminAuthStatus)
		router.POST("/api/admin/auth/login", adminNetwork, s.adminLogin)
		router.POST("/api/admin/auth/logout", adminNetwork, s.adminLogout)
		router.POST("/api/admin/auth/setup", adminNetwork, s.adminSetup)

		admin := router.Group("/api/admin", adminNetwork, s.adminAuth())
		admin.PUT("/auth/password", s.adminChangePassword)
		admin.GET("/settings", s.getSettings)
		admin.PUT("/settings", s.putSettings)
		admin.POST("/settings/discover", s.discoverSettings)
		admin.POST("/settings/certificates/:scope", s.uploadCertificate)
		admin.POST("/idp-route/restart", s.restartIDPRouteHandler)
		admin.POST("/package/restart", s.restartPackageHandler)
		admin.GET("/version", s.version)
		admin.GET("/helper/status", s.helperStatus)
		admin.POST("/helper/restart", s.restartHelper)
		admin.GET("/provider-types", s.providerTypes)
		admin.GET("/providers", s.providers)
		admin.POST("/providers", s.createProvider)
		admin.PUT("/providers/:slug", s.updateProvider)
		admin.DELETE("/providers/:slug", s.deleteProvider)
		admin.POST("/providers/:slug/reset-sync-data", s.resetProviderSyncData)
		admin.GET("/providers/:slug/sync-runs", s.sourceSyncRuns)
		admin.GET("/providers/:slug/sync-logs", s.sourceSyncLogs)
		admin.GET("/audit/logins", s.loginAuditLogs)
		admin.GET("/audit/admin-operations", s.adminOperationLogs)
		admin.GET("/firewall/logs", s.firewallLogs)
		admin.GET("/external-accounts", s.externalAccounts)
		admin.GET("/identities", s.identities)
		admin.GET("/provider-groups", s.providerGroups)
		admin.GET("/group-links", s.groupLinks)
		admin.GET("/dsm-accounts", s.dsmAccounts)
		admin.PUT("/dsm-accounts/login", s.setDSMAccountsLogin)
		admin.PUT("/dsm-accounts/:id/login", s.setDSMAccountLogin)
		admin.PUT("/dsm-accounts/:id/username", s.setDSMAccountUsername)
		admin.POST("/dsm-accounts/:id/provision", s.provisionDSMAccount)
		admin.GET("/dsm-groups", s.dsmGroups)
		admin.PUT("/dsm-groups/:id/name", s.setDSMGroupName)
		admin.POST("/dsm-groups/:id/provision", s.provisionDSMGroup)
		admin.GET("/group-members", s.groupMembers)
		admin.POST("/group-members/:id/provision", s.provisionGroupMember)
		admin.GET("/security/check", s.securityCheck)
		admin.GET("/relay/journals", s.relayJournals)
		admin.POST("/relay/recover", s.relayRecover)

		sync := router.Group("/api/sync/:provider", adminNetwork, s.adminAuth())
		sync.POST("/apply", s.syncApply)
	}

	if includeIDP {
		idp := router.Group("/idp/:provider", s.idpAccessControl())
		idp.GET("/launch", s.launch)
		idp.GET("/callback", s.callback)
		idp.POST("/browser-login/complete", s.completeBrowserLogin)
	}

	if includeAdmin {
		router.NoRoute(s.adminAccessControl(), s.frontend)
	}
	return router
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
