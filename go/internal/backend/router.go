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
		router.GET("/api/admin/auth/status", s.adminAuthStatus)
		router.POST("/api/admin/auth/login", s.adminLogin)
		router.POST("/api/admin/auth/logout", s.adminLogout)
		router.POST("/api/admin/auth/setup", s.adminSetup)

		admin := router.Group("/api/admin", s.adminAuth())
		admin.PUT("/auth/password", s.adminChangePassword)
		admin.GET("/settings", s.getSettings)
		admin.PUT("/settings", s.putSettings)
		admin.POST("/settings/discover", s.discoverSettings)
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
		admin.GET("/external-accounts", s.externalAccounts)
		admin.GET("/identities", s.identities)
		admin.GET("/provider-groups", s.providerGroups)
		admin.GET("/group-links", s.groupLinks)
		admin.GET("/dsm-accounts", s.dsmAccounts)
		admin.PUT("/dsm-accounts/login", s.setDSMAccountsLogin)
		admin.PUT("/dsm-accounts/:id/login", s.setDSMAccountLogin)
		admin.POST("/dsm-accounts/:id/provision", s.provisionDSMAccount)
		admin.GET("/dsm-groups", s.dsmGroups)
		admin.POST("/dsm-groups/:id/provision", s.provisionDSMGroup)
		admin.GET("/group-members", s.groupMembers)
		admin.POST("/group-members/:id/provision", s.provisionGroupMember)
		admin.GET("/security/check", s.securityCheck)
		admin.GET("/relay/journals", s.relayJournals)
		admin.POST("/relay/recover", s.relayRecover)

		sync := router.Group("/api/sync/:provider", s.adminAuth())
		sync.POST("/apply", s.syncApply)
	}

	if includeIDP {
		idp := router.Group("/idp/:provider")
		idp.GET("/launch", s.launch)
		idp.GET("/callback", s.callback)
		idp.POST("/browser-login/complete", s.completeBrowserLogin)
	}

	if includeAdmin {
		router.NoRoute(s.frontend)
	}
	return router
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
