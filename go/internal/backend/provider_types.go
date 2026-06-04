package backend

import "github.com/gin-gonic/gin"

func (s *Server) providerTypes(c *gin.Context) {
	c.JSON(200, gin.H{"items": supportedProviderTypes()})
}

func supportedProviderType(providerType string) bool {
	for _, item := range supportedProviderTypes() {
		if item["type"] == providerType {
			return true
		}
	}
	return false
}

func supportedProviderTypes() []gin.H {
	return []gin.H{
		{
			"type":                 "feishu",
			"display_name":         "飞书",
			"supports_login":       true,
			"supports_sync":        true,
			"requires_client_id":   true,
			"requires_secret":      true,
			"supports_authorize":   true,
			"supports_contact_api": true,
		},
	}
}
