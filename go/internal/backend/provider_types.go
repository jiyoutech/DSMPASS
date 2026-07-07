package backend

import (
	"strings"

	"github.com/gin-gonic/gin"
)

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
			"display_name":         providerTypeDisplayName("feishu"),
			"supports_login":       true,
			"supports_sync":        true,
			"requires_client_id":   true,
			"requires_secret":      true,
			"supports_authorize":   true,
			"supports_contact_api": true,
		},
		{
			"type":                 "wecom",
			"display_name":         providerTypeDisplayName("wecom"),
			"supports_login":       true,
			"supports_sync":        true,
			"requires_client_id":   true,
			"requires_secret":      true,
			"requires_agent_id":    true,
			"supports_authorize":   true,
			"supports_contact_api": true,
		},
		{
			"type":                 "dingtalk",
			"display_name":         providerTypeDisplayName("dingtalk"),
			"supports_login":       true,
			"supports_sync":        true,
			"requires_client_id":   true,
			"requires_secret":      true,
			"supports_authorize":   true,
			"supports_contact_api": true,
		},
	}
}

func providerTypeDisplayName(providerType string) string {
	providerType = strings.TrimSpace(providerType)
	switch providerType {
	case "feishu":
		return "飞书"
	case "wecom":
		return "企业微信"
	case "dingtalk":
		return "钉钉"
	default:
		if strings.HasPrefix(providerType, "feishu") {
			return "飞书"
		}
		if strings.HasPrefix(providerType, "wecom") {
			return "企业微信"
		}
		if strings.HasPrefix(providerType, "dingtalk") {
			return "钉钉"
		}
		return "身份源"
	}
}
