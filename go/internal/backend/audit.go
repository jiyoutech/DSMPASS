package backend

import (
	"context"
	"database/sql"
	"net"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

type loginAuditEvent struct {
	RequestID         string
	Provider          string
	ExternalAccountID string
	AppIdentityID     string
	DSMUsername       string
	Result            string
	ErrorCode         string
	IPAddress         string
	DurationMs        int64
}

func (s *Server) logLoginAudit(ctx context.Context, event loginAuditEvent) {
	_ = s.store.CreateLoginAuditLog(ctx, db.CreateLoginAuditLogParams{
		ID:                randomHex(16),
		RequestID:         event.RequestID,
		ProviderSlug:      event.Provider,
		ExternalAccountID: nullStringValue(event.ExternalAccountID),
		AppIdentityID:     nullStringValue(event.AppIdentityID),
		DSMUsername:       nullStringValue(event.DSMUsername),
		Result:            event.Result,
		ErrorCode:         nullStringValue(event.ErrorCode),
		IPAddress:         nullStringValue(event.IPAddress),
		DurationMs:        sql.NullInt64{Int64: event.DurationMs, Valid: true},
	})
	s.maybeCleanupLogs(ctx)
}

func requestClientIP(c *gin.Context) string {
	if forwarded := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); forwarded != "" {
		if comma := strings.Index(forwarded, ","); comma >= 0 {
			forwarded = forwarded[:comma]
		}
		if ip := net.ParseIP(strings.TrimSpace(forwarded)); ip != nil {
			return ip.String()
		}
	}
	if realIP := strings.TrimSpace(c.GetHeader("X-Real-IP")); realIP != "" {
		if ip := net.ParseIP(realIP); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(c.ClientIP()); ip != nil {
		return ip.String()
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err == nil {
		return host
	}
	return c.Request.RemoteAddr
}
