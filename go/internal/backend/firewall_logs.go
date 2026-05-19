package backend

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

func (s *Server) recordFirewallAccess(r *http.Request, scope, decision, reason string) {
	database, err := s.openFirewallDatabase(r.Context())
	if err != nil {
		return
	}
	defer database.Close()
	id, err := randomUUID()
	if err != nil {
		id = randomHex(16)
	}
	remoteIP := ""
	if ip := requestRemoteIP(r); ip != nil {
		remoteIP = ip.String()
	}
	ctx := r.Context()
	_, _ = database.ExecContext(ctx, `
INSERT INTO firewall_access_logs (id, scope, decision, remote_ip, method, path, reason)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id,
		scope,
		decision,
		nullableText(remoteIP),
		r.Method,
		r.URL.Path,
		nullableText(reason),
	)
}

func (s *Server) firewallLogs(c *gin.Context) {
	database, err := s.openFirewallDatabase(c.Request.Context())
	if err != nil {
		writeError(c, internalError(err))
		return
	}
	defer database.Close()
	rows, err := database.QueryContext(c.Request.Context(), `
SELECT id, scope, decision, remote_ip, method, path, reason, created_at
FROM firewall_access_logs
ORDER BY created_at DESC
LIMIT 300`)
	if err != nil {
		writeError(c, internalError(err))
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, scope, decision, method, path, createdAt string
		var remoteIP, reason sql.NullString
		if err := rows.Scan(&id, &scope, &decision, &remoteIP, &method, &path, &reason, &createdAt); err != nil {
			writeError(c, internalError(err))
			return
		}
		items = append(items, gin.H{
			"id":         id,
			"scope":      scope,
			"decision":   decision,
			"remote_ip":  nullableString(remoteIP),
			"method":     method,
			"path":       path,
			"reason":     nullableString(reason),
			"created_at": createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		writeError(c, internalError(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *Server) openFirewallDatabase(ctx context.Context) (*sql.DB, error) {
	if err := os.MkdirAll(s.cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", filepath.Join(s.cfg.DataDir, "firewall.db"))
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(2)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(2 * time.Minute)
	if _, err := database.ExecContext(ctx, "PRAGMA busy_timeout = 3000"); err != nil {
		_ = database.Close()
		return nil, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		_ = database.Close()
		return nil, err
	}
	if _, err := database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS firewall_access_logs (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    decision TEXT NOT NULL,
    remote_ip TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_firewall_access_logs_created_at ON firewall_access_logs(created_at DESC);`); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func nullableText(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
