package backend

import (
	"context"
	"strconv"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

const (
	logRetentionDays              = 90
	logCleanupInterval            = time.Hour
	maxSyncOperationLogsPerSource = 100000
	maxLoginAuditLogsPerProvider  = 50000
)

func (s *Server) maybeCleanupLogs(ctx context.Context) {
	s.logCleanupMu.Lock()
	if time.Since(s.lastLogCleanup) < logCleanupInterval {
		s.logCleanupMu.Unlock()
		return
	}
	s.lastLogCleanup = time.Now()
	s.logCleanupMu.Unlock()
	_ = s.cleanupLogs(ctx)
}

func (s *Server) cleanupLogs(ctx context.Context) error {
	if err := cleanupOldLogs(ctx, s.store.DBTX(), "sync_operation_logs"); err != nil {
		return err
	}
	if err := cleanupOldLogs(ctx, s.store.DBTX(), "login_audit_logs"); err != nil {
		return err
	}
	if err := cleanupSyncOperationLogCaps(ctx, s.store.DBTX()); err != nil {
		return err
	}
	return cleanupLoginAuditLogCaps(ctx, s.store.DBTX())
}

func cleanupOldLogs(ctx context.Context, tx db.DBTX, table string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE created_at < datetime('now', ?)`, "-"+strconv.Itoa(logRetentionDays)+" days")
	return err
}

func cleanupSyncOperationLogCaps(ctx context.Context, tx db.DBTX) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT source_slug FROM sync_operation_logs`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var sources []string
	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			return err
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, source := range sources {
		if _, err := tx.ExecContext(ctx, `
DELETE FROM sync_operation_logs
WHERE source_slug = ?
  AND id NOT IN (
    SELECT id FROM sync_operation_logs
    WHERE source_slug = ?
    ORDER BY created_at DESC, id DESC
    LIMIT ?
  )`, source, source, maxSyncOperationLogsPerSource); err != nil {
			return err
		}
	}
	return nil
}

func cleanupLoginAuditLogCaps(ctx context.Context, tx db.DBTX) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT provider_slug FROM login_audit_logs`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var providers []string
	for rows.Next() {
		var provider string
		if err := rows.Scan(&provider); err != nil {
			return err
		}
		providers = append(providers, provider)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, provider := range providers {
		if _, err := tx.ExecContext(ctx, `
DELETE FROM login_audit_logs
WHERE provider_slug = ?
  AND id NOT IN (
    SELECT id FROM login_audit_logs
    WHERE provider_slug = ?
    ORDER BY created_at DESC, id DESC
    LIMIT ?
  )`, provider, provider, maxLoginAuditLogsPerProvider); err != nil {
			return err
		}
	}
	return nil
}
