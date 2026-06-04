package backend

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type operationProgress struct {
	server    *Server
	id        string
	kind      string
	source    string
	phase     string
	total     int
	current   int
	lastFlush time.Time
	lastEvent time.Time
}

func (s *Server) createOperationRun(ctx context.Context, kind, sourceSlug, phase, message string, total int) (*operationProgress, error) {
	id := "op_" + randomHex(12)
	if total < 0 {
		total = 0
	}
	if _, err := s.logs().DBTX().ExecContext(ctx, `
INSERT INTO operation_runs (id, kind, source_slug, status, phase, message, current, total, started_at, updated_at)
VALUES (?, ?, ?, 'running', ?, ?, 0, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, id, kind, nullStringValue(sourceSlug), phase, message, total); err != nil {
		return nil, err
	}
	progress := &operationProgress{
		server:    s,
		id:        id,
		kind:      kind,
		source:    sourceSlug,
		phase:     phase,
		total:     total,
		current:   0,
		lastFlush: time.Now(),
	}
	progress.event(ctx, phase, message, "running", "")
	return progress, nil
}

func (p *operationProgress) setTotal(ctx context.Context, phase, message string, total int) {
	if p == nil {
		return
	}
	if total < 0 {
		total = 0
	}
	p.phase = phase
	p.total = total
	p.current = 0
	p.lastFlush = time.Now()
	_, _ = p.server.logs().DBTX().ExecContext(ctx, `
UPDATE operation_runs
SET phase = ?, message = ?, current = 0, total = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, phase, message, total, p.id)
	p.event(ctx, phase, message, "running", "")
}

func (p *operationProgress) step(ctx context.Context, phase, message string) {
	if p == nil {
		return
	}
	p.current++
	if p.total > 0 && p.current > p.total {
		p.total = p.current
	}
	p.report(ctx, phase, p.current, p.total, message)
	if time.Since(p.lastEvent) >= 2*time.Second || p.current == p.total {
		p.event(ctx, phase, message, "running", "")
	}
}

func (p *operationProgress) report(ctx context.Context, phase string, current, total int, message string) {
	if p == nil {
		return
	}
	phaseChanged := phase != p.phase
	p.phase = phase
	p.current = current
	p.total = total
	if total < 0 {
		p.total = 0
	}
	if !phaseChanged && current != total && time.Since(p.lastFlush) < 250*time.Millisecond {
		return
	}
	p.lastFlush = time.Now()
	_, _ = p.server.logs().DBTX().ExecContext(ctx, `
UPDATE operation_runs
SET phase = ?, message = ?, current = ?, total = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, phase, message, current, p.total, p.id)
}

func (p *operationProgress) message(ctx context.Context, phase, message string) {
	if p == nil {
		return
	}
	p.phase = phase
	_, _ = p.server.logs().DBTX().ExecContext(ctx, `
UPDATE operation_runs
SET phase = ?, message = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, phase, message, p.id)
	p.event(ctx, phase, message, "running", "")
}

func (p *operationProgress) complete(ctx context.Context, message string) {
	if p == nil {
		return
	}
	if strings.TrimSpace(message) == "" {
		message = "已完成"
	}
	current := p.current
	if p.total > 0 {
		current = p.total
	}
	_, _ = p.server.logs().DBTX().ExecContext(ctx, `
UPDATE operation_runs
SET status = 'success', message = ?, current = ?, finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, message, current, p.id)
	p.current = current
	p.event(ctx, p.phase, message, "success", "")
}

func (p *operationProgress) fail(ctx context.Context, err error) {
	if p == nil || err == nil {
		return
	}
	message := err.Error()
	_, _ = p.server.logs().DBTX().ExecContext(ctx, `
UPDATE operation_runs
SET status = 'failed', message = ?, error = ?, finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE id = ?`, message, message, p.id)
	p.event(ctx, p.phase, message, "failed", message)
}

func (p *operationProgress) event(ctx context.Context, phase, message, status, errorText string) {
	if p == nil {
		return
	}
	p.lastEvent = time.Now()
	_, _ = p.server.logs().DBTX().ExecContext(ctx, `
INSERT INTO operation_events (id, operation_run_id, source_slug, kind, phase, message, current, total, status, error, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
`, randomHex(16), p.id, nullStringValue(p.source), p.kind, phase, message, p.current, p.total, status, nullStringValue(errorText))
}

func (s *Server) operationRun(c *gin.Context) {
	runID := strings.TrimSpace(c.Param("id"))
	rows, err := queryJSON(c.Request.Context(), s.logs(), `
SELECT id, kind, source_slug, status, phase, message, current, total, started_at, updated_at, finished_at, error
FROM operation_runs
WHERE id = ?`, runID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	if len(rows) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "operation run not found"})
		return
	}
	c.JSON(http.StatusOK, rows[0])
}

func (s *Server) operationRunEvents(c *gin.Context) {
	runID := strings.TrimSpace(c.Param("id"))
	paging := parsePagination(c)
	dataArgs := []any{runID, paging.Limit, paging.Offset}
	total, err := queryCount(c.Request.Context(), s.logs(), `SELECT COUNT(*) FROM operation_events WHERE operation_run_id = ?`, runID)
	if err != nil {
		writeItems(c, nil, err)
		return
	}
	rows, err := queryJSON(c.Request.Context(), s.logs(), `
SELECT id, operation_run_id, source_slug, kind, phase, message, current, total, status, error, created_at
FROM operation_events
WHERE operation_run_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?`, dataArgs...)
	writePagedItems(c, rows, total, paging, err)
}
