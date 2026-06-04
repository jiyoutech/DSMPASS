package backend

import (
	"context"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

type paginationParams struct {
	Page   int
	Limit  int
	Offset int
}

func parsePagination(c *gin.Context) paginationParams {
	page := parsePositiveInt(c.Query("page"), 1)
	limit := parsePositiveInt(c.Query("limit"), defaultPageLimit)
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	return paginationParams{Page: page, Limit: limit, Offset: (page - 1) * limit}
}

func parsePositiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func queryCount(ctx context.Context, q *db.Queries, query string, args ...any) (int64, error) {
	var count int64
	err := q.DBTX().QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func writePagedItems(c *gin.Context, rows []map[string]any, total int64, paging paginationParams, err error) {
	if err != nil {
		writeItems(c, rows, err)
		return
	}
	c.JSON(200, gin.H{
		"items":  rows,
		"page":   paging.Page,
		"limit":  paging.Limit,
		"total":  total,
		"offset": paging.Offset,
	})
}

func likePattern(raw string) string {
	value := strings.TrimSpace(raw)
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return "%" + value + "%"
}

func queryText(c *gin.Context) string {
	return strings.TrimSpace(c.Query("q"))
}
