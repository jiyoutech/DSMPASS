package backend

import (
	"context"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func queryJSON(ctx context.Context, q *db.Queries, query string, args ...any) ([]map[string]any, error) {
	rows, err := q.DBTX().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for i, column := range columns {
			switch value := values[i].(type) {
			case nil:
				item[column] = nil
			case []byte:
				item[column] = string(value)
			case int64:
				if column == "active" || column == "allow_login" {
					item[column] = value != 0
				} else {
					item[column] = value
				}
			default:
				item[column] = value
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func queryStringIDs(ctx context.Context, tx db.DBTX, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func deleteByIDs(ctx context.Context, tx db.DBTX, table, column string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+column+` IN (`+placeholders(len(ids))+`)`, anySlice(ids)...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func placeholders(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", count), ",")
}

func anySlice(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}
