package db

import (
	"modernc.org/sqlite"
	"strings"
)

// SQLite's built-in NOCASE folds ASCII only. Use the directory planner's
// Unicode case and whitespace rules for live ownership checks as well.
func init() {
	sqlite.MustRegisterCollationUtf8("dsmpass_name", func(left, right string) int {
		return strings.Compare(strings.ToLower(strings.TrimSpace(left)), strings.ToLower(strings.TrimSpace(right)))
	})
}
