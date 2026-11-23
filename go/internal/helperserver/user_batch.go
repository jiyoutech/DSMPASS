package helperserver

import (
	"context"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

// Validate the envelope before writing the first account. If the caller disconnects,
// finish the in-flight native mutation and leave subsequent rows for a later sync.
func (s *Server) provisionAccounts(ctx context.Context, cfg config.HelperConfig, payload map[string]any) map[string]any {
	raw, ok := payload["dsm_users"].([]any)
	password, hasPassword := payload["initial_password"].(string)
	if !ok || !hasPassword || len(raw) == 0 || len(raw) > helperclient.UserProvisionBatchSize {
		return errorResponse("BAD_REQUEST", "invalid user batch")
	}
	rows := make([]map[string]any, len(raw))
	seen := map[string]bool{}
	for i, entry := range raw {
		row, ok := entry.(map[string]any)
		name, err := requiredString(row, "dsm_username")
		key := strings.ToLower(name)
		displayName, hasDisplay := row["display_name"].(string)
		email, hasEmail := row["email"].(string)
		if !ok || err != nil || seen[key] || !hasDisplay || !hasEmail {
			return errorResponse("BAD_REQUEST", "invalid or duplicate user batch entry")
		}
		seen[key] = true
		rows[i] = map[string]any{"dsm_username": name, "display_name": displayName, "email": email, "initial_password": password}
	}
	results := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if ctx.Err() != nil {
			return errorResponse("USER_BATCH_INTERRUPTED", "user batch interrupted; reconcile confirmed identities on next sync")
		}
		result := s.provisionAccount(cfg, row)
		result["dsm_username"] = row["dsm_username"]
		results = append(results, result)
	}
	return map[string]any{"success": true, "user_results": results}
}
