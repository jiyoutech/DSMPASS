package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

type pendingAccountProvision struct {
	id          string
	username    string
	displayName string
	email       string
	status      string
}

func (s *Server) provisionUserBatch(ctx context.Context, client helperclient.UserBatchClient, batch []pendingAccountProvision, password string, full bool) ([]helperclient.UserProvisionOutcome, error) {
	if client != nil {
		users := make([]helperclient.UserProfile, len(batch))
		for i, item := range batch {
			users[i] = helperclient.UserProfile{Username: item.username, DisplayName: item.displayName, Email: item.email}
		}
		result, err := client.ProvisionUsers(ctx, "sync_users_"+randomHex(8), users, password)
		if err == nil && len(result) != len(users) {
			return nil, errors.New("incomplete DSM user batch confirmation")
		}
		return result, err
	}
	item := batch[0]
	id := "sync_user_" + randomHex(8)
	var result helperclient.UserProvisionOutcome
	if c, ok := s.helper.(helperclient.UserProvisionResultClient); ok && full {
		result.ProvisionUserResult, result.Err = c.ProvisionUserWithResult(ctx, id, item.username, item.displayName, item.email, password)
	} else {
		result.Created, result.Err = s.helper.ProvisionUser(ctx, id, item.username, item.displayName, item.email, password)
	}
	return []helperclient.UserProvisionOutcome{result}, nil
}

// Native work completes outside the SQLite write transaction. Only confirmed
// outcomes are reflected locally, together, before progress is published.
func (s *Server) saveSyncUserBatch(ctx context.Context, batch []pendingAccountProvision, results []helperclient.UserProvisionOutcome) error {
	return s.withSyncTransaction(ctx, func(tx db.DBTX) error {
		for i, item := range batch {
			result := results[i]
			if result.Err != nil {
				if err := saveObjectState(ctx, tx, item.username, `UPDATE dsm_accounts SET provision_status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=? AND dsm_username=?`, item.id, item.username); err != nil {
					return errors.Join(result.Err, err)
				}
				continue
			}
			status := "linked_existing"
			if result.Created {
				status = "created"
			}
			if err := saveObjectState(ctx, tx, item.username, `UPDATE dsm_accounts SET provision_status=?,conflict_reason=NULL,allow_login=(manual_login_blocked=0),updated_at=CURRENT_TIMESTAMP WHERE id=? AND dsm_username=?`, status, item.id, item.username); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Server) pendingSourceAccounts(ctx context.Context, sourceSlug string, policy sourceSyncPolicy) ([]pendingAccountProvision, error) {
	accountRows, err := s.store.DBTX().QueryContext(ctx, `
	SELECT DISTINCT a.id, a.dsm_username, COALESCE(i.display_name, ''), COALESCE(i.primary_email, ''), a.provision_status
		FROM dsm_accounts a
		JOIN app_identities i ON i.id = a.app_identity_id
		JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id
		WHERE me.provider_slug = ? AND me.mapping_type = 'user' AND me.active = 1 AND a.provision_status IN ('pending', 'failed', 'created', 'linked_existing', 'disabled')
		AND (NOT ? OR EXISTS (SELECT 1 FROM external_accounts e WHERE e.id=me.external_account_id AND e.provider_slug=me.provider_slug AND e.app_identity_id=i.id AND e.active=1))
        ORDER BY a.created_at`, sourceSlug, policy.DingTalk)
	if err != nil {
		return nil, err
	}
	var pendingAccounts []pendingAccountProvision
	for accountRows.Next() {
		var item pendingAccountProvision
		if err := accountRows.Scan(&item.id, &item.username, &item.displayName, &item.email, &item.status); err != nil {
			accountRows.Close()
			return nil, err
		}
		pendingAccounts = append(pendingAccounts, item)
	}
	if err := accountRows.Err(); err != nil {
		accountRows.Close()
		return nil, err
	}
	accountRows.Close()
	return pendingAccounts, nil
}

func (s *Server) readSyncAccountPlan(ctx context.Context, runID, sourceSlug string, policy sourceSyncPolicy, logBuffer *syncLogBuffer, progress *operationProgress) (map[pendingAccountProvision]helperclient.DirectoryAccountState, error) {
	reader, ok := s.helper.(helperclient.DirectorySnapshotClient)
	if !ok {
		return nil, nil
	}
	started := time.Now()
	accounts, err := s.pendingSourceAccounts(ctx, sourceSlug, policy)
	if err != nil {
		return nil, err
	}
	profiles := make([]helperclient.UserProfile, len(accounts))
	for i, a := range accounts {
		profiles[i] = helperclient.UserProfile{Username: a.username, Email: a.email, DisplayName: a.displayName}
	}
	if progress != nil {
		progress.message(ctx, "读取 DSM", "正在分页核对 DSM 用户和本地群组")
	}
	states, err := reader.DirectorySnapshot(ctx, runID, profiles)
	if err != nil {
		return nil, fmt.Errorf("读取 DSM 完整目录失败: %w", err)
	}
	var missing, unchanged int
	for _, state := range states {
		switch state {
		case helperclient.DirectoryMissing:
			missing++
		case helperclient.DirectoryUnchanged:
			unchanged++
		}
	}
	detail := fmt.Sprintf("目标 %d 人，待建 %d 人，资料一致 %d 人，需复核 %d 人，用时 %s", len(accounts), missing, unchanged, len(accounts)-missing-unchanged, time.Since(started).Round(time.Millisecond))
	s.writeSyncOperation(logBuffer, runID, sourceSlug, "directory", sourceSlug, "", "read_dsm_snapshot", "success", "", "", detail)
	if progress != nil {
		progress.message(ctx, "读取 DSM", detail)
	}
	plan := make(map[pendingAccountProvision]helperclient.DirectoryAccountState, len(accounts))
	for _, a := range accounts {
		plan[a] = states[a.username]
	}
	return plan, nil
}
