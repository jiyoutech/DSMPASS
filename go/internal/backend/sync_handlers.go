package backend

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

func (s *Server) syncApply(c *gin.Context) {
	s.syncProvider(c)
}

func (s *Server) syncProvider(c *gin.Context) {
	result, err := s.runSyncProvider(c.Request.Context(), c.Param("provider"))
	if errors.Is(err, errUnknownProvider) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "unknown provider"})
		return
	}
	if errors.Is(err, errSyncAlreadyRunning) {
		c.JSON(http.StatusConflict, gin.H{"detail": "sync already running"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *Server) runSyncProvider(ctx context.Context, providerSlug string) (syncsvc.Result, error) {
	directory, ok := s.directoryProvider(providerSlug)
	if !ok {
		return syncsvc.Result{}, errUnknownProvider
	}
	if !s.beginSourceSync(directory.Slug()) {
		return syncsvc.Result{}, errSyncAlreadyRunning
	}
	defer s.endSourceSync(directory.Slug())
	runID := "sync_" + randomHex(12)
	var syncStart string
	_ = s.store.DBTX().QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&syncStart)
	_, _ = s.store.DBTX().ExecContext(ctx, `
INSERT INTO sync_runs (id, source_slug, dry_run, status, started_at)
VALUES (?, ?, 0, 'running', CURRENT_TIMESTAMP)
`, runID, directory.Slug())
	q := s.store
	var tx *sql.Tx
	if s.database != nil {
		var err error
		tx, err = s.database.BeginTx(ctx, nil)
		if err != nil {
			return syncsvc.Result{}, err
		}
		q = db.New(tx)
	}
	result, err := syncsvc.NewEngine(s.cfg, q).SyncProvider(ctx, directory)
	if tx != nil {
		if err != nil {
			_ = tx.Rollback()
		} else if commitErr := tx.Commit(); commitErr != nil {
			err = commitErr
		}
	}
	if err != nil {
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?`, err.Error(), runID)
		s.logSyncOperation(ctx, runID, directory.Slug(), "identity_source", directory.Slug(), "", "read_directory", "failed", "running", "failed", err.Error())
		return result, err
	}
	operations, err := s.syncSourceToDSM(ctx, runID, directory.Slug(), syncStart)
	if err != nil {
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?`, err.Error(), runID)
		return result, err
	}
	_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'success', finished_at = CURRENT_TIMESTAMP WHERE id = ?`, runID)
	result.Items = append(result.Items, operations...)
	return result, nil
}

func (s *Server) beginSourceSync(slug string) bool {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if s.syncRuns == nil {
		s.syncRuns = map[string]bool{}
	}
	if s.syncRuns[slug] {
		return false
	}
	s.syncRuns[slug] = true
	return true
}

func (s *Server) endSourceSync(slug string) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	delete(s.syncRuns, slug)
}

func (s *Server) syncSourceToDSM(ctx context.Context, runID, sourceSlug, syncStart string) ([]syncsvc.PlanItem, error) {
	var operations []syncsvc.PlanItem
	if err := s.ensureRealDSMProvisioning(ctx); err != nil {
		return operations, err
	}
	var groupConflicts int
	if err := s.store.DBTX().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM dsm_groups g
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups p ON p.id = l.provider_group_id
WHERE p.provider_slug = ? AND p.active = 1 AND g.provision_status = 'conflict'`, sourceSlug).Scan(&groupConflicts); err != nil {
		return operations, err
	}
	if groupConflicts > 0 {
		err := errors.New("存在飞书部门名冲突，请先由管理员处理部门组名后再同步用户")
		s.logSyncOperation(ctx, runID, sourceSlug, "group", sourceSlug, "", "resolve_group_conflicts", "blocked", "conflict", "conflict", err.Error())
		return operations, err
	}
	accountRows, err := s.store.DBTX().QueryContext(ctx, `
SELECT DISTINCT a.id, a.dsm_username, COALESCE(i.display_name, ''), COALESCE(i.primary_email, ''), a.provision_status
FROM dsm_accounts a
JOIN app_identities i ON i.id = a.app_identity_id
JOIN external_accounts e ON e.app_identity_id = i.id
WHERE e.provider_slug = ? AND e.active = 1 AND a.allow_login = 1 AND a.provision_status IN ('pending', 'failed', 'created')
ORDER BY a.created_at`, sourceSlug)
	if err != nil {
		return operations, err
	}
	for accountRows.Next() {
		var id, username, displayName, email, status string
		if err := accountRows.Scan(&id, &username, &displayName, &email, &status); err != nil {
			accountRows.Close()
			return operations, err
		}
		err := error(nil)
		created, err := s.helper.ProvisionUser(ctx, "sync_user_"+randomHex(8), username, displayName, email, s.initialPasswordForSource(ctx, sourceSlug))
		if err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.logSyncOperation(ctx, runID, sourceSlug, "user", id, username, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		nextStatus := "created"
		action := "sync_dsm_user"
		if !created {
			nextStatus = "linked_existing"
			action = "link_existing_dsm_user"
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = ?, conflict_reason = NULL, allow_login = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, nextStatus, id)
		s.logSyncOperation(ctx, runID, sourceSlug, "user", id, username, "create_or_update", "success", status, nextStatus, "")
		operations = append(operations, syncsvc.PlanItem{Action: action, ProviderSlug: sourceSlug, Subject: id, DSMUsername: username, ProvisionStatus: nextStatus})
	}
	if err := accountRows.Err(); err != nil {
		accountRows.Close()
		return operations, err
	}
	accountRows.Close()

	groupRows, err := s.store.DBTX().QueryContext(ctx, `
SELECT DISTINCT g.id, g.dsm_groupname, g.provision_status
FROM dsm_groups g
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups p ON p.id = l.provider_group_id
WHERE p.provider_slug = ? AND p.active = 1 AND g.provision_status IN ('pending', 'failed', 'created')
ORDER BY g.created_at`, sourceSlug)
	if err != nil {
		return operations, err
	}
	for groupRows.Next() {
		var id, groupname, status string
		if err := groupRows.Scan(&id, &groupname, &status); err != nil {
			groupRows.Close()
			return operations, err
		}
		created, err := s.helper.ProvisionGroup(ctx, "sync_group_"+randomHex(8), groupname)
		if err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_groups SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.logSyncOperation(ctx, runID, sourceSlug, "group", id, groupname, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		if !created {
			s.logSyncOperation(ctx, runID, sourceSlug, "group", id, groupname, "create_or_update", "success", status, "pending", "DSM CLI deferred empty group creation until first member is added")
			operations = append(operations, syncsvc.PlanItem{Action: "defer_dsm_group_until_member", ProviderSlug: sourceSlug, Subject: id, DSMGroupname: groupname, ProvisionStatus: "pending"})
			continue
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_groups SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
		s.logSyncOperation(ctx, runID, sourceSlug, "group", id, groupname, "create_or_update", "success", status, "created", "")
		operations = append(operations, syncsvc.PlanItem{Action: "sync_dsm_group", ProviderSlug: sourceSlug, Subject: id, DSMGroupname: groupname, ProvisionStatus: "created"})
	}
	if err := groupRows.Err(); err != nil {
		groupRows.Close()
		return operations, err
	}
	groupRows.Close()

	memberRows, err := s.store.DBTX().QueryContext(ctx, `
SELECT DISTINCT m.id, g.id, g.dsm_groupname, a.dsm_username, m.provision_status
FROM group_members m
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN dsm_accounts a ON a.id = m.dsm_account_id
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups p ON p.id = l.provider_group_id
WHERE p.provider_slug = ? AND p.active = 1 AND m.active = 1 AND m.provision_status IN ('pending', 'failed', 'created')
ORDER BY m.created_at`, sourceSlug)
	if err != nil {
		return operations, err
	}
	for memberRows.Next() {
		var id, groupID, groupname, username, status string
		if err := memberRows.Scan(&id, &groupID, &groupname, &username, &status); err != nil {
			memberRows.Close()
			return operations, err
		}
		if _, err := s.helper.AddGroupMember(ctx, "sync_member_"+randomHex(8), groupname, username); err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE group_members SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.logSyncOperation(ctx, runID, sourceSlug, "member", id, groupname+":"+username, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_groups SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, groupID)
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE group_members SET provision_status = 'created', active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
		s.logSyncOperation(ctx, runID, sourceSlug, "member", id, groupname+":"+username, "create_or_update", "success", status, "created", "")
		operations = append(operations, syncsvc.PlanItem{Action: "sync_dsm_group_member", ProviderSlug: sourceSlug, Subject: id, DSMUsername: username, DSMGroupname: groupname, ProvisionStatus: "created"})
	}
	if err := memberRows.Err(); err != nil {
		memberRows.Close()
		return operations, err
	}
	memberRows.Close()

	disableRows, err := s.store.DBTX().QueryContext(ctx, `
SELECT DISTINCT e.id, a.id, a.dsm_username
FROM external_accounts e
JOIN dsm_accounts a ON a.app_identity_id = e.app_identity_id
WHERE e.provider_slug = ? AND e.active = 1 AND a.allow_login = 1 AND (e.last_seen_at IS NULL OR e.last_seen_at < ?)`, sourceSlug, syncStart)
	if err != nil {
		return operations, err
	}
	for disableRows.Next() {
		var externalID, accountID, username string
		if err := disableRows.Scan(&externalID, &accountID, &username); err != nil {
			disableRows.Close()
			return operations, err
		}
		if _, err := s.helper.DisableUser(ctx, "sync_disable_"+randomHex(8), username); err != nil {
			s.logSyncOperation(ctx, runID, sourceSlug, "user", accountID, username, "disable_missing", "failed", "active", "active", err.Error())
			return operations, err
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE external_accounts SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, externalID)
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET allow_login = 0, provision_status = 'disabled', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, accountID)
		s.logSyncOperation(ctx, runID, sourceSlug, "user", accountID, username, "disable_missing", "success", "active", "disabled", "")
		operations = append(operations, syncsvc.PlanItem{Action: "disable_missing_dsm_user", ProviderSlug: sourceSlug, Subject: accountID, DSMUsername: username, ProvisionStatus: "disabled"})
	}
	if err := disableRows.Err(); err != nil {
		disableRows.Close()
		return operations, err
	}
	disableRows.Close()

	_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE provider_groups SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE provider_slug = ? AND active = 1 AND updated_at < ?`, sourceSlug, syncStart)
	_, _ = s.store.DBTX().ExecContext(ctx, `
UPDATE group_members SET active = 0, updated_at = CURRENT_TIMESTAMP
WHERE id IN (
	SELECT m.id
	FROM group_members m
	JOIN dsm_groups g ON g.id = m.dsm_group_id
	JOIN group_links l ON l.dsm_group_id = g.id
	JOIN provider_groups p ON p.id = l.provider_group_id
	WHERE p.provider_slug = ? AND p.active = 0
)`, sourceSlug)
	return operations, nil
}

func (s *Server) logSyncOperation(ctx context.Context, runID, sourceSlug, objectType, objectKey, dsmName, action, status, before, after, errorText string) {
	_, _ = s.store.DBTX().ExecContext(ctx, `
INSERT INTO sync_operation_logs (
	id, sync_run_id, source_slug, object_type, object_key, dsm_name, action, status, before_state, after_state, error, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
`, randomHex(16), runID, sourceSlug, objectType, objectKey, nullStringValue(dsmName), action, status, nullStringValue(before), nullStringValue(after), nullStringValue(errorText))
}
