package backend

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

func (s *Server) syncApply(c *gin.Context) {
	s.syncProvider(c)
}

func (s *Server) startProviderSyncRun(c *gin.Context) {
	sourceSlug := c.Param("slug")
	if _, ok := s.directoryProvider(sourceSlug); !ok {
		c.JSON(http.StatusNotFound, gin.H{"detail": "unknown provider"})
		return
	}
	progress, err := s.createOperationRun(c.Request.Context(), "sync", sourceSlug, "等待开始", "同步任务已创建", 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	go func() {
		ctx := context.Background()
		_, err := s.runSyncProviderWithProgress(ctx, sourceSlug, progress)
		if err != nil {
			progress.fail(ctx, err)
			return
		}
		progress.complete(ctx, "同步完成")
	}()
	c.JSON(http.StatusAccepted, gin.H{"run_id": progress.id})
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
	return s.runSyncProviderWithProgress(ctx, providerSlug, nil)
}

func (s *Server) runSyncProviderWithProgress(ctx context.Context, providerSlug string, progress *operationProgress) (syncsvc.Result, error) {
	defer s.maybeCleanupLogs(ctx)
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
	_, _ = s.logs().DBTX().ExecContext(ctx, `
INSERT INTO sync_runs (id, source_slug, dry_run, status, started_at)
VALUES (?, ?, 0, 'running', CURRENT_TIMESTAMP)
ON CONFLICT(id) DO NOTHING
`, runID, directory.Slug())
	logBuffer := s.newSyncLogBuffer(ctx)
	defer func() { _ = logBuffer.Flush() }()
	policy := s.sourceSyncPolicy(ctx, directory.Slug())
	if progress != nil {
		progress.message(ctx, "读取身份源", "正在读取身份源通讯录")
	}
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
	result, err := syncsvc.NewEngineWithOptions(s.cfg, q, syncsvc.Options{
		DeactivateMissingData: policy.DeactivateMissingData,
		SyncStart:             syncStart,
		Progress: func(phase string, current, total int, message string) {
			if progress == nil {
				return
			}
			progress.report(ctx, phase, current, total, message)
		},
	}).SyncProvider(ctx, directory)
	if tx != nil {
		if err != nil {
			_ = tx.Rollback()
		} else if commitErr := tx.Commit(); commitErr != nil {
			err = commitErr
		}
	}
	if err != nil {
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?`, err.Error(), runID)
		_, _ = s.logs().DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?`, err.Error(), runID)
		logBuffer.Log(runID, directory.Slug(), "identity_source", directory.Slug(), "", "read_directory", "failed", "running", "failed", err.Error())
		_ = logBuffer.Flush()
		return result, err
	}
	if progress != nil {
		progress.message(ctx, "写入同步日志", "正在记录映射结果")
	}
	s.logDirectoryLinkPlanWithBuffer(logBuffer, runID, directory.Slug(), result.Items)
	if syncResultHasDirectoryWarning(result) {
		policy.PreserveMissingGroups = true
	}
	operations, err := s.syncSourceToDSMWithBuffer(ctx, runID, directory.Slug(), syncStart, policy, logBuffer, progress)
	if err != nil {
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?`, err.Error(), runID)
		_, _ = s.logs().DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, error = ? WHERE id = ?`, err.Error(), runID)
		_ = logBuffer.Flush()
		return result, err
	}
	_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'success', finished_at = CURRENT_TIMESTAMP WHERE id = ?`, runID)
	_, _ = s.logs().DBTX().ExecContext(ctx, `UPDATE sync_runs SET status = 'success', finished_at = CURRENT_TIMESTAMP WHERE id = ?`, runID)
	_ = logBuffer.Flush()
	result.Items = append(result.Items, operations...)
	return result, nil
}

func (s *Server) logDirectoryLinkPlan(ctx context.Context, runID, sourceSlug string, items []syncsvc.PlanItem) {
	s.logDirectoryLinkPlanWithBuffer(nil, runID, sourceSlug, items)
}

func (s *Server) logDirectoryLinkPlanWithBuffer(buffer *syncLogBuffer, runID, sourceSlug string, items []syncsvc.PlanItem) {
	for _, item := range items {
		switch item.Action {
		case "link_existing_dsm_user":
			s.writeSyncOperation(buffer, runID, sourceSlug, "user", item.Subject, item.DSMUsername, item.Action, "success", "unlinked", "linked_existing", "跨身份源同名用户，自动按同一人关联")
		case "link_existing_dsm_group":
			s.writeSyncOperation(buffer, runID, sourceSlug, "group", item.Subject, item.DSMGroupname, item.Action, "success", "unlinked", "linked_existing", "跨身份源同名部门，自动按同一部门关联")
		case "directory_warning":
			message := strings.TrimSpace(item.DisplayName)
			if message == "" {
				message = "身份源同步提示"
			}
			s.writeSyncOperation(buffer, runID, sourceSlug, "identity_source", item.Subject, "", item.Action, "warning", "", "warning", message)
		}
	}
}

func syncResultHasDirectoryWarning(result syncsvc.Result) bool {
	for _, item := range result.Items {
		if item.Action == "directory_warning" {
			return true
		}
	}
	return false
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

type sourceSyncPolicy struct {
	DisableMissingUsers   bool
	DeactivateMissingData bool
	PreserveMissingGroups bool
}

func (s *Server) sourceSyncPolicy(ctx context.Context, sourceSlug string) sourceSyncPolicy {
	source, err := s.loadIdentitySource(ctx, sourceSlug)
	if err != nil {
		return sourceSyncPolicy{DisableMissingUsers: false, DeactivateMissingData: true}
	}
	cfg := decodeSourceConfigForType(source.ProviderType, source.ConfigJSON)
	return sourceSyncPolicy{
		DisableMissingUsers:   boolValue(cfg.DisableMissingUsers, false),
		DeactivateMissingData: boolValue(cfg.DeactivateMissingData, true),
	}
}

func (s *Server) syncSourceToDSM(ctx context.Context, runID, sourceSlug, syncStart string, policy sourceSyncPolicy) ([]syncsvc.PlanItem, error) {
	return s.syncSourceToDSMWithBuffer(ctx, runID, sourceSlug, syncStart, policy, nil, nil)
}

func (s *Server) syncSourceToDSMWithBuffer(ctx context.Context, runID, sourceSlug, syncStart string, policy sourceSyncPolicy, logBuffer *syncLogBuffer, progress *operationProgress) ([]syncsvc.PlanItem, error) {
	var operations []syncsvc.PlanItem
	if err := s.ensureRealDSMProvisioning(ctx); err != nil {
		return operations, err
	}
	if policy.DeactivateMissingData {
		if policy.PreserveMissingGroups {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE external_accounts SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE provider_slug = ? AND active = 1 AND updated_at < ?`, sourceSlug, syncStart)
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_mapping_entries SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE provider_slug = ? AND mapping_type = 'user' AND active = 1 AND updated_at < ?`, sourceSlug, syncStart)
		} else {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE provider_groups SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE provider_slug = ? AND active = 1 AND updated_at < ?`, sourceSlug, syncStart)
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE external_accounts SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE provider_slug = ? AND active = 1 AND updated_at < ?`, sourceSlug, syncStart)
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_mapping_entries SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE provider_slug = ? AND active = 1 AND updated_at < ?`, sourceSlug, syncStart)
		}
	}
	var groupConflicts, accountConflicts int
	if err := s.store.DBTX().QueryRowContext(ctx, `
	SELECT COUNT(*)
		FROM dsm_groups g
		JOIN group_links l ON l.dsm_group_id = g.id
		JOIN provider_groups p ON p.id = l.provider_group_id
		WHERE p.provider_slug = ? AND p.active = 1 AND g.provision_status = 'conflict'`, sourceSlug).Scan(&groupConflicts); err != nil {
		return operations, err
	}
	if err := s.store.DBTX().QueryRowContext(ctx, `
	SELECT COUNT(*)
	FROM dsm_accounts a
	JOIN external_accounts e ON e.app_identity_id = a.app_identity_id
	WHERE e.provider_slug = ? AND e.active = 1 AND a.provision_status = 'conflict'`, sourceSlug).Scan(&accountConflicts); err != nil {
		return operations, err
	}
	providerName := s.providerDisplayNameForSourceSlug(ctx, sourceSlug)
	if groupConflicts > 0 {
		err := errors.New("存在" + providerName + "部门名冲突，请先由管理员处理部门组名后再同步 DSM")
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "group", sourceSlug, "", "resolve_group_conflicts", "blocked", "conflict", "conflict", err.Error())
		if progress != nil {
			progress.message(ctx, "等待冲突处理", err.Error())
		}
		return operations, err
	}
	if accountConflicts > 0 {
		err := errors.New("存在" + providerName + "用户冲突，请先由管理员处理 DSM 用户名后再同步 DSM")
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", sourceSlug, "", "resolve_user_conflicts", "blocked", "conflict", "conflict", err.Error())
		if progress != nil {
			progress.message(ctx, "等待冲突处理", err.Error())
		}
		return operations, err
	}

	groupRows, err := s.store.DBTX().QueryContext(ctx, `
		SELECT DISTINCT g.id, g.dsm_groupname, g.provision_status
		FROM dsm_groups g
		JOIN dsm_mapping_entries me ON me.dsm_group_id = g.id
		WHERE me.provider_slug = ? AND me.mapping_type = 'group' AND me.active = 1 AND g.provision_status IN ('pending', 'failed', 'created')
		ORDER BY g.created_at`, sourceSlug)
	if err != nil {
		return operations, err
	}
	type pendingGroupProvision struct {
		id        string
		groupname string
		status    string
	}
	var pendingGroups []pendingGroupProvision
	for groupRows.Next() {
		var item pendingGroupProvision
		if err := groupRows.Scan(&item.id, &item.groupname, &item.status); err != nil {
			groupRows.Close()
			return operations, err
		}
		pendingGroups = append(pendingGroups, item)
	}
	if err := groupRows.Err(); err != nil {
		groupRows.Close()
		return operations, err
	}
	groupRows.Close()
	if progress != nil {
		progress.setTotal(ctx, "同步 DSM 部门", "正在同步 DSM 部门", len(pendingGroups))
	}
	for _, item := range pendingGroups {
		id, groupname, status := item.id, item.groupname, item.status
		created, err := s.helper.ProvisionGroup(ctx, "sync_group_"+randomHex(8), groupname)
		if err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_groups SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "group", id, groupname, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		if !created {
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "group", id, groupname, "create_or_update", "success", status, "pending", "DSM CLI deferred empty group creation until first member is added")
			operations = append(operations, syncsvc.PlanItem{Action: "defer_dsm_group_until_member", ProviderSlug: sourceSlug, Subject: id, DSMGroupname: groupname, ProvisionStatus: "pending"})
			if progress != nil {
				progress.step(ctx, "同步 DSM 部门", groupname)
			}
			continue
		}
		if progress != nil {
			progress.step(ctx, "同步 DSM 部门", groupname)
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_groups SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "group", id, groupname, "create_or_update", "success", status, "created", "")
		operations = append(operations, syncsvc.PlanItem{Action: "sync_dsm_group", ProviderSlug: sourceSlug, Subject: id, DSMGroupname: groupname, ProvisionStatus: "created"})
	}

	accountRows, err := s.store.DBTX().QueryContext(ctx, `
	SELECT DISTINCT a.id, a.dsm_username, COALESCE(i.display_name, ''), COALESCE(i.primary_email, ''), a.provision_status
		FROM dsm_accounts a
		JOIN app_identities i ON i.id = a.app_identity_id
		JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id
		WHERE me.provider_slug = ? AND me.mapping_type = 'user' AND me.active = 1 AND a.provision_status IN ('pending', 'failed', 'created', 'linked_existing', 'disabled')
		ORDER BY a.created_at`, sourceSlug)
	if err != nil {
		return operations, err
	}
	type pendingAccountProvision struct {
		id          string
		username    string
		displayName string
		email       string
		status      string
	}
	var pendingAccounts []pendingAccountProvision
	for accountRows.Next() {
		var item pendingAccountProvision
		if err := accountRows.Scan(&item.id, &item.username, &item.displayName, &item.email, &item.status); err != nil {
			accountRows.Close()
			return operations, err
		}
		pendingAccounts = append(pendingAccounts, item)
	}
	if err := accountRows.Err(); err != nil {
		accountRows.Close()
		return operations, err
	}
	accountRows.Close()
	if progress != nil {
		progress.setTotal(ctx, "同步 DSM 用户", "正在同步 DSM 用户", len(pendingAccounts))
	}
	for _, item := range pendingAccounts {
		id, username, displayName, email, status := item.id, item.username, item.displayName, item.email, item.status
		err := error(nil)
		password, err := s.provisionUserInitialPassword(ctx, sourceSlug)
		if err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", id, username, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		created, err := s.helper.ProvisionUser(ctx, "sync_user_"+randomHex(8), username, displayName, email, password)
		if err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", id, username, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		nextStatus := "created"
		action := "sync_dsm_user"
		if !created {
			nextStatus = "linked_existing"
			action = "link_existing_dsm_user"
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET provision_status = ?, conflict_reason = NULL, allow_login = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, nextStatus, id)
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", id, username, "create_or_update", "success", status, nextStatus, "")
		operations = append(operations, syncsvc.PlanItem{Action: action, ProviderSlug: sourceSlug, Subject: id, DSMUsername: username, ProvisionStatus: nextStatus})
		if progress != nil {
			progress.step(ctx, "同步 DSM 用户", username)
		}
	}

	memberRows, err := s.store.DBTX().QueryContext(ctx, `
	SELECT DISTINCT m.id, g.id, g.dsm_groupname, a.dsm_username, m.provision_status
	FROM group_members m
	JOIN dsm_groups g ON g.id = m.dsm_group_id
	JOIN dsm_accounts a ON a.id = m.dsm_account_id
	WHERE m.active = 1 AND m.provision_status IN ('pending', 'failed', 'created')
	  AND EXISTS (
		SELECT 1 FROM dsm_mapping_entries me
			WHERE me.mapping_type = 'member'
			  AND me.provider_slug = ?
			  AND me.active = 1
			  AND me.dsm_group_id = m.dsm_group_id
			  AND me.dsm_account_id = m.dsm_account_id
		  )
		ORDER BY m.created_at`, sourceSlug)
	if err != nil {
		return operations, err
	}
	type pendingMemberProvision struct {
		id        string
		groupID   string
		groupname string
		username  string
		status    string
	}
	var pendingMembers []pendingMemberProvision
	for memberRows.Next() {
		var item pendingMemberProvision
		if err := memberRows.Scan(&item.id, &item.groupID, &item.groupname, &item.username, &item.status); err != nil {
			memberRows.Close()
			return operations, err
		}
		pendingMembers = append(pendingMembers, item)
	}
	if err := memberRows.Err(); err != nil {
		memberRows.Close()
		return operations, err
	}
	memberRows.Close()
	if progress != nil {
		progress.setTotal(ctx, "同步 DSM 成员", "正在同步 DSM 成员", len(pendingMembers))
	}
	for _, item := range pendingMembers {
		id, groupID, groupname, username, status := item.id, item.groupID, item.groupname, item.username, item.status
		if _, err := s.helper.AddGroupMember(ctx, "sync_member_"+randomHex(8), groupname, username); err != nil {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE group_members SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "member", id, groupname+":"+username, "create_or_update", "failed", status, "failed", err.Error())
			return operations, err
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_groups SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, groupID)
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE group_members SET provision_status = 'created', active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "member", id, groupname+":"+username, "create_or_update", "success", status, "created", "")
		operations = append(operations, syncsvc.PlanItem{Action: "sync_dsm_group_member", ProviderSlug: sourceSlug, Subject: id, DSMUsername: username, DSMGroupname: groupname, ProvisionStatus: "created"})
		if progress != nil {
			progress.step(ctx, "同步 DSM 成员", groupname+":"+username)
		}
	}

	if policy.DeactivateMissingData {
		removeRows, err := s.store.DBTX().QueryContext(ctx, `
	SELECT DISTINCT m.id, g.dsm_groupname, a.dsm_username, m.provision_status
		FROM group_members m
		JOIN dsm_groups g ON g.id = m.dsm_group_id
		JOIN dsm_accounts a ON a.id = m.dsm_account_id
		WHERE m.active = 0 AND m.provision_status IN ('remove_pending', 'remove_failed')
			  AND EXISTS (
				SELECT 1
				FROM dsm_mapping_entries me
				WHERE me.provider_slug = ?
				  AND me.mapping_type = 'member'
				  AND me.dsm_group_id = m.dsm_group_id
				  AND me.dsm_account_id = m.dsm_account_id
			  )
		ORDER BY m.updated_at`, sourceSlug)
		if err != nil {
			return operations, err
		}
		type pendingMemberRemoval struct {
			id        string
			groupname string
			username  string
			status    string
		}
		var pendingRemovals []pendingMemberRemoval
		for removeRows.Next() {
			var item pendingMemberRemoval
			if err := removeRows.Scan(&item.id, &item.groupname, &item.username, &item.status); err != nil {
				removeRows.Close()
				return operations, err
			}
			pendingRemovals = append(pendingRemovals, item)
		}
		if err := removeRows.Err(); err != nil {
			removeRows.Close()
			return operations, err
		}
		removeRows.Close()
		if progress != nil {
			progress.setTotal(ctx, "禁用本地成员关系", "正在禁用本地成员关系", len(pendingRemovals))
		}
		for _, item := range pendingRemovals {
			_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE group_members SET provision_status = 'disabled', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, item.id)
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "member", item.id, item.groupname+":"+item.username, "disable_local_group_member", "success", item.status, "disabled", "本地成员关系已禁用；DSM 群组成员关系不自动处理")
			operations = append(operations, syncsvc.PlanItem{Action: "disable_local_group_member", ProviderSlug: sourceSlug, Subject: item.id, DSMUsername: item.username, DSMGroupname: item.groupname, ProvisionStatus: "disabled"})
			if progress != nil {
				progress.step(ctx, "禁用本地成员关系", item.groupname+":"+item.username)
			}
		}
	}

	if !policy.DisableMissingUsers {
		return operations, nil
	}
	disableRows, err := s.store.DBTX().QueryContext(ctx, `
		SELECT DISTINCT a.id, a.dsm_username
		FROM dsm_accounts a
		WHERE a.allow_login = 1
		  AND EXISTS (
			SELECT 1
			FROM dsm_mapping_entries stale
			WHERE stale.provider_slug = ?
			  AND stale.mapping_type = 'user'
			  AND stale.active = 0
			  AND stale.dsm_account_id = a.id
		  )
		  AND NOT EXISTS (
			SELECT 1
			FROM dsm_mapping_entries me
		WHERE me.mapping_type = 'user'
			  AND me.active = 1
			  AND me.dsm_account_id = a.id
		  )`, sourceSlug)
	if err != nil {
		return operations, err
	}
	type pendingUserDisable struct {
		accountID string
		username  string
	}
	var pendingDisables []pendingUserDisable
	for disableRows.Next() {
		var item pendingUserDisable
		if err := disableRows.Scan(&item.accountID, &item.username); err != nil {
			disableRows.Close()
			return operations, err
		}
		pendingDisables = append(pendingDisables, item)
	}
	if err := disableRows.Err(); err != nil {
		disableRows.Close()
		return operations, err
	}
	disableRows.Close()
	if progress != nil {
		progress.setTotal(ctx, "禁用缺失用户", "正在禁用缺失用户", len(pendingDisables))
	}
	for _, item := range pendingDisables {
		accountID, username := item.accountID, item.username
		if _, err := s.helper.DisableUser(ctx, "sync_disable_"+randomHex(8), username); err != nil {
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", accountID, username, "disable_missing", "failed", "active", "active", err.Error())
			return operations, err
		}
		_, _ = s.store.DBTX().ExecContext(ctx, `UPDATE dsm_accounts SET allow_login = 0, provision_status = 'disabled', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, accountID)
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", accountID, username, "disable_missing", "success", "active", "disabled", "")
		operations = append(operations, syncsvc.PlanItem{Action: "disable_missing_dsm_user", ProviderSlug: sourceSlug, Subject: accountID, DSMUsername: username, ProvisionStatus: "disabled"})
		if progress != nil {
			progress.step(ctx, "禁用缺失用户", username)
		}
	}
	return operations, nil
}

func (s *Server) logSyncOperation(ctx context.Context, runID, sourceSlug, objectType, objectKey, dsmName, action, status, before, after, errorText string) {
	entry := syncLogEntry{
		id:         randomHex(16),
		runID:      runID,
		sourceSlug: sourceSlug,
		objectType: objectType,
		objectKey:  objectKey,
		dsmName:    dsmName,
		action:     action,
		status:     status,
		before:     before,
		after:      after,
		errorText:  errorText,
	}
	_ = s.insertSyncLogEntries(ctx, []syncLogEntry{entry})
}

type syncLogEntry struct {
	id         string
	runID      string
	sourceSlug string
	objectType string
	objectKey  string
	dsmName    string
	action     string
	status     string
	before     string
	after      string
	errorText  string
}

type syncLogBuffer struct {
	server    *Server
	ctx       context.Context
	entries   []syncLogEntry
	lastFlush time.Time
}

const syncLogFlushSize = 100
const syncLogFlushInterval = 2 * time.Second

func (s *Server) newSyncLogBuffer(ctx context.Context) *syncLogBuffer {
	return &syncLogBuffer{server: s, ctx: ctx, lastFlush: time.Now()}
}

func (s *Server) writeSyncOperation(buffer *syncLogBuffer, runID, sourceSlug, objectType, objectKey, dsmName, action, status, before, after, errorText string) {
	entry := syncLogEntry{
		id:         randomHex(16),
		runID:      runID,
		sourceSlug: sourceSlug,
		objectType: objectType,
		objectKey:  objectKey,
		dsmName:    dsmName,
		action:     action,
		status:     status,
		before:     before,
		after:      after,
		errorText:  errorText,
	}
	if buffer != nil {
		buffer.LogEntry(entry)
		return
	}
	_ = s.insertSyncLogEntries(context.Background(), []syncLogEntry{entry})
}

func (b *syncLogBuffer) Log(runID, sourceSlug, objectType, objectKey, dsmName, action, status, before, after, errorText string) {
	b.server.writeSyncOperation(b, runID, sourceSlug, objectType, objectKey, dsmName, action, status, before, after, errorText)
}

func (b *syncLogBuffer) LogEntry(entry syncLogEntry) {
	b.entries = append(b.entries, entry)
	if len(b.entries) >= syncLogFlushSize || time.Since(b.lastFlush) >= syncLogFlushInterval {
		_ = b.Flush()
	}
}

func (b *syncLogBuffer) Flush() error {
	if b == nil || len(b.entries) == 0 {
		return nil
	}
	entries := b.entries
	b.entries = nil
	b.lastFlush = time.Now()
	return b.server.insertSyncLogEntries(b.ctx, entries)
}

func (s *Server) insertSyncLogEntries(ctx context.Context, entries []syncLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := beginMaybe(ctx, s.logDatabase, s.logs().DBTX())
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed && tx != nil {
			_ = tx.Rollback()
		}
	}()
	exec := s.logs().DBTX()
	if tx != nil {
		exec = tx
	}
	for _, entry := range entries {
		if _, err := exec.ExecContext(ctx, `
INSERT INTO sync_operation_logs (
	id, sync_run_id, source_slug, object_type, object_key, dsm_name, action, status, before_state, after_state, error, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
`, entry.id, entry.runID, entry.sourceSlug, entry.objectType, entry.objectKey, nullStringValue(entry.dsmName), entry.action, entry.status, nullStringValue(entry.before), nullStringValue(entry.after), nullStringValue(entry.errorText)); err != nil {
			return err
		}
	}
	if tx == nil {
		return nil
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func beginMaybe(ctx context.Context, database *sql.DB, fallback db.DBTX) (*sql.Tx, error) {
	if database == nil {
		return nil, nil
	}
	return database.BeginTx(ctx, nil)
}
