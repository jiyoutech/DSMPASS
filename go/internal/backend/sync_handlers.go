package backend

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

func (s *Server) syncApply(c *gin.Context) {
	s.syncProvider(c)
}

func (s *Server) startProviderSyncRun(c *gin.Context) {
	mode, ok := readSyncMode(c)
	if !ok {
		return
	}
	sourceSlug := c.Param("slug")
	if _, ok := s.directoryProvider(sourceSlug); !ok {
		c.JSON(http.StatusNotFound, gin.H{"detail": "unknown provider"})
		return
	}
	progress, err := s.createOperationRun(c.Request.Context(), "sync", sourceSlug, "等待开始", mode.label()+"任务已创建", 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	go func() {
		ctx := context.Background()
		_, err := s.runSyncProviderModeWithProgress(ctx, sourceSlug, mode, progress)
		if err != nil {
			progress.fail(ctx, err)
			return
		}
		progress.complete(ctx, mode.label()+"完成")
	}()
	c.JSON(http.StatusAccepted, gin.H{"run_id": progress.id})
}

func (s *Server) syncProvider(c *gin.Context) {
	mode, ok := readSyncMode(c)
	if !ok {
		return
	}
	result, err := s.runSyncProviderModeWithProgress(c.Request.Context(), c.Param("provider"), mode, nil)
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
	return s.runSyncProviderModeWithProgress(ctx, providerSlug, syncIncremental, progress)
}

func (s *Server) runSyncProviderModeWithProgress(ctx context.Context, providerSlug string, mode syncMode, progress *operationProgress) (result syncsvc.Result, runErr error) {
	defer s.maybeCleanupLogs(ctx)
	directory, ok := s.directoryProvider(providerSlug)
	if !ok {
		return syncsvc.Result{}, errUnknownProvider
	}
	if !s.beginSourceSync(directory.Slug()) {
		return syncsvc.Result{}, errSyncAlreadyRunning
	}
	defer s.endSourceSync(directory.Slug())
	if mode == syncFull {
		health, err := s.helper.HealthCheck(ctx)
		if err != nil {
			return syncsvc.Result{}, err
		}
		if supported, _ := health["synced_password_reset"].(bool); !supported {
			return syncsvc.Result{}, errors.New("Helper 不支持全量同步密码修复，请升级并重启 Helper")
		}
	}
	runID := "sync_" + randomHex(12)
	var syncStart string
	if err := s.store.DBTX().QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&syncStart); err != nil {
		return result, err
	}
	const beginRun = `INSERT INTO sync_runs (id,source_slug,dry_run,status,started_at) VALUES(?,?,0,'running',CURRENT_TIMESTAMP)`
	if _, err := s.store.DBTX().ExecContext(ctx, beginRun, runID, directory.Slug()); err != nil {
		return result, err
	}
	logBuffer := s.newSyncLogBuffer(ctx)
	defer func() {
		runErr = errors.Join(runErr, logBuffer.Flush())
		finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, finishSyncRun(finalCtx, s.store, runID, runErr))
		if s.logs() != s.store {
			runErr = errors.Join(runErr, finishSyncRun(finalCtx, s.logs(), runID, runErr))
		}
	}()
	if s.logs() != s.store {
		if _, err := s.logs().DBTX().ExecContext(ctx, beginRun, runID, directory.Slug()); err != nil {
			return result, err
		}
	}
	policy, err := s.sourceSyncPolicy(ctx, directory.Slug())
	if err != nil {
		return result, err
	}
	policy.FullSync = mode == syncFull
	var scopeCheck func() (bool, error)
	if policy.DingTalk && policy.FullSync && policy.DisableMissingUsers && policy.DeactivateMissingData {
		if directoryScope, ok := directory.(interface{ WholeDirectoryVisible() (bool, error) }); ok {
			scopeCheck = directoryScope.WholeDirectoryVisible
		}
	}
	visibleBefore := false
	if scopeCheck != nil {
		visibleBefore, err = scopeCheck()
		if err != nil {
			return result, err
		}
	}
	logBuffer.Log(runID, directory.Slug(), "identity_source", directory.Slug(), "", "sync_mode", "success", "", string(mode), "")
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
	result, err = syncsvc.NewEngineWithOptions(s.cfg, q, syncsvc.Options{
		TrackAccountSuspensions: policy.DingTalk && policy.DisableMissingUsers,
		DeactivateMissingData:   policy.DeactivateMissingData,
		SyncStart:               syncStart,
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
		logBuffer.Log(runID, directory.Slug(), "identity_source", directory.Slug(), "", "read_directory", "failed", "running", "failed", err.Error())
		return result, err
	}
	if progress != nil {
		progress.message(ctx, "写入同步日志", "正在记录映射结果")
	}
	s.logDirectoryLinkPlanWithBuffer(logBuffer, runID, directory.Slug(), result.Items)
	if syncResultHasDirectoryWarning(result) {
		policy.PreserveMissingGroups = true
	}
	if policy.DingTalk && policy.DisableMissingUsers {
		policy.dingTalkUsers = result.AccountSuspensions
		if visibleBefore && !policy.PreserveMissingGroups {
			policy.confirmDingTalkAbsence, err = scopeCheck()
			if err != nil {
				return result, err
			}
		}
		if policy.FullSync && !policy.confirmDingTalkAbsence {
			logBuffer.Log(runID, directory.Slug(), "identity_source", directory.Slug(), "", "offboarding_scope", "skipped", "", "", "未确认完整组织通讯录，仅处理企业账号明确停用状态")
		}
	}
	operations, err := s.syncSourceToDSMWithBuffer(ctx, runID, directory.Slug(), syncStart, policy, logBuffer, progress)
	result.Items = append(result.Items, operations...)
	return result, err
}

func finishSyncRun(ctx context.Context, q *db.Queries, id string, runErr error) error {
	status := "success"
	var detail any
	if runErr != nil {
		status = "failed"
		detail = runErr.Error()
	}
	return saveObjectState(ctx, q.DBTX(), id, `UPDATE sync_runs SET status=?, finished_at=CURRENT_TIMESTAMP, error=? WHERE id=?`, status, detail, id)
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
	DingTalk               bool
	dingTalkUsers          map[string]bool
	confirmDingTalkAbsence bool
	FullSync               bool
	DisableMissingUsers    bool
	DeactivateMissingData  bool
	PreserveMissingGroups  bool
}

func (s *Server) sourceSyncPolicy(ctx context.Context, sourceSlug string) (sourceSyncPolicy, error) {
	source, err := s.loadIdentitySource(ctx, sourceSlug)
	if errors.Is(err, sql.ErrNoRows) && sourceSlug == "feishu" && s.cfg.FeishuEnabled {
		return sourceSyncPolicy{DeactivateMissingData: true}, nil
	}
	if err != nil {
		return sourceSyncPolicy{}, err
	}
	cfg := decodeSourceConfigForType(source.ProviderType, source.ConfigJSON)
	return sourceSyncPolicy{
		DingTalk:              source.ProviderType == "dingtalk",
		DisableMissingUsers:   boolValue(cfg.DisableMissingUsers, false),
		DeactivateMissingData: boolValue(cfg.DeactivateMissingData, true),
	}, nil
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
		if err := s.markMissingSourceData(ctx, sourceSlug, syncStart, policy.PreserveMissingGroups); err != nil {
			return operations, err
		}
	}
	var disableErr error
	if policy.DisableMissingUsers && policy.DingTalk {
		operations, disableErr = s.disableDingTalkAccounts(ctx, runID, sourceSlug, policy, logBuffer)
	} else if policy.DisableMissingUsers {
		operations, disableErr = s.disableMissingAccounts(ctx, runID, sourceSlug, logBuffer, progress)
	}
	provisioned, err := s.provisionSourceToDSM(ctx, runID, sourceSlug, policy, logBuffer, progress)
	return append(operations, provisioned...), errors.Join(disableErr, err)
}

func (s *Server) provisionSourceToDSM(ctx context.Context, runID, sourceSlug string, policy sourceSyncPolicy, logBuffer *syncLogBuffer, progress *operationProgress) ([]syncsvc.PlanItem, error) {
	var operations []syncsvc.PlanItem
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
			err = errors.Join(err, saveObjectState(ctx, s.store.DBTX(), groupname, `UPDATE dsm_groups SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id))
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
		if err := saveObjectState(ctx, s.store.DBTX(), groupname, `UPDATE dsm_groups SET provision_status = 'created', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
			return operations, err
		}
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "group", id, groupname, "create_or_update", "success", status, "created", "")
		operations = append(operations, syncsvc.PlanItem{Action: "sync_dsm_group", ProviderSlug: sourceSlug, Subject: id, DSMGroupname: groupname, ProvisionStatus: "created"})
	}

	accountRows, err := s.store.DBTX().QueryContext(ctx, `
	SELECT DISTINCT a.id, a.dsm_username, COALESCE(i.display_name, ''), COALESCE(i.primary_email, ''), a.provision_status
		FROM dsm_accounts a
		JOIN app_identities i ON i.id = a.app_identity_id
		JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id
		WHERE me.provider_slug = ? AND me.mapping_type = 'user' AND me.active = 1 AND a.provision_status IN ('pending', 'failed', 'created', 'linked_existing', 'disabled')
		AND (NOT ? OR EXISTS (SELECT 1 FROM external_accounts e WHERE e.id=me.external_account_id AND e.provider_slug=me.provider_slug AND e.app_identity_id=i.id AND e.active=1))
        ORDER BY a.created_at`, sourceSlug, policy.DingTalk)
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
	var accountErrors []error
	var createdPasswords syncCreatedPasswords
	var initialPassword string
	resultClient, _ := s.helper.(helperclient.UserProvisionResultClient)
	for _, item := range pendingAccounts {
		id, username, displayName, email, status := item.id, item.username, item.displayName, item.email, item.status
		var err error
		if initialPassword == "" {
			initialPassword, err = s.provisionUserInitialPassword(ctx, sourceSlug)
		}
		if err != nil {
			err = errors.Join(err, saveObjectState(ctx, s.store.DBTX(), username, `UPDATE dsm_accounts SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id))
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", id, username, "create_or_update", "failed", status, "failed", err.Error())
			return operations, errors.Join(append(accountErrors, err)...)
		}
		requestID := "sync_user_" + randomHex(8)
		var result helperclient.ProvisionUserResult
		if policy.FullSync && resultClient != nil {
			result, err = resultClient.ProvisionUserWithResult(ctx, requestID, username, displayName, email, initialPassword)
		} else {
			result.Created, err = s.helper.ProvisionUser(ctx, requestID, username, displayName, email, initialPassword)
		}
		if err != nil {
			err = errors.Join(err, saveObjectState(ctx, s.store.DBTX(), username, `UPDATE dsm_accounts SET provision_status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id))
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", id, username, "create_or_update", "failed", status, "failed", err.Error())
			accountErrors = append(accountErrors, err)
			if progress != nil {
				progress.step(ctx, "同步 DSM 用户", username)
			}
			continue
		}
		nextStatus := "created"
		action := "sync_dsm_user"
		if !result.Created {
			nextStatus = "linked_existing"
			action = "link_existing_dsm_user"
		}
		if err := saveObjectState(ctx, s.store.DBTX(), username, `UPDATE dsm_accounts SET provision_status = ?, conflict_reason = NULL, allow_login = (manual_login_blocked = 0), updated_at = CURRENT_TIMESTAMP WHERE id = ?`, nextStatus, id); err != nil {
			return operations, errors.Join(append(accountErrors, err)...)
		}
		if result.Created && result.InitialPasswordApplied {
			if createdPasswords.accounts == nil {
				createdPasswords.accounts = map[string]string{}
				createdPasswords.password = initialPassword
			}
			createdPasswords.accounts[id] = username
		}
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", id, username, "create_or_update", "success", status, nextStatus, "")
		operations = append(operations, syncsvc.PlanItem{Action: action, ProviderSlug: sourceSlug, Subject: id, DSMUsername: username, ProvisionStatus: nextStatus})
		if progress != nil {
			progress.step(ctx, "同步 DSM 用户", username)
		}
	}
	if policy.FullSync {
		passwordOperations, err := s.resetFullSyncPasswords(ctx, runID, sourceSlug, logBuffer, progress, createdPasswords)
		operations = append(operations, passwordOperations...)
		if err != nil {
			accountErrors = append(accountErrors, err)
		}
	}

	memberRows, err := s.store.DBTX().QueryContext(ctx, `
	SELECT DISTINCT m.id, g.dsm_groupname, a.dsm_username, m.provision_status
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
		ORDER BY g.dsm_groupname, m.created_at, m.id`, sourceSlug)
	if err != nil {
		return operations, errors.Join(append(accountErrors, err)...)
	}
	var pendingMembers []syncMember
	for memberRows.Next() {
		var item syncMember
		if err := memberRows.Scan(&item.id, &item.groupname, &item.username, &item.status); err != nil {
			memberRows.Close()
			return operations, errors.Join(append(accountErrors, err)...)
		}
		pendingMembers = append(pendingMembers, item)
	}
	if err := memberRows.Err(); err != nil {
		memberRows.Close()
		return operations, errors.Join(append(accountErrors, err)...)
	}
	memberRows.Close()
	if progress != nil {
		progress.setTotal(ctx, "同步 DSM 成员", "正在同步 DSM 成员", len(pendingMembers))
	}
	memberOps, err := s.syncGroupMembers(ctx, runID, sourceSlug, pendingMembers, logBuffer, progress)
	operations = append(operations, memberOps...)
	if err != nil {
		return operations, errors.Join(append(accountErrors, err)...)
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
			return operations, errors.Join(append(accountErrors, err)...)
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
				return operations, errors.Join(append(accountErrors, err)...)
			}
			pendingRemovals = append(pendingRemovals, item)
		}
		if err := removeRows.Err(); err != nil {
			removeRows.Close()
			return operations, errors.Join(append(accountErrors, err)...)
		}
		removeRows.Close()
		if progress != nil {
			progress.setTotal(ctx, "禁用本地成员关系", "正在禁用本地成员关系", len(pendingRemovals))
		}
		for _, item := range pendingRemovals {
			if err := saveObjectState(ctx, s.store.DBTX(), item.groupname+":"+item.username, `UPDATE group_members SET provision_status = 'disabled', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, item.id); err != nil {
				return operations, errors.Join(append(accountErrors, err)...)
			}
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "member", item.id, item.groupname+":"+item.username, "disable_local_group_member", "success", item.status, "disabled", "本地成员关系已禁用；DSM 群组成员关系不自动处理")
			operations = append(operations, syncsvc.PlanItem{Action: "disable_local_group_member", ProviderSlug: sourceSlug, Subject: item.id, DSMUsername: item.username, DSMGroupname: item.groupname, ProvisionStatus: "disabled"})
			if progress != nil {
				progress.step(ctx, "禁用本地成员关系", item.groupname+":"+item.username)
			}
		}
	}

	return operations, errors.Join(accountErrors...)
}

func (s *Server) disableMissingAccounts(ctx context.Context, runID, sourceSlug string, logBuffer *syncLogBuffer, progress *operationProgress) ([]syncsvc.PlanItem, error) {
	var operations []syncsvc.PlanItem
	var accountErrors []error
	disableRows, err := s.store.DBTX().QueryContext(ctx, `
		SELECT DISTINCT a.id, a.dsm_username
		FROM dsm_accounts a
		WHERE a.provision_status <> 'disabled' AND a.provision_status <> 'conflict'
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
		return operations, errors.Join(append(accountErrors, err)...)
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
			return operations, errors.Join(append(accountErrors, err)...)
		}
		pendingDisables = append(pendingDisables, item)
	}
	if err := disableRows.Err(); err != nil {
		disableRows.Close()
		return operations, errors.Join(append(accountErrors, err)...)
	}
	disableRows.Close()
	if progress != nil {
		progress.setTotal(ctx, "禁用缺失用户", "正在禁用缺失用户", len(pendingDisables))
	}
	for _, item := range pendingDisables {
		accountID, username := item.accountID, item.username
		if _, err := s.helper.DisableUser(ctx, "sync_disable_"+randomHex(8), username); err != nil {
			s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", accountID, username, "disable_missing", "failed", "active", "active", err.Error())
			accountErrors = append(accountErrors, fmt.Errorf("停用 %s: %w", username, err))
			continue
		}
		if err := saveObjectState(ctx, s.store.DBTX(), username, `UPDATE dsm_accounts SET allow_login = 0, provision_status = 'disabled', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, accountID); err != nil {
			accountErrors = append(accountErrors, err)
			continue
		}
		s.writeSyncOperation(logBuffer, runID, sourceSlug, "user", accountID, username, "disable_missing", "success", "active", "disabled", "")
		operations = append(operations, syncsvc.PlanItem{Action: "disable_missing_dsm_user", ProviderSlug: sourceSlug, Subject: accountID, DSMUsername: username, ProvisionStatus: "disabled"})
		if progress != nil {
			progress.step(ctx, "禁用缺失用户", username)
		}
	}
	return operations, errors.Join(accountErrors...)
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
	flushErr  error
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
	if b.flushErr != nil {
		return
	}
	b.entries = append(b.entries, entry)
	if len(b.entries) >= syncLogFlushSize || time.Since(b.lastFlush) >= syncLogFlushInterval {
		_ = b.Flush()
	}
}

func (b *syncLogBuffer) Flush() error {
	if b == nil {
		return nil
	}
	if b.flushErr != nil || len(b.entries) == 0 {
		return b.flushErr
	}
	entries := b.entries
	b.entries = nil
	b.lastFlush = time.Now()
	b.flushErr = b.server.insertSyncLogEntries(b.ctx, entries)
	return b.flushErr
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
