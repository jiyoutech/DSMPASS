package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/identity"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

type syncMode string

const (
	syncIncremental syncMode = "incremental"
	syncFull        syncMode = "full"
)

func (mode syncMode) label() string {
	if mode == syncFull {
		return "全量同步"
	}
	return "增量同步"
}

func readSyncMode(c *gin.Context) (syncMode, bool) {
	var payload struct {
		Mode syncMode `json:"mode"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid sync mode request"})
		return "", false
	}
	if payload.Mode == "" {
		payload.Mode = syncIncremental
	}
	if payload.Mode != syncIncremental && payload.Mode != syncFull {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "mode must be incremental or full"})
		return "", false
	}
	return payload.Mode, true
}

func (s *Server) resetFullSyncPasswords(ctx context.Context, runID, sourceSlug string, buffer *syncLogBuffer, progress *operationProgress) ([]syncsvc.PlanItem, error) {
	rows, err := queryJSON(ctx, s.store, `
SELECT DISTINCT a.id, a.dsm_username FROM dsm_accounts a
JOIN dsm_mapping_entries me ON me.dsm_account_id = a.id
WHERE me.provider_slug = ? AND me.mapping_type = 'user' AND me.active = 1
ORDER BY a.id`, sourceSlug)
	if err != nil {
		return nil, err
	}
	var operations []syncsvc.PlanItem
	if progress != nil {
		progress.setTotal(ctx, "统一 DSM/SMB 密码", "仅重置当前身份源的有效同步账号", len(rows))
	}
	for _, row := range rows {
		id, _ := row["id"].(string)
		username, _ := row["dsm_username"].(string)
		allowed, err := db.SyncedPasswordResetAllowed(ctx, s.store, sourceSlug, id, username)
		if err != nil {
			return operations, err
		}
		if !allowed || identity.IsReservedDSMUsername(username) {
			s.writeSyncOperation(buffer, runID, sourceSlug, "user", id, username, "reset_password", "skipped", "", "", "非有效同步账号或系统保留账号，保留密码")
		} else {
			password, err := s.provisionUserInitialPassword(ctx, sourceSlug)
			if err == nil {
				err = s.helper.ResetSyncedUserPassword(ctx, "sync_password_"+randomHex(8), sourceSlug, id, username, password)
			}
			if err != nil {
				s.writeSyncOperation(buffer, runID, sourceSlug, "user", id, username, "reset_password", "failed", "", "", "密码重置失败，请查看任务错误并重新执行全量同步")
				return operations, fmt.Errorf("全量同步重置 %s 的 DSM/SMB 密码失败；已完成的账号不会回滚，请排查后重新全量同步：%w", username, err)
			}
			s.writeSyncOperation(buffer, runID, sourceSlug, "user", id, username, "reset_password", "success", "", "source_initial_password", "")
			operations = append(operations, syncsvc.PlanItem{Action: "reset_dsm_smb_password", ProviderSlug: sourceSlug, Subject: id, DSMUsername: username, ProvisionStatus: "success"})
		}
		if progress != nil {
			progress.step(ctx, "统一 DSM/SMB 密码", username)
		}
	}
	return operations, nil
}
