package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

func (s *Server) disableDingTalkAccounts(ctx context.Context, runID, source string, policy sourceSyncPolicy, buffer *syncLogBuffer) ([]syncsvc.PlanItem, error) {
	if policy.dingTalkUsers == nil {
		return nil, nil
	}
	candidates, err := db.DingTalkOffboardingCandidates(ctx, s.store, source)
	if err != nil {
		return nil, err
	}
	var operations []syncsvc.PlanItem
	var errs []error
	for _, user := range candidates {
		suspended, present := policy.dingTalkUsers[user.Subject]
		reason := "disabled"
		if !suspended {
			if present || !policy.FullSync || !policy.confirmDingTalkAbsence {
				continue
			}
			reason = "departed"
		}
		_, err := s.store.DBTX().ExecContext(ctx, `INSERT INTO dingtalk_offboarding(source_slug,account_id,subject,run_id,reason) VALUES(?,?,?,?,?)
        ON CONFLICT(source_slug,account_id) DO UPDATE SET subject=excluded.subject,run_id=excluded.run_id,reason=excluded.reason`, source, user.AccountID, user.Subject, runID, reason)
		if err != nil {
			return operations, errors.Join(append(errs, err)...)
		}
		err = s.helper.DisableDingTalkUser(ctx, "sync_disable_"+randomHex(8), runID, source, user.AccountID, user.Subject, user.Username)
		if err == nil {
			err = saveObjectState(ctx, s.store.DBTX(), user.Username, `UPDATE dsm_accounts SET allow_login=0,provision_status='disabled',updated_at=CURRENT_TIMESTAMP WHERE id=?`, user.AccountID)
		}
		if err != nil {
			s.writeSyncOperation(buffer, runID, source, "user", user.AccountID, user.Username, "disable_missing", "failed", "", "", err.Error())
			errs = append(errs, fmt.Errorf("停用 %s: %w", user.Username, err))
			continue
		}
		s.writeSyncOperation(buffer, runID, source, "user", user.AccountID, user.Username, "disable_missing", "success", reason, "disabled", "")
		operations = append(operations, syncsvc.PlanItem{Action: "disable_missing_dsm_user", ProviderSlug: source, Subject: user.Subject, DSMUsername: user.Username, ProvisionStatus: "disabled"})
	}
	return operations, errors.Join(errs...)
}
