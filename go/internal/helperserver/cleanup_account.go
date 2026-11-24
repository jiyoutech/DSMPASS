package helperserver

import (
	"errors"
	"os"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) cleanupAccount(cfg config.HelperConfig, payload map[string]any) map[string]any {
	name, _ := requiredString(payload, "dsm_username")
	source, _ := requiredString(payload, "source_slug")
	account, _ := requiredString(payload, "account_id")
	id, _ := requiredString(payload, "request_id")
	if id == "" || source == "" || account == "" || assertAllowed(cfg, name) != nil {
		return errorResponse("BAD_REQUEST", "清理目标无效")
	}
	req := db.HelperAuthorizationQuery{Username: name, SourceSlug: source, AccountID: account, RunID: id}
	classify := func() (string, error) {
		grant, err := userEnrollment(cfg, name)
		req.Action = "cleanup_user"
		outcome := "disabled"
		switch {
		case errors.Is(err, os.ErrNotExist):
			req.Action = "cleanup_absent"
			outcome = "absent"
		case errors.Is(err, errUserNotEnrolled):
			req.Action = "cleanup_conflict"
			outcome = "unmapped_conflict"
		case err != nil:
			return "", err
		case grant != nil:
			outcome = "membership_only"
		}
		return outcome, s.authorizeAccount(cfg, req)
	}
	outcome, err := classify()
	if err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	err = withAccountMutation(cfg, name, outcome == "disabled", func() error {
		current, err := classify()
		if err != nil {
			return err
		}
		if current != outcome {
			return errors.New("DSM 账号归属已变化，请重试")
		}
		if outcome == "unmapped_conflict" || outcome == "membership_only" {
			return nil
		}
		info, err := getSynoUser(cfg.SynoUserPath, name)
		if outcome == "absent" {
			if !dsmUserNotFound(err) {
				return errors.New("DSM 未确认账号不存在")
			}
			if err := verifyAccountAbsent(cfg, name); err != nil {
				return err
			}
			if _, found, err := (creationTarget{cfg: cfg, name: name}).receiptID(); err != nil || found {
				return errors.Join(errors.New("DSM 账号创建回执待核实"), err)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if !info.ExpiryKnown {
			return errors.New("无法确认 DSM 账号启停状态")
		}
		// Cleanup removes mappings. A previous offboarding receipt must not
		// authorize a future directory import to re-enable this account.
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		if _, exists := p.SyncDisables[name]; exists {
			delete(p.SyncDisables, name)
			if err := saveAccountPolicy(cfg, p); err != nil {
				return err
			}
		}
		if info.Expired {
			return nil
		}
		if err := modifySynoUser(cfg.SynoUserPath, name, info.FullName, true, info.Mail); err != nil {
			return err
		}
		confirmed, err := getSynoUser(cfg.SynoUserPath, name)
		if err != nil || !confirmed.ExpiryKnown || !confirmed.Expired {
			return errors.Join(errors.New("DSM 未确认账号已停用"), err)
		}
		return nil
	})
	if err != nil {
		return errorResponse("CLEANUP_FAILED", err.Error())
	}
	return map[string]any{"success": true, "outcome": outcome}
}
