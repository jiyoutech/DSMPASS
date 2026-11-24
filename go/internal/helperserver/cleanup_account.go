package helperserver

import (
	"errors"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/identity"
	"os"
)

type cleanupResult struct {
	RequestID string
	Source    string
	AccountID string
	Outcome   string
	UID       int
}

func (s *Server) cleanupAccount(cfg config.HelperConfig, payload map[string]any) map[string]any {
	name, _ := requiredString(payload, "dsm_username")
	source, _ := requiredString(payload, "source_slug")
	account, _ := requiredString(payload, "account_id")
	id, _ := requiredString(payload, "request_id")
	reserved := identity.IsReservedDSMUsername(name)
	if id == "" || account == "" || source == "" || (!reserved && assertAllowed(cfg, name) != nil) {
		return errorResponse("BAD_REQUEST", "清理目标无效")
	}
	req := db.HelperAuthorizationQuery{Username: name, SourceSlug: source, AccountID: account, RunID: id}
	classify := func() (string, error) {
		if reserved {
			req.Action = "cleanup_protected"
			return "unmapped_conflict", s.authorizeCleanupRecord(cfg, req)
		}
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return "", err
		}
		prior := p.CleanupResults[name]
		if prior.RequestID == id && prior.Source == source && prior.AccountID == account {
			req.Action = "cleanup_replay"
			return prior.Outcome, s.authorizeAccount(cfg, req)
		}
		grant, err := userEnrollment(cfg, name)
		req.Action = "cleanup_user"
		outcome := "disabled"
		switch {
		case errors.Is(err, os.ErrNotExist):
			req.Action = "cleanup_absent"
			outcome = "absent"
		case errors.Is(err, errPrivilegedUser), errors.Is(err, errRevokedUser):
			req.Action = "cleanup_protected"
			outcome = "unmapped_conflict"
		case errors.Is(err, errUserNotEnrolled):
			req.Action = "cleanup_conflict"
			outcome = "unmapped_conflict"
		case err != nil:
			return "", err
		case grant != nil:
			outcome = "membership_only"
		}
		if req.Action == "cleanup_protected" {
			return outcome, s.authorizeCleanupRecord(cfg, req)
		}
		return outcome, s.authorizeAccount(cfg, req)
	}
	outcome, err := classify()
	if err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	err = withAccountMutation(cfg, name, outcome == "disabled" && req.Action != "cleanup_replay", func() error {
		now, err := classify()
		if err != nil {
			return err
		}
		if now != outcome {
			return errors.New("DSM 账号归属已变化，请重试")
		}
		if req.Action == "cleanup_protected" {
			return nil
		}
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		if req.Action == "cleanup_replay" {
			if outcome == "disabled" {
				local, err := normalUser(cfg, name)
				if err != nil {
					return err
				}
				info, err := getSynoUser(cfg.SynoUserPath, name)
				if err != nil || !info.ExpiryKnown || !info.Expired || p.CleanupResults[name].UID != local.id {
					return errors.Join(errors.New("清理后 DSM 账号状态已变化，请核实"), err)
				}
			}
			if outcome == "absent" {
				return confirmedNativeAbsence(cfg, name)
			}
			return nil
		}
		result := cleanupResult{RequestID: id, Source: source, AccountID: account, Outcome: outcome}
		switch outcome {
		case "absent":
			if err := confirmedNativeAbsence(cfg, name); err != nil {
				return err
			}
		case "disabled":
			local, err := normalUser(cfg, name)
			if err != nil {
				return err
			}
			result.UID = local.id
			info, err := getSynoUser(cfg.SynoUserPath, name)
			if err != nil {
				return err
			}
			if !info.ExpiryKnown {
				return errors.New("无法确认 DSM 账号启停状态")
			}
			if !info.Expired {
				if err := modifySynoUser(cfg.SynoUserPath, name, info.FullName, true, info.Mail); err != nil {
					return err
				}
				confirmed, err := getSynoUser(cfg.SynoUserPath, name)
				if err != nil || !confirmed.ExpiryKnown || !confirmed.Expired {
					return errors.Join(errors.New("DSM 未确认账号已停用"), err)
				}
			}
		}
		releaseSourceGrants(&p, name, source)
		if p.CleanupResults == nil {
			p.CleanupResults = map[string]cleanupResult{}
		}
		p.CleanupResults[name] = result
		return saveAccountPolicy(cfg, p)
	})
	if err != nil {
		return errorResponse("CLEANUP_FAILED", err.Error())
	}
	return map[string]any{"success": true, "outcome": outcome}
}

// A protected collision only retires the package record and can never
// change the native account or its independent root policy.
func (s *Server) authorizeCleanupRecord(cfg config.HelperConfig, req db.HelperAuthorizationQuery) error {
	allowed, err := s.mappingAllowed(cfg, req)
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("账号不属于本次清理的冲突记录")
	}
	return nil
}

// A preserved standalone grant has no source. A source-issued credential and
// its matching UID grant must be removed together, even on interrupted cleanup.
func releaseSourceGrants(p *accountPolicy, name, source string) {
	if p.CredentialOwners[name].SourceSlug == source || p.CreatedUsers[name].SourceSlug == source {
		if p.Users[name] != revokedUserID {
			delete(p.Users, name)
		}
		if p.CredentialOwners[name].SourceSlug == source {
			delete(p.CredentialOwners, name)
		}
		if p.CreatedUsers[name].SourceSlug == source {
			delete(p.CreatedUsers, name)
		}
	}
	if g := p.DirectoryUsers[name]; g.Source == source || (g.DingTalk != nil && g.DingTalk.SourceSlug == source) {
		if g.Source == "" && len(g.Groups) > 0 {
			g.DingTalk = nil
			p.DirectoryUsers[name] = g
		} else {
			delete(p.DirectoryUsers, name)
		}
	}
	if p.CredentialCandidates[name].Owner.SourceSlug == source {
		delete(p.CredentialCandidates, name)
	}
	if p.LoginApprovals[name].Owner.SourceSlug == source {
		delete(p.LoginApprovals, name)
	}
	if p.SyncDisables[name].Source == source {
		delete(p.SyncDisables, name)
	}
}

func confirmedNativeAbsence(cfg config.HelperConfig, name string) error {
	_, err := getSynoUser(cfg.SynoUserPath, name)
	if !dsmUserNotFound(err) {
		return errors.Join(errors.New("DSM 未确认账号不存在"), err)
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return err
	}
	if _, present := users[name]; present {
		return errors.New("DSM 本地账号表仍有此人")
	}
	if _, found, err := (creationTarget{cfg: cfg, name: name}).receiptID(); err != nil || found {
		return errors.Join(errors.New("DSM 账号创建回执待核实"), err)
	}
	return nil
}

// Only the local root CLI may retire an unscoped legacy grant after manual removal.
func forgetAbsentUser(cfg config.HelperConfig, name string) error {
	if err := confirmedNativeAbsence(cfg, name); err != nil {
		return err
	}
	if err := checkPasswordResetPending(cfg, name); err != nil {
		return err
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	if p.Users[name] == revokedUserID {
		return errRevokedUser
	}
	delete(p.Users, name)
	delete(p.CredentialOwners, name)
	delete(p.CreatedUsers, name)
	delete(p.DirectoryUsers, name)
	delete(p.CredentialCandidates, name)
	delete(p.LoginApprovals, name)
	delete(p.SyncDisables, name)
	delete(p.CleanupResults, name)
	if p.DingTalkScope != nil {
		delete(p.DingTalkScope.Users, name)
	}
	return saveAccountPolicy(cfg, p)
}
