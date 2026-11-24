package helperserver

import (
	"errors"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

// This receipt is written in the root policy only after a native transition
// from active to disabled has been read back under the account and writer locks.
type syncDisableReceipt struct {
	UID       int    `json:"uid"`
	Source    string `json:"source"`
	Subject   string `json:"subject"`
	AccountID string `json:"account_id"`
	RunID     string `json:"run_id"`
}

func (s *Server) reconcileSyncDisable(cfg config.HelperConfig, name string, info synoUserInfo) (bool, error) {
	if cfg.AccountPolicyPath == "" {
		if info.Expired {
			return false, errAccountDisabled
		}
		return false, nil
	}
	policy, err := readAccountPolicy(cfg)
	if err != nil {
		return false, err
	}
	receipt, found := policy.SyncDisables[name]
	if !found {
		if info.Expired {
			return false, errAccountDisabled
		}
		return false, nil
	}
	u, err := normalUser(cfg, name)
	if err != nil || u.id != receipt.UID {
		return false, errors.Join(errAccountDisabled, err)
	}
	grant, err := userEnrollment(cfg, name)
	if err != nil {
		return false, err
	}
	if grant != nil && (grant.DingTalk == nil || grant.DingTalk.Subject != receipt.Subject || grant.DingTalk.SourceSlug != receipt.Source) {
		return false, errAccountDisabled
	}
	if !info.ExpiryKnown {
		return false, errors.New("无法确认此前停用的 DSM 账号状态")
	}
	if info.Expired {
		query := db.HelperAuthorizationQuery{Action: "restore_sync_disable", Username: name, SourceSlug: receipt.Source, Subject: receipt.Subject, AccountID: receipt.AccountID}
		if err := s.authorizeAccount(cfg, query); err != nil {
			return false, errors.Join(errAccountDisabled, err)
		}
	}
	// Consume before enabling. An interrupted native command must never leave
	// authorization to override a subsequent manual disable.
	delete(policy.SyncDisables, name)
	if err := saveAccountPolicy(cfg, policy); err != nil {
		return false, err
	}
	if !info.Expired {
		return false, nil
	}
	if err := modifySynoUser(cfg.SynoUserPath, name, info.FullName, false, info.Mail); err != nil {
		return false, err
	}
	active, err := getSynoUser(cfg.SynoUserPath, name)
	if err != nil || !active.ExpiryKnown || active.Expired {
		return false, errors.Join(errors.New("DSM 未确认账号已恢复"), err)
	}
	return true, nil
}
