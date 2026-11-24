package helperserver

import (
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

type loginApprovalTicket struct {
	Owner     db.CredentialIdentity `json:"owner"`
	UID       int                   `json:"uid"`
	Code      string                `json:"code"`
	ExpiresAt int64                 `json:"expires_at"`
}

// For a legacy membership-only binding, the administrator proves control of
// the pinned native account by editing its description in DSM. No field
// supplied by the browser or directory is accepted as that proof.
func (s *Server) webLoginApproval(cfg config.HelperConfig, payload map[string]any) map[string]any {
	name, e1 := requiredString(payload, "dsm_username")
	source, e2 := requiredString(payload, "source_slug")
	subject, e3 := requiredString(payload, "subject")
	identityID, e4 := requiredString(payload, "identity_id")
	verify, ok := payload["verify"].(bool)
	if errors.Join(e1, e2, e3, e4) != nil || !ok || cfg.AccountPolicyPath == "" {
		return errorResponse("BAD_REQUEST", "缺少要核实的账号或来源身份")
	}
	owner := db.CredentialIdentity{Username: name, SourceSlug: source, Subject: subject}
	req := db.HelperAuthorizationQuery{Action: "login", Username: name, SourceSlug: source, IdentityID: identityID, CredentialOwner: &owner}
	result := map[string]any{"success": true, "approved": false}
	err := withAccountMutation(cfg, name, false, func() error {
		grant, err := userEnrollment(cfg, name)
		if err != nil {
			return err
		}
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		bound, hasOwner := p.CredentialOwners[name]
		if hasOwner && bound != owner {
			return errors.New("此 DSM 账号已绑定其他身份")
		}
		allowed, err := s.mappingAllowed(cfg, req)
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("当前登录映射已禁用、失效或存在多个归属")
		}
		if grant == nil {
			result["approved"] = true
			return nil
		}
		if hasOwner || (grant.DingTalk != nil && (grant.DingTalk.SourceSlug != source || grant.DingTalk.Subject != subject)) {
			return errors.New("待核实身份与原通讯录绑定不一致")
		}
		if other, ok := p.CredentialCandidates[name]; ok && (other.Owner != owner || other.UID != grant.UID) {
			return errors.New("存在另一条待核实的身份记录")
		}
		if _, err := os.Lstat((creationTarget{cfg: cfg, name: name}).path()); !os.IsNotExist(err) {
			return errors.New("账号的创建回执仍待核实")
		}
		info, err := getSynoUser(cfg.SynoUserPath, name)
		if err != nil {
			return err
		}
		if !info.ExpiryKnown {
			return errors.New("无法确认 DSM 账号是否启用")
		}
		if info.Expired {
			return errors.New("此 DSM 账号已停用")
		}
		now := time.Now()
		ticket := p.LoginApprovals[name]
		valid := ticket.Owner == owner && ticket.UID == grant.UID && ticket.Code != "" && ticket.ExpiresAt > now.Unix()
		if verify {
			if !valid || !slices.Contains(strings.Fields(info.FullName), ticket.Code) {
				return errors.New("请检查当前确认码是否已保存到该 DSM 用户的描述，过期后需重新获取")
			}
			linked, err := s.bindCredentialOwner(cfg, p, owner, grant.UID, grant, req)
			if err != nil {
				return err
			}
			if !linked {
				return errors.New("账号绑定已变化，请刷新后重试")
			}
			result["approved"] = true
			return nil
		}
		if !valid {
			if p.LoginApprovals == nil {
				p.LoginApprovals = make(map[string]loginApprovalTicket)
			}
			for key, pending := range p.LoginApprovals {
				if pending.ExpiresAt <= now.Unix() {
					delete(p.LoginApprovals, key)
				}
			}
			if _, exists := p.LoginApprovals[name]; !exists && len(p.LoginApprovals) >= 256 {
				return errors.New("待核实账号较多，请先完成已有确认")
			}
			ticket = loginApprovalTicket{Owner: owner, UID: grant.UID, Code: "DP-U-" + rand.Text(), ExpiresAt: now.Add(15 * time.Minute).Unix()}
			p.LoginApprovals[name] = ticket
			if err := saveAccountPolicy(cfg, p); err != nil {
				return err
			}
		}
		result["code"] = ticket.Code
		result["expires_at"] = time.Unix(ticket.ExpiresAt, 0).UTC().Format(time.RFC3339)
		return nil
	})
	if err != nil {
		return errorResponse("LOGIN_APPROVAL_FAILED", err.Error())
	}
	return result
}
