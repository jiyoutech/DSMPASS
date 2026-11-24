package helperserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

// Only the trusted installer captures the verified email/subject pairs and local UIDs.
// Provisioning or the first login can complete the link using the independently stored DSM email.
func captureVerifiedDirectory(cfg config.HelperConfig, p *accountPolicy, emails map[string]db.CredentialIdentity, users, groups map[string]systemAccount) bool {
	changed := false
	for email, owner := range emails {
		name := owner.Username
		if _, fixed := p.CredentialCandidates[name]; fixed {
			continue
		}
		if _, managed := p.Users[name]; managed {
			continue
		}
		if name == "" || owner.SourceSlug == "" || owner.Subject == "" || email == "" || assertAllowed(cfg, name) != nil {
			continue
		}
		user, err := normalLocalUser(name, users, groups)
		if err != nil || !ordinaryInstallUser(user, groups) {
			continue
		}
		if previous, ok := p.DirectoryUsers[name]; ok && previous.UID != user.id {
			continue
		}
		if p.DingTalkScope != nil {
			if uid, ok := p.DingTalkScope.Users[name]; ok && uid != user.id {
				continue
			}
		}
		if p.CredentialCandidates == nil {
			p.CredentialCandidates = map[string]verifiedAccountCandidate{}
		}
		p.CredentialCandidates[name] = verifiedAccountCandidate{UID: user.id, Email: email, Owner: owner}
		changed = true
	}
	return changed
}

func (s *Server) dingTalkLoginBinding(cfg config.HelperConfig, name string, uid int) (*db.DingTalkLoginMatch, error) {
	if cfg.Privileged {
		result, err := queryHelperAsPackage(cfg, db.HelperAuthorizationQuery{Action: "dingtalk_login_binding", Username: name, LocalUID: uid, DatabasePath: strings.TrimPrefix(cfg.DatabaseURL, "sqlite://")})
		return result.DingTalkLoginMatch, err
	}
	return db.DingTalkLoginBinding(context.Background(), s.store, name, uid)
}

// The account and policy locks cover both enrollment paths. On first login
// we only query DSM once a candidate exists. Provisioning has already read it.
func (s *Server) linkExistingDirectoryUser(cfg config.HelperConfig, req db.HelperAuthorizationQuery, grant *directoryUserGrant, info *synoUserInfo) (bool, error) {
	name := req.Username
	local, err := normalUser(cfg, name)
	if err != nil {
		return false, err
	}
	binding, err := s.dingTalkLoginBinding(cfg, name, local.id)
	if err != nil {
		return false, err
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return false, err
	}
	// A database mapping can identify an employee only within a root-enrolled
	// local account and source. Retained DingTalk grants carry that same pin.
	if binding != nil {
		pinned := grant != nil && grant.UID == local.id && grant.DingTalk != nil && grant.DingTalk.SourceSlug == binding.SourceSlug &&
			(grant.DingTalk.Subject == binding.Subject || binding.Selected)
		if scope := p.DingTalkScope; scope != nil {
			pinned = slices.Contains(scope.Sources, binding.SourceSlug) && (pinned || scope.Users[name] == local.id)
		}
		if !pinned {
			binding = nil
		}
	}
	candidate, hasEmail := p.CredentialCandidates[name]
	if binding == nil && (!hasEmail || (req.SourceSlug != "" && candidate.Owner.SourceSlug != req.SourceSlug)) {
		return false, nil
	}
	if info == nil {
		current, err := getSynoUser(cfg.SynoUserPath, name)
		if err != nil {
			return false, err
		}
		info = &current
	}
	if req.Action == "login" && !info.ExpiryKnown {
		return false, errors.New("无法确认 DSM 账号是否启用")
	}
	if info.Expired {
		return false, fmt.Errorf("DSM 用户 %q 已停用", name)
	}
	if binding != nil && info.ExpiryKnown {
		owner := db.CredentialIdentity{Username: name, SourceSlug: binding.SourceSlug, Subject: binding.Subject}
		if hasEmail && (candidate.UID != local.id || candidate.Owner != owner) {
			return false, nil
		}
		if _, err := os.Lstat((creationTarget{cfg: cfg, name: name}).path()); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
		for other, g := range p.DirectoryUsers {
			if other != name && g.DingTalk != nil && *g.DingTalk == binding.DingTalkUserBinding {
				return false, nil
			}
		}
		for other, c := range p.CredentialCandidates {
			if other != name && c.Owner.SourceSlug == owner.SourceSlug && c.Owner.Subject == owner.Subject {
				return false, nil
			}
		}
		// An explicit choice can supersede a membership-only subject for the
		// same enrolled source and UID. Established credentials remain pinned.
		if binding.Selected && grant != nil && grant.DingTalk != nil && grant.DingTalk.SourceSlug == binding.SourceSlug {
			choice := *grant
			choice.DingTalk = &binding.DingTalkUserBinding
			grant = &choice
		}
		return s.bindCredentialOwner(cfg, p, owner, local.id, grant, req)
	}
	if req.Action == "provision" {
		req.Action = "verify_existing_owner"
	}
	return s.linkVerifiedDirectoryUser(cfg, name, info.Mail, grant, req)
}

// Called under both account locks, using the email read from DSM itself.
func (s *Server) linkVerifiedDirectoryUser(cfg config.HelperConfig, name, mail string, grant *directoryUserGrant, req db.HelperAuthorizationQuery) (bool, error) {
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return false, err
	}
	candidate, ok := p.CredentialCandidates[name]
	mail = strings.ToLower(strings.TrimSpace(mail))
	if !ok || candidate.Email != mail || mail == "" {
		return false, nil
	}
	req.VerifiedEmail = mail
	return s.bindCredentialOwner(cfg, p, candidate.Owner, candidate.UID, grant, req)
}

// The caller holds both account locks and has independently verified ownership in DSM.
func (s *Server) bindCredentialOwner(cfg config.HelperConfig, p accountPolicy, owner db.CredentialIdentity, uid int, grant *directoryUserGrant, req db.HelperAuthorizationQuery) (bool, error) {
	name := req.Username
	if prior, ok := p.CredentialOwners[name]; ok && prior != owner {
		return false, errors.New("该账号已有其他固定登录归属")
	}
	if _, explicit := p.Users[name]; explicit || owner.Username != name {
		return false, nil
	}
	if scope := p.DingTalkScope; scope != nil {
		if original, ok := scope.Users[name]; ok && original != uid {
			return false, errors.New("DSM 用户的原始 UID 与映射不符")
		}
	}
	if grant != nil && (grant.UID != uid || (grant.DingTalk != nil && (grant.DingTalk.Subject != owner.Subject || grant.DingTalk.SourceSlug != owner.SourceSlug))) {
		return false, nil
	}
	account, err := normalUser(cfg, name)
	if err != nil {
		return false, err
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return false, err
	}
	if account.id != uid || !ordinaryInstallUser(account, groups) {
		return false, errors.New("DSM 普通账号的 UID 或权限已改变")
	}
	for existing, bound := range p.CredentialOwners {
		if existing != name && bound.Subject == owner.Subject && bound.SourceSlug == owner.SourceSlug {
			return false, errors.New("该身份已绑定其他 DSM 账号")
		}
	}
	req.CredentialOwner = &owner
	allowed, err := s.mappingAllowed(cfg, req)
	if err != nil || !allowed {
		return false, err
	}
	if p.CredentialOwners == nil {
		p.CredentialOwners = map[string]db.CredentialIdentity{}
	}
	p.CredentialOwners[name] = owner
	p.Users[name] = uid
	delete(p.CredentialCandidates, name)
	delete(p.DirectoryUsers, name)
	delete(p.LoginApprovals, name)
	return true, saveAccountPolicy(cfg, p)
}
