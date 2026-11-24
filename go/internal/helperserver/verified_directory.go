package helperserver

import (
	"errors"
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
