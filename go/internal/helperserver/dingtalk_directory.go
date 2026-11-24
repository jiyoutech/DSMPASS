package helperserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

// Only the explicit root installer selects sources and pins existing ordinary
// DSM users. New directory mappings can use these UIDs for membership only.
func captureDingTalkDirectory(cfg config.HelperConfig, policy *accountPolicy, sources []string, users, groups map[string]systemAccount) bool {
	if len(sources) == 0 && policy.DingTalkScope == nil {
		return false
	}
	changed := false
	if policy.DingTalkScope == nil {
		policy.DingTalkScope = &dingTalkDirectoryScope{Users: make(map[string]int)}
		changed = true
	}
	scope := policy.DingTalkScope
	if !slices.Equal(scope.Sources, sources) {
		scope.Sources = slices.Clone(sources)
		changed = true
	}
	if len(sources) == 0 {
		return changed
	}
	if scope.Users == nil {
		scope.Users = make(map[string]int)
	}
	for name, user := range users {
		if _, fixed := scope.Users[name]; fixed {
			continue
		}
		if _, enrolled := policy.Users[name]; enrolled {
			continue
		}
		if grant, enrolled := policy.DirectoryUsers[name]; enrolled && grant.UID != user.id {
			continue
		}
		if assertAllowed(cfg, name) != nil || !ordinaryInstallUser(user, groups) {
			continue
		}
		if _, err := normalLocalUser(name, users, groups); err != nil {
			continue
		}
		scope.Users[name] = user.id
		changed = true
	}
	return changed
}

// Called under the account and policy writer locks, after DSM has confirmed the
// account exists and is active. No login, reset, or group RPC may create a link.
func (s *Server) linkDingTalkDirectoryUser(cfg config.HelperConfig, name string) (*directoryUserGrant, error) {
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return nil, err
	}
	if p.DingTalkScope == nil || len(p.DingTalkScope.Sources) == 0 {
		return nil, fmt.Errorf("DSM 用户 %q %w，请运行 setup-helper-sudo.sh 核对钉钉身份源和 UID", name, errUserNotEnrolled)
	}
	if _, explicit := p.Users[name]; explicit {
		return nil, errors.New("该用户已有独立授权或撤销记录")
	}
	if _, linked := p.DirectoryUsers[name]; linked {
		return nil, errors.New("该用户已有通讯录绑定")
	}
	id, captured := p.DingTalkScope.Users[name]
	if !captured {
		return nil, fmt.Errorf("DSM 用户 %q 尚未登记，请运行 setup-helper-sudo.sh 核对当前 UID", name)
	}
	account, err := normalUser(cfg, name)
	if err != nil {
		return nil, err
	}
	if account.id != id {
		return nil, fmt.Errorf("DSM 用户 %q 的 UID 已从 %d 变为 %d", name, id, account.id)
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return nil, err
	}
	if !ordinaryInstallUser(account, groups) {
		return nil, errors.New("仅普通本地用户可按钉钉姓名关联")
	}

	var binding *db.DingTalkUserBinding
	if cfg.Privileged {
		result, err := queryHelperAsPackage(cfg, db.HelperAuthorizationQuery{Action: "dingtalk_binding", DatabasePath: strings.TrimPrefix(cfg.DatabaseURL, "sqlite://"), Username: name})
		if err != nil {
			return nil, err
		}
		binding = result.DingTalkBinding
	} else {
		binding, err = db.DingTalkBindingForName(context.Background(), s.store, name)
		if err != nil {
			return nil, err
		}
	}
	if binding == nil || !slices.Contains(p.DingTalkScope.Sources, binding.SourceSlug) {
		return nil, errors.New("未找到已启用钉钉通讯录中唯一的同名用户")
	}
	grant := directoryUserGrant{UID: id, DingTalk: binding}
	if p.DirectoryUsers == nil {
		p.DirectoryUsers = make(map[string]directoryUserGrant)
	}
	p.DirectoryUsers[name] = grant
	return &grant, saveAccountPolicy(cfg, p)
}
