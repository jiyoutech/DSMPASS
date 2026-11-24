package helperserver

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

type loginRosterEntry struct {
	Username string
	Subject  string
	UID      int
	email    string
}

// BindDingTalkLogins is an explicit, source-scoped DSM administrator command.
// Database rows and directory membership by themselves cannot grant credentials.
func BindDingTalkLogins(cfg config.HelperConfig, source string, dryRun bool) (int, error) {
	if !cfg.Privileged || os.Geteuid() != 0 || source == "" {
		return 0, errors.New("请用 DSM 管理员身份指定要处理的钉钉身份源")
	}
	return bindDingTalkLogins(cfg, source, dryRun, func() (map[string]string, error) {
		result, err := queryHelperAsPackage(cfg, db.HelperAuthorizationQuery{
			Action: "dingtalk_login_roster", SourceSlug: source, DatabasePath: strings.TrimPrefix(cfg.DatabaseURL, "sqlite://"),
		})
		return result.LoginRoster, err
	})
}

func bindDingTalkLogins(cfg config.HelperConfig, source string, dryRun bool, query func() (map[string]string, error)) (int, error) {
	load := func() (accountPolicy, []loginRosterEntry, error) {
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return p, nil, err
		}
		rows, err := query()
		if err != nil {
			return p, nil, err
		}
		entries, err := eligibleLoginRoster(cfg, p, source, rows)
		return p, entries, err
	}
	_, preview, err := load()
	if err != nil {
		return 0, err
	}
	if len(preview) == 0 {
		return 0, nil
	}
	// Do the potentially slow, read-only DSM commands outside the writer lock.
	active := make(map[string]bool, len(preview))
	for _, entry := range preview {
		info, err := getSynoUser(cfg.SynoUserPath, entry.Username)
		if err != nil {
			return 0, fmt.Errorf("读取 DSM 用户 %q 失败，本批未写入: %w", entry.Username, err)
		}
		mail := strings.TrimSpace(info.Mail)
		if info.ExpiryKnown && !info.Expired && !directoryMailConflict(entry.email, mail) {
			active[entry.Username] = true
		}
	}
	if dryRun {
		return len(active), nil
	}
	err = withFileLock(cfg.ShadowLockPath, func() error {
		p, current, err := load()
		if err != nil {
			return err
		}
		if !slices.Equal(preview, current) {
			return errors.New("批处理期间账号或映射发生变化，本批未写入，请重试")
		}
		if len(active) == 0 {
			return nil
		}
		if p.CredentialOwners == nil {
			p.CredentialOwners = map[string]db.CredentialIdentity{}
		}
		for _, entry := range current {
			name := entry.Username
			if !active[name] {
				continue
			}
			p.Users[name] = entry.UID
			p.CredentialOwners[name] = db.CredentialIdentity{Username: name, SourceSlug: source, Subject: entry.Subject}
			delete(p.DirectoryUsers, name)
			delete(p.CredentialCandidates, name)
			delete(p.LoginApprovals, name)
		}
		return saveAccountPolicy(cfg, p)
	})
	if err != nil {
		return 0, err
	}
	return len(active), nil
}

func eligibleLoginRoster(cfg config.HelperConfig, p accountPolicy, source string, rows map[string]string) ([]loginRosterEntry, error) {
	if p.DingTalkScope != nil && !slices.Contains(p.DingTalkScope.Sources, source) {
		return nil, nil
	}
	users, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return nil, err
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return nil, err
	}
	if _, ok := groups["administrators"]; !ok {
		return nil, errors.New("无法确定 DSM 管理员组")
	}
	// Count distinct DSM names pinned to each employee, including existing owners.
	subjectNames := make(map[string]string)
	record := func(name, slug, subject string) {
		if slug != source {
			return
		}
		if first, ok := subjectNames[subject]; ok && first != name {
			subjectNames[subject] = ""
		} else {
			subjectNames[subject] = name
		}
	}
	for name, grant := range p.DirectoryUsers {
		if grant.DingTalk != nil {
			record(name, grant.DingTalk.SourceSlug, grant.DingTalk.Subject)
		}
	}
	for name, owner := range p.CredentialOwners {
		record(name, owner.SourceSlug, owner.Subject)
	}
	for name, candidate := range p.CredentialCandidates {
		record(name, candidate.Owner.SourceSlug, candidate.Owner.Subject)
	}
	localNames := make(map[string]int, len(users))
	for name := range users {
		localNames[strings.ToLower(strings.TrimSpace(name))]++
	}
	var entries []loginRosterEntry
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		subject := rows[name]
		g := p.DirectoryUsers[name]
		if subject == "" || g.DingTalk == nil || g.DingTalk.SourceSlug != source || g.DingTalk.Subject != subject || subjectNames[subject] != name {
			continue
		}
		if _, managedOrRevoked := p.Users[name]; managedOrRevoked || assertAllowed(cfg, name) != nil || localNames[strings.ToLower(name)] != 1 {
			continue
		}
		if _, owned := p.CredentialOwners[name]; owned {
			continue
		}
		user, err := normalLocalUser(name, users, groups)
		if err != nil || user.id != g.UID || !ordinaryInstallUser(user, groups) {
			continue
		}
		if scope := p.DingTalkScope; scope != nil {
			if uid, ok := scope.Users[name]; ok && uid != user.id {
				continue
			}
		}
		entry := loginRosterEntry{Username: name, Subject: subject, UID: g.UID}
		if c, ok := p.CredentialCandidates[name]; ok {
			if c.UID != g.UID || c.Owner != (db.CredentialIdentity{Username: name, SourceSlug: source, Subject: subject}) {
				continue
			}
			entry.email = c.Email
		}
		if _, err := os.Lstat((creationTarget{cfg: cfg, name: name}).path()); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
