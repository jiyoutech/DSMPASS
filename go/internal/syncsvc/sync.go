package syncsvc

import (
	"context"
	"fmt"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/identity"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

type PlanItem struct {
	Action          string `json:"action"`
	ProviderSlug    string `json:"provider_slug"`
	Subject         string `json:"subject"`
	DisplayName     string `json:"display_name"`
	DSMUsername     string `json:"dsm_username"`
	DSMGroupname    string `json:"dsm_groupname"`
	ProvisionStatus string `json:"provision_status"`
}

type Result struct {
	ProviderSlug string     `json:"provider_slug"`
	Items        []PlanItem `json:"items"`
}

type Engine struct {
	cfg     config.BackendConfig
	q       *db.Queries
	options Options
}

type Options struct {
	DeactivateMissingData bool
	SyncStart             string
	Progress              func(phase string, current, total int, message string)
}

func NewEngine(cfg config.BackendConfig, q *db.Queries) *Engine {
	return &Engine{cfg: cfg, q: q}
}

func NewEngineWithOptions(cfg config.BackendConfig, q *db.Queries, options Options) *Engine {
	return &Engine{cfg: cfg, q: q, options: options}
}

func (e *Engine) SyncProvider(ctx context.Context, directory provider.Directory) (Result, error) {
	identityService := identity.NewService(e.cfg, e.q)
	providerName := providerDisplayName(directory)
	result := Result{ProviderSlug: directory.Slug()}
	syncStart := e.options.SyncStart
	if e.options.DeactivateMissingData && strings.TrimSpace(syncStart) == "" {
		_ = e.q.DBTX().QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&syncStart)
	}
	users, err := directory.ListUsers()
	if err != nil {
		return result, err
	}
	e.report("写入用户映射", 0, len(users), "正在写入用户映射")
	duplicateUserNames := duplicateUserNameCounts(users, e.cfg)
	for index, user := range users {
		verified := true
		subjectType := strings.TrimSpace(user.SubjectType)
		if subjectType == "" {
			subjectType = "directory_subject"
		}
		external, err := identityService.UpsertProfile(ctx, identity.ExternalProfile{
			ProviderSlug:  user.ProviderSlug,
			Subject:       user.Subject,
			SubjectType:   subjectType,
			DisplayName:   user.DisplayName,
			Email:         user.Email,
			EmailVerified: &verified,
			Mobile:        user.Mobile,
		})
		if err != nil {
			return result, err
		}
		appIdentity, identityLinkedExisting, err := identityService.ResolveOrCreateIdentityWithLinkedExisting(ctx, external)
		if err != nil {
			return result, err
		}
		account, accountCreated, err := identityService.EnsureDSMAccountWithCreated(ctx, appIdentity)
		if err != nil {
			return result, err
		}
		if accountCreated && duplicateUserNames[userNameKey(user.DisplayName, e.cfg)] > 1 && account.Managed == 1 {
			account, err = identityService.MarkDSMAccountConflict(ctx, account.ID, fmt.Sprintf("冲突类型：%s通讯录内用户姓名重名。请根据邮箱、手机号、身份 ID 和部门手动指定最终 DSM 用户名", providerName))
			if err != nil {
				return result, err
			}
		}
		if account.ProvisionStatus != "conflict" {
			if err := identityService.EnsureDSMUserMapping(ctx, user.ProviderSlug, external.ID, account.ID); err != nil {
				return result, err
			}
		}
		action := "update_external_account"
		if identityLinkedExisting {
			action = "link_existing_dsm_user"
		} else if account.ProvisionStatus == "pending" {
			action = "ensure_dsm_user"
		}
		result.Items = append(result.Items, PlanItem{
			Action:          action,
			ProviderSlug:    user.ProviderSlug,
			Subject:         user.Subject,
			DisplayName:     user.DisplayName,
			DSMUsername:     account.DSMUsername,
			ProvisionStatus: account.ProvisionStatus,
		})
		e.report("写入用户映射", index+1, len(users), user.DisplayName)
	}
	groups, err := directory.ListGroups()
	if err != nil {
		return result, err
	}
	e.report("写入部门映射", 0, len(groups), "正在写入部门映射")
	duplicateGroupSubjects := duplicateGroupSubjects(groups)
	groups = disambiguateDuplicateGroupNames(groups)
	for index, group := range groups {
		providerGroup, err := identityService.EnsureProviderGroup(ctx, group.ProviderSlug, group.Subject, group.ParentSubject, group.Name, group.Path)
		if err != nil {
			return result, err
		}
		dsmGroup, groupLinkedExisting, err := identityService.EnsureDSMGroupWithLinkedExisting(ctx, providerGroup)
		if err != nil {
			return result, err
		}
		if duplicateGroupSubjects[group.Subject] && dsmGroup.Managed == 1 {
			dsmGroup, err = identityService.MarkDSMGroupConflict(ctx, dsmGroup.ID, fmt.Sprintf("%s部门名重名，请管理员根据%s部门路径手动指定 DSM 部门组名", providerName, providerName))
			if err != nil {
				return result, err
			}
		}
		if err := identityService.EnsureGroupLink(ctx, providerGroup.ID, dsmGroup.ID); err != nil {
			return result, err
		}
		if dsmGroup.ProvisionStatus != "conflict" {
			if err := identityService.EnsureDSMGroupMapping(ctx, group.ProviderSlug, providerGroup.ID, dsmGroup.ID); err != nil {
				return result, err
			}
		}
		action := "update_provider_group"
		if groupLinkedExisting {
			action = "link_existing_dsm_group"
		} else if dsmGroup.ProvisionStatus == "pending" {
			action = "ensure_dsm_group"
		}
		result.Items = append(result.Items, PlanItem{
			Action:          action,
			ProviderSlug:    group.ProviderSlug,
			Subject:         group.Subject,
			DisplayName:     group.Name,
			DSMGroupname:    dsmGroup.DSMGroupname,
			ProvisionStatus: dsmGroup.ProvisionStatus,
		})
		e.report("写入部门映射", index+1, len(groups), group.Path)
	}
	groupMap, err := identityService.ProviderGroupsToDSMGroups(ctx, directory.Slug())
	if err != nil {
		return result, err
	}
	accountMap, err := identityService.ExternalToDSMAccounts(ctx, directory.Slug())
	if err != nil {
		return result, err
	}
	membersByGroup := usersDepartmentMemberships(users, groups)
	memberTotal := 0
	if len(membersByGroup) > 0 {
		for _, members := range membersByGroup {
			memberTotal += len(members)
		}
	} else {
		memberTotal = len(groups)
	}
	memberCurrent := 0
	e.report("写入成员映射", 0, memberTotal, "正在写入成员映射")
	for _, group := range groups {
		dsmGroup, ok := groupMap[group.Subject]
		if !ok || dsmGroup.ProvisionStatus == "conflict" {
			continue
		}
		members := membersByGroup[group.Subject]
		if len(membersByGroup) == 0 {
			var err error
			members, err = directory.ListGroupMembers(group.Subject)
			if err != nil {
				return result, err
			}
			memberCurrent++
			e.report("读取部门成员", memberCurrent, memberTotal, group.Path)
		}
		for _, memberSubject := range members {
			account, ok := accountMap[memberSubject]
			if !ok || account.ProvisionStatus == "conflict" {
				continue
			}
			if err := identityService.EnsureDSMMemberMapping(ctx, group.ProviderSlug, group.Subject, memberSubject, dsmGroup.ID, account.ID); err != nil {
				return result, err
			}
			member, err := identityService.EnsureGroupMember(ctx, dsmGroup.ID, account.ID)
			if err != nil {
				return result, err
			}
			result.Items = append(result.Items, PlanItem{
				Action:          "ensure_group_member",
				ProviderSlug:    group.ProviderSlug,
				Subject:         group.Subject + ":" + memberSubject,
				DSMUsername:     account.DSMUsername,
				DSMGroupname:    dsmGroup.DSMGroupname,
				ProvisionStatus: member.ProvisionStatus,
			})
			memberCurrent++
			e.report("写入成员映射", memberCurrent, memberTotal, group.Path)
		}
	}
	if e.options.DeactivateMissingData {
		if err := identityService.DeactivateStaleMappings(ctx, directory.Slug(), syncStart); err != nil {
			return result, err
		}
	}
	if err := identityService.ReconcileFinalGroupMembers(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func providerDisplayName(directory provider.Directory) string {
	if named, ok := directory.(provider.Named); ok {
		if name := strings.TrimSpace(named.ProviderDisplayName()); name != "" {
			return name
		}
	}
	slug := strings.TrimSpace(directory.Slug())
	if strings.HasPrefix(slug, "feishu") {
		return "飞书"
	}
	if strings.HasPrefix(slug, "wecom") {
		return "企业微信"
	}
	if strings.HasPrefix(slug, "dingtalk") {
		return "钉钉"
	}
	return "身份源"
}

func (e *Engine) report(phase string, current, total int, message string) {
	if e.options.Progress != nil {
		e.options.Progress(phase, current, total, message)
	}
}

func deactivateMissingGroupMembers(ctx context.Context, q *db.Queries, providerSlug string, current map[string]bool) error {
	rows, err := q.DBTX().QueryContext(ctx, `
SELECT DISTINCT m.id, m.dsm_group_id, m.dsm_account_id
FROM group_members m
JOIN dsm_groups g ON g.id = m.dsm_group_id
JOIN group_links l ON l.dsm_group_id = g.id
JOIN provider_groups p ON p.id = l.provider_group_id
WHERE p.provider_slug = ? AND p.active = 1 AND m.active = 1`, providerSlug)
	if err != nil {
		return err
	}
	defer rows.Close()
	var staleIDs []string
	for rows.Next() {
		var id, groupID, accountID string
		if err := rows.Scan(&id, &groupID, &accountID); err != nil {
			return err
		}
		if !current[groupID+"\x00"+accountID] {
			staleIDs = append(staleIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range staleIDs {
		if _, err := q.DBTX().ExecContext(ctx, `
UPDATE group_members
SET active = 0, provision_status = 'remove_pending', updated_at = CURRENT_TIMESTAMP
WHERE id = ? AND active = 1`, id); err != nil {
			return err
		}
	}
	return nil
}

func usersDepartmentMemberships(users []provider.User, groups []provider.Group) map[string][]string {
	result := map[string][]string{}
	parentByGroup := groupParentSubjects(groups)
	seenMemberships := map[string]bool{}
	for _, user := range users {
		if len(user.DepartmentSubjects) == 0 {
			continue
		}
		for _, departmentSubject := range user.DepartmentSubjects {
			for _, inheritedSubject := range inheritedDepartmentSubjects(departmentSubject, parentByGroup) {
				key := inheritedSubject + "\x00" + user.Subject
				if seenMemberships[key] {
					continue
				}
				seenMemberships[key] = true
				result[inheritedSubject] = append(result[inheritedSubject], user.Subject)
			}
		}
	}
	return result
}

func groupParentSubjects(groups []provider.Group) map[string]string {
	result := map[string]string{}
	for _, group := range groups {
		subject := strings.TrimSpace(group.Subject)
		parent := strings.TrimSpace(group.ParentSubject)
		if subject == "" || parent == "" || subject == parent {
			continue
		}
		result[subject] = parent
	}
	return result
}

func inheritedDepartmentSubjects(subject string, parentByGroup map[string]string) []string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil
	}
	var result []string
	seen := map[string]bool{}
	for subject != "" && !seen[subject] {
		seen[subject] = true
		result = append(result, subject)
		subject = strings.TrimSpace(parentByGroup[subject])
	}
	return result
}

func duplicateUserNameCounts(users []provider.User, cfg config.BackendConfig) map[string]int {
	counts := map[string]int{}
	for _, user := range users {
		key := userNameKey(user.DisplayName, cfg)
		if key == "" {
			continue
		}
		counts[key]++
	}
	return counts
}

func userNameKey(displayName string, cfg config.BackendConfig) string {
	username, err := identity.GenerateRequiredSequentialReadableUsername(displayName, cfg.UsernameReadableDelimiter, 1, 32)
	if err != nil {
		return ""
	}
	return identity.Normalize(username)
}

func duplicateGroupNameCounts(groups []provider.Group) map[string]int {
	nameCounts := map[string]int{}
	for _, group := range groups {
		name := groupNameKey(group.Name)
		if name == "" {
			continue
		}
		nameCounts[name]++
	}
	return nameCounts
}

func duplicateGroupSubjects(groups []provider.Group) map[string]bool {
	nameCounts := duplicateGroupNameCounts(groups)
	result := map[string]bool{}
	for _, group := range groups {
		if nameCounts[groupNameKey(group.Name)] > 1 {
			result[group.Subject] = true
		}
	}
	return result
}

func disambiguateDuplicateGroupNames(groups []provider.Group) []provider.Group {
	nameCounts := duplicateGroupNameCounts(groups)
	result := make([]provider.Group, len(groups))
	copy(result, groups)
	for index, group := range result {
		name := groupNameKey(group.Name)
		if nameCounts[name] <= 1 {
			continue
		}
		path := strings.TrimSpace(group.Path)
		if path == "" {
			continue
		}
		result[index].Name = path
	}
	return result
}

func groupNameKey(name string) string {
	groupName, err := identity.SanitizeGroupName(name)
	if err != nil {
		return ""
	}
	return identity.Normalize(groupName)
}
