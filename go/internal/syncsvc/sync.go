package syncsvc

import (
	"context"
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
	cfg config.BackendConfig
	q   *db.Queries
}

func NewEngine(cfg config.BackendConfig, q *db.Queries) *Engine {
	return &Engine{cfg: cfg, q: q}
}

func (e *Engine) SyncProvider(ctx context.Context, directory provider.Directory) (Result, error) {
	identityService := identity.NewService(e.cfg, e.q)
	result := Result{ProviderSlug: directory.Slug()}
	users, err := directory.ListUsers()
	if err != nil {
		return result, err
	}
	duplicateUserNames := duplicateUserNameCounts(users, e.cfg)
	for _, user := range users {
		verified := true
		external, err := identityService.UpsertProfile(ctx, identity.ExternalProfile{
			ProviderSlug:  user.ProviderSlug,
			Subject:       user.Subject,
			SubjectType:   "directory_subject",
			DisplayName:   user.DisplayName,
			Email:         user.Email,
			EmailVerified: &verified,
			Mobile:        user.Mobile,
		})
		if err != nil {
			return result, err
		}
		appIdentity, err := identityService.ResolveOrCreateIdentity(ctx, external)
		if err != nil {
			return result, err
		}
		account, accountCreated, err := identityService.EnsureDSMAccountWithCreated(ctx, appIdentity)
		if err != nil {
			return result, err
		}
		if accountCreated && duplicateUserNames[userNameKey(user.DisplayName, e.cfg)] > 1 && account.Managed == 1 {
			account, err = identityService.MarkDSMAccountConflict(ctx, account.ID, "冲突类型：飞书通讯录内用户姓名重名。请根据邮箱、手机号、身份 ID 和部门手动指定最终 DSM 用户名")
			if err != nil {
				return result, err
			}
		}
		action := "update_external_account"
		if account.ProvisionStatus == "pending" {
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
	}
	groups, err := directory.ListGroups()
	if err != nil {
		return result, err
	}
	duplicateGroupSubjects := duplicateGroupSubjects(groups)
	groups = disambiguateDuplicateGroupNames(groups)
	for _, group := range groups {
		providerGroup, err := identityService.EnsureProviderGroup(ctx, group.ProviderSlug, group.Subject, group.ParentSubject, group.Name, group.Path)
		if err != nil {
			return result, err
		}
		dsmGroup, err := identityService.EnsureDSMGroup(ctx, providerGroup)
		if err != nil {
			return result, err
		}
		if duplicateGroupSubjects[group.Subject] && dsmGroup.Managed == 1 {
			dsmGroup, err = identityService.MarkDSMGroupConflict(ctx, dsmGroup.ID, "飞书部门名重名，请管理员根据飞书部门路径手动指定 DSM 部门组名")
			if err != nil {
				return result, err
			}
		}
		if err := identityService.EnsureGroupLink(ctx, providerGroup.ID, dsmGroup.ID); err != nil {
			return result, err
		}
		action := "update_provider_group"
		if dsmGroup.ProvisionStatus == "pending" {
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
	}
	groupMap, err := identityService.ProviderGroupsToDSMGroups(ctx, directory.Slug())
	if err != nil {
		return result, err
	}
	accountMap, err := identityService.ExternalToDSMAccounts(ctx, directory.Slug())
	if err != nil {
		return result, err
	}
	membersByGroup := usersDepartmentMemberships(users)
	for _, group := range groups {
		dsmGroup, ok := groupMap[group.Subject]
		if !ok {
			continue
		}
		members := membersByGroup[group.Subject]
		if len(membersByGroup) == 0 {
			var err error
			members, err = directory.ListGroupMembers(group.Subject)
			if err != nil {
				return result, err
			}
		}
		for _, memberSubject := range members {
			account, ok := accountMap[memberSubject]
			if !ok {
				continue
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
		}
	}
	return result, nil
}

func usersDepartmentMemberships(users []provider.User) map[string][]string {
	result := map[string][]string{}
	for _, user := range users {
		if len(user.DepartmentSubjects) == 0 {
			continue
		}
		for _, departmentSubject := range user.DepartmentSubjects {
			if departmentSubject == "" {
				continue
			}
			result[departmentSubject] = append(result[departmentSubject], user.Subject)
		}
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
