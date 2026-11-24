package syncsvc

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/identity"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

type directoryName struct {
	username string
	choice   string
}

type nativeUser struct {
	name     string
	uid      int
	ordinary bool
}

func (u nativeUser) choiceReason() string {
	return fmt.Sprintf("%s%s（UID %d）", identity.OwnerChoicePrefix, u.name, u.uid)
}

// Plan against the complete source before assigning the first number. Previously
// synchronized subjects keep their names, even after departing the directory.
func (e *Engine) directoryNames(ctx context.Context, source, label string, users []provider.User, passwdPath string) (map[string]directoryName, error) {
	counts := make(map[string]int)
	activeSubjects := make(map[string]bool, len(users))
	var active []provider.User
	for _, user := range users {
		subject := identity.Normalize(user.Subject)
		if _, seen := activeSubjects[subject]; subject == "" || seen || user.ProviderSlug != source {
			return nil, fmt.Errorf("通讯录用户标识为空、重复或来源不符")
		}
		activeSubjects[subject] = user.Active
		if user.Active {
			counts[userNameKey(user.DisplayName, e.cfg)]++
			active = append(active, user)
		}
	}

	// A missing or inactive former employee can still own a NAS account.
	// Only the old automatic duplicate conflict is eligible for reassignment.
	rows, err := e.q.DBTX().QueryContext(ctx, `
SELECT e.subject_norm, COALESCE(e.display_name, ''), a.dsm_username_norm,
 CASE WHEN a.provision_status='conflict' AND a.managed=1 AND (a.conflict_reason IN (?,?) OR instr(a.conflict_reason,?)=1) THEN
   NOT EXISTS (SELECT 1 FROM dsm_mapping_entries m WHERE m.dsm_account_id=a.id AND m.mapping_type='user')
   AND NOT EXISTS (SELECT 1 FROM external_accounts x WHERE x.app_identity_id=a.app_identity_id AND x.id<>e.id)
 ELSE 0 END
FROM external_accounts e JOIN dsm_accounts a ON a.app_identity_id=e.app_identity_id
WHERE e.provider_slug=?`, identity.LegacyDuplicateReason(label), label+"用户姓名重名", identity.OwnerChoicePrefix, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	releasable := make(map[string]bool)
	existing := make(map[string]bool) // value indicates a recoverable legacy conflict
	for rows.Next() {
		var subject, name, accountName string
		var recoverable bool
		if err := rows.Scan(&subject, &name, &accountName, &recoverable); err != nil {
			return nil, err
		}
		existing[subject] = recoverable
		if recoverable && activeSubjects[subject] {
			releasable[accountName] = true
		}
		if !activeSubjects[subject] && !recoverable {
			counts[userNameKey(name, e.cfg)]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// An explicit selection belongs to one source subject. A namesake arriving
	// from another source must get a free name as well.
	pinned, err := e.q.DBTX().QueryContext(ctx, `SELECT a.dsm_username_norm FROM directory_owner_choices c
JOIN dsm_accounts a ON a.id=c.account_id AND a.dsm_username=c.username WHERE c.source_slug<>?`, source)
	if err != nil {
		return nil, err
	}
	for pinned.Next() {
		var key string
		if err := pinned.Scan(&key); err != nil {
			pinned.Close()
			return nil, err
		}
		counts[key]++
	}
	if err := pinned.Close(); err != nil {
		return nil, err
	}
	if err := pinned.Err(); err != nil {
		return nil, err
	}

	var candidates []provider.User
	for _, user := range active {
		key := userNameKey(user.DisplayName, e.cfg)
		recoverable, found := existing[identity.Normalize(user.Subject)]
		if key != "" && !identity.IsReservedDSMUsername(key) && (recoverable || !found) {
			candidates = append(candidates, user)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	native, err := nativeDirectoryUsers(passwdPath, e.localGroup)
	if err != nil {
		return nil, err
	}
	claimed, err := e.claimedDSMNames(ctx, source)
	if err != nil {
		return nil, err
	}
	occupied := make(map[string]bool)
	for key := range native {
		occupied[key] = true
	}
	for key := range claimed {
		occupied[key] = true
	}
	for key := range counts {
		occupied[key] = true // A literal directory name such as "张三1" takes precedence.
	}
	slices.SortFunc(candidates, func(a, b provider.User) int {
		return strings.Compare(identity.Normalize(a.Subject), identity.Normalize(b.Subject))
	})
	numbers := make(map[string]int)
	result := make(map[string]directoryName, len(candidates))
	for _, user := range candidates {
		key := userNameKey(user.DisplayName, e.cfg)
		otherSource, occupiedBase := claimed[key]
		availableBase := !occupiedBase || releasable[key]
		local, foundNative := native[key]
		subject := identity.Normalize(user.Subject)
		if counts[key] == 1 && !existing[subject] && ((!foundNative && !occupiedBase) || (otherSource && (!foundNative || local.ordinary))) {
			// Preserve the identity resolver's existing cross-source linking rules.
			continue
		}
		if counts[key] == 1 && availableBase && (!foundNative || local.ordinary) {
			base, err := identity.SanitizeRequiredNameBase(user.DisplayName, identity.DSMUsernameMaxLength)
			if err != nil {
				return nil, err
			}
			if foundNative {
				base = local.name
			}
			result[subject] = directoryName{username: base}
			continue
		}
		if availableBase && foundNative && local.ordinary {
			result[subject] = directoryName{choice: local.choiceReason()}
			continue
		}
		for {
			numbers[key]++
			suffix := strconv.Itoa(numbers[key])
			base, err := identity.SanitizeRequiredNameBase(user.DisplayName, identity.DSMUsernameMaxLength-len(suffix))
			if err != nil {
				return nil, err
			}
			name := base + suffix
			norm := identity.Normalize(name)
			if occupied[norm] {
				continue
			}
			occupied[norm] = true
			result[subject] = directoryName{username: name}
			break
		}
	}
	return result, nil
}

func nativeDirectoryUsers(passwdPath, groupPath string) (map[string]nativeUser, error) {
	// The SPK backend runs on the NAS. Read only login names from the local
	// account list, including accounts that have never appeared in DSMPASS.
	file, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("读取 DSM 已有登录名: %w", err)
	}
	defer file.Close()
	groups, err := nativeDirectoryGroups(groupPath)
	if err != nil {
		return nil, err
	}
	native := make(map[string]nativeUser)
	uidCounts := make(map[int]int)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[0] == "" {
			return nil, fmt.Errorf("DSM 本地账号列表格式异常")
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("读取 DSM 用户 UID: %w", err)
		}
		key := identity.Normalize(fields[0])
		if _, exists := native[key]; exists {
			return nil, fmt.Errorf("DSM 本地用户名重复：%s", fields[0])
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return nil, fmt.Errorf("读取 DSM 用户 GID: %w", err)
		}
		uidCounts[uid]++
		native[key] = nativeUser{name: fields[0], uid: uid, ordinary: uid >= 1024 && uid < 65536 && gid == groups.usersGID && groups.hasAdmins && !groups.privilegedGIDs[gid] && !groups.privilegedMembers[key] && !identity.IsReservedDSMUsername(key) && key != "guest" && key != "nobody" && key != "dsmpass"}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 DSM 已有登录名: %w", err)
	}

	for key, user := range native {
		if uidCounts[user.uid] > 1 {
			user.ordinary = false
			native[key] = user
		}
	}
	return native, nil
}

type nativeGroupScope struct {
	usersGID          int
	hasAdmins         bool
	privilegedMembers map[string]bool
	privilegedGIDs    map[int]bool
}

func nativeDirectoryGroups(path string) (nativeGroupScope, error) {
	scope := nativeGroupScope{usersGID: -1, privilegedGIDs: map[int]bool{0: true}, privilegedMembers: map[string]bool{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return scope, fmt.Errorf("读取 DSM 本地组: %w", err)
	}
	members := map[int][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			return scope, fmt.Errorf("DSM 本地组列表格式异常")
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			return scope, err
		}
		members[gid] = append(members[gid], strings.Split(fields[3], ",")...)
		switch fields[0] {
		case "users":
			scope.usersGID = gid
		case "administrators":
			scope.hasAdmins = true
			scope.privilegedGIDs[gid] = true
		case "admin", "docker", "lxd", "incus-admin", "sudo", "wheel", "disk", "libvirt":
			scope.privilegedGIDs[gid] = true
		}
	}
	for gid := range scope.privilegedGIDs {
		for _, member := range members[gid] {
			scope.privilegedMembers[identity.Normalize(member)] = true
		}
	}
	return scope, nil
}

func (e *Engine) claimedDSMNames(ctx context.Context, source string) (map[string]bool, error) {
	occupied := make(map[string]bool)
	rows, err := e.q.DBTX().QueryContext(ctx, `SELECT a.dsm_username_norm, EXISTS (SELECT 1 FROM external_accounts e WHERE e.app_identity_id=a.app_identity_id AND e.provider_slug<>? AND e.active=1) AND NOT EXISTS (SELECT 1 FROM external_accounts e WHERE e.app_identity_id=a.app_identity_id AND e.provider_slug=?) FROM dsm_accounts a`, source, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var otherSource bool
		if err := rows.Scan(&name, &otherSource); err != nil {
			return nil, err
		}
		occupied[name] = otherSource
	}
	return occupied, rows.Err()
}
