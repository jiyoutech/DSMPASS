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

// Plan against the complete source before assigning the first number. Previously
// synchronized subjects keep their names, even after departing the directory.
func (e *Engine) dingTalkNumberedNames(ctx context.Context, source string, users []provider.User, passwdPath string) (map[string]string, error) {
	counts := make(map[string]int)
	activeSubjects := make(map[string]bool, len(users))
	var active []provider.User
	for _, user := range users {
		subject := identity.Normalize(user.Subject)
		if _, seen := activeSubjects[subject]; subject == "" || seen || user.ProviderSlug != source {
			return nil, fmt.Errorf("钉钉通讯录用户标识为空、重复或来源不符")
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
SELECT e.subject_norm, COALESCE(e.display_name, ''),
 CASE WHEN a.provision_status='conflict' AND a.managed=1 AND a.conflict_reason=? THEN
   NOT EXISTS (SELECT 1 FROM dsm_mapping_entries m WHERE m.dsm_account_id=a.id AND m.mapping_type='user')
   AND NOT EXISTS (SELECT 1 FROM external_accounts x WHERE x.app_identity_id=a.app_identity_id AND x.id<>e.id)
 ELSE 0 END
FROM external_accounts e JOIN dsm_accounts a ON a.app_identity_id=e.app_identity_id
WHERE e.provider_slug=?`, identity.LegacyDingTalkDuplicateReason, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	existing := make(map[string]bool) // value indicates a recoverable legacy conflict
	for rows.Next() {
		var subject, name string
		var recoverable bool
		if err := rows.Scan(&subject, &name, &recoverable); err != nil {
			return nil, err
		}
		existing[subject] = recoverable
		if !activeSubjects[subject] {
			counts[userNameKey(name, e.cfg)]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var candidates []provider.User
	for _, user := range active {
		key := userNameKey(user.DisplayName, e.cfg)
		recoverable, found := existing[identity.Normalize(user.Subject)]
		if key != "" && !identity.IsReservedDSMUsername(key) && (recoverable || (!found && counts[key] > 1)) {
			candidates = append(candidates, user)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	occupied, err := e.occupiedDSMNames(ctx, passwdPath)
	if err != nil {
		return nil, err
	}
	for key := range counts {
		occupied[key] = true // A literal directory name such as "张三1" takes precedence.
	}
	slices.SortFunc(candidates, func(a, b provider.User) int {
		return strings.Compare(identity.Normalize(a.Subject), identity.Normalize(b.Subject))
	})
	numbers := make(map[string]int)
	result := make(map[string]string, len(candidates))
	for _, user := range candidates {
		key := userNameKey(user.DisplayName, e.cfg)
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
			result[identity.Normalize(user.Subject)] = name
			break
		}
	}
	return result, nil
}

func (e *Engine) occupiedDSMNames(ctx context.Context, passwdPath string) (map[string]bool, error) {
	// The SPK backend runs on the NAS. Read only login names from the local
	// account list, including accounts that have never appeared in DSMPASS.
	file, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("读取 DSM 已有登录名: %w", err)
	}
	defer file.Close()
	occupied := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("DSM 本地账号列表格式异常")
		}
		occupied[identity.Normalize(name)] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 DSM 已有登录名: %w", err)
	}

	rows, err := e.q.DBTX().QueryContext(ctx, "SELECT dsm_username_norm FROM dsm_accounts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		occupied[name] = true
	}
	return occupied, rows.Err()
}
