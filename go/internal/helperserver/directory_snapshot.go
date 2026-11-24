package helperserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

// DSM lists visible local users. System and directory-name protections are
// checked independently before a create, including names absent from this list.
func completeDSMProfiles(ctx context.Context, path string, local map[string]systemAccount) (map[string]dsmUserProfile, error) {
	out := make(map[string]dsmUserProfile)
	total := -1
	for offset := 0; ; {
		var page dsmProfilePage
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			page, err = readDSMProfilePage(ctx, path, offset)
			if err == nil && page.Offset != nil && *page.Offset == offset && page.Total != nil &&
				*page.Total >= offset && *page.Total <= len(local) && (total == -1 || *page.Total == total) &&
				len(page.Users) <= helperclient.UserProvisionBatchSize && len(page.Users) <= *page.Total-offset &&
				(len(page.Users) > 0 || offset == *page.Total) {
				break
			}
			if err == nil {
				err = errors.New("invalid page offset, size or total")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("读取 DSM 用户列表 offset=%d: %w", offset, err)
		}
		total = *page.Total
		for _, p := range page.Users {
			account, exists := local[p.Name]
			if _, duplicate := out[p.Name]; p.Name == "" || duplicate || !exists || p.UID == nil || *p.UID != account.id {
				return nil, errors.New("DSM 用户分页重复或与本机 UID 不一致")
			}
			out[p.Name] = p
		}
		offset += len(page.Users)
		if offset == total {
			return out, nil
		}
	}
}

func (s *Server) directorySnapshot(ctx context.Context, cfg config.HelperConfig, payload map[string]any) map[string]any {
	rows, ok := payload["dsm_users"].([]any)
	if !ok || cfg.SynoWebAPIPath == "" || cfg.AccountPolicyPath == "" {
		return errorResponse("DSM_SNAPSHOT_UNAVAILABLE", "DSM directory snapshot unavailable")
	}
	names := make([]string, len(rows))
	seen := make(map[string]bool, len(rows))
	for i, raw := range rows {
		row, ok := raw.(map[string]any)
		name, err := requiredString(row, "dsm_username")
		_, hasDisplay := row["display_name"].(string)
		_, hasMail := row["email"].(string)
		if !ok || err != nil || seen[name] || !hasDisplay || !hasMail {
			return errorResponse("BAD_REQUEST", "invalid DSM snapshot target")
		}
		seen[name] = true
		names[i] = name
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	states := make([]byte, len(names))
	err := withFileLock(cfg.ShadowLockPath, func() error {
		local, err := systemAccounts(cfg.PasswdPath, false)
		if err != nil {
			return err
		}
		groups, err := systemAccounts(cfg.GroupPath, true)
		if err != nil {
			return err
		}
		policy, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		profiles, err := completeDSMProfiles(ctx, cfg.SynoWebAPIPath, local)
		if err != nil {
			return err
		}
		offset := 0
		for batch := range slices.Chunk(names, helperclient.UserProvisionBatchSize) {
			allowed, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "provision_users", Usernames: batch})
			if err != nil {
				return err
			}
			for j, name := range batch {
				i := offset + j
				states[i] = 'r'
				if !allowed || assertAllowed(cfg, name) != nil {
					continue
				}
				user, found := local[name]
				if !found {
					states[i] = 'm'
					continue
				}
				profile, visible := profiles[name]
				if !visible || !profile.matches(user, rows[i].(map[string]any)) {
					continue
				}
				if s.canConfirmDirectoryUser(cfg, policy, name, local, groups) {
					states[i] = 'u'
				}
			}
			offset += len(batch)
		}
		return nil
	})
	if err != nil {
		return errorResponse("DSM_SNAPSHOT_FAILED", err.Error())
	}
	return map[string]any{"success": true, "states": string(states)}
}

func (s *Server) canConfirmDirectoryUser(cfg config.HelperConfig, policy accountPolicy, name string, users, groups map[string]systemAccount) bool {
	if _, bound := policy.CredentialOwners[name]; bound {
		return false
	}
	grant, err := enrolledLocalUser(policy, name, users, groups)
	if err != nil || grant != nil {
		return false
	}
	if _, err := os.Lstat((creationTarget{cfg: cfg, name: name}).path()); !os.IsNotExist(err) {
		return false
	}
	_, busy, err := browserLeaseForUser(cfg, name)
	return err == nil && !busy
}
