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

type directoryInventory struct {
	stamp    directoryStamp
	expiry   *time.Timer
	users    map[string]systemAccount
	profiles map[string]dsmUserProfile
}

// Native account and group files may also be changed outside the Helper.
type directoryStamp [3]os.FileInfo

func readDirectoryStamp(cfg config.HelperConfig) (directoryStamp, error) {
	var stamp directoryStamp
	for i, path := range []string{cfg.PasswdPath, cfg.GroupPath, cfg.ShadowPath} {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return stamp, err
		}
		stamp[i] = info
	}
	return stamp, nil
}
func (stamp directoryStamp) matches(other directoryStamp) bool {
	for i, info := range stamp {
		current := other[i]
		if info == nil && current == nil {
			continue
		}
		if info == nil || current == nil || !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
			return false
		}
	}
	return true
}
func readDirectoryInventory(ctx context.Context, cfg config.HelperConfig) (*directoryInventory, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var inventory directoryInventory
		err := withFileLockContext(ctx, cfg.ShadowLockPath, func() error {
			var err error
			inventory.stamp, err = readDirectoryStamp(cfg)
			if err != nil {
				return err
			}
			inventory.users, err = systemAccounts(cfg.PasswdPath, false)
			if err != nil {
				return err
			}
			_, err = systemAccounts(cfg.GroupPath, true)
			return err
		})
		if err != nil {
			return nil, err
		}
		inventory.profiles, err = completeDSMProfiles(ctx, cfg.SynoWebAPIPath, inventory.users)
		var current directoryStamp
		if checkErr := withFileLockContext(ctx, cfg.ShadowLockPath, func() error {
			var err error
			current, err = readDirectoryStamp(cfg)
			return err
		}); checkErr != nil {
			return nil, checkErr
		}
		if !inventory.stamp.matches(current) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &inventory, nil
	}
	return nil, errors.New("采集期间 DSM 账号目录已变化，请重试")
}

func (s *Server) captureDirectory(ctx context.Context, cfg config.HelperConfig, runID string) map[string]any {
	if runID == "" || cfg.SynoWebAPIPath == "" || cfg.AccountPolicyPath == "" {
		return errorResponse("DSM_SNAPSHOT_UNAVAILABLE", "DSM directory snapshot unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	inventory, err := readDirectoryInventory(ctx, cfg)
	if err != nil {
		return errorResponse("DSM_SNAPSHOT_FAILED", err.Error())
	}
	// Release normally stops this timer. A backend crash also frees the inventory.
	inventory.expiry = time.AfterFunc(time.Hour, func() { s.directories.CompareAndDelete(runID, inventory) })
	if _, loaded := s.directories.LoadOrStore(runID, inventory); loaded {
		inventory.expiry.Stop()
		return errorResponse("DSM_SNAPSHOT_FAILED", "duplicate directory capture")
	}
	return map[string]any{"success": true}
}

func (s *Server) releaseDirectory(runID string) {
	if old, ok := s.directories.LoadAndDelete(runID); ok {
		old.(*directoryInventory).expiry.Stop()
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
	var err error
	var inventory *directoryInventory
	if id, captured := payload["snapshot_id"]; captured {
		snapshotID, ok := id.(string)
		if !ok || snapshotID == "" || snapshotID != payload["request_id"] {
			return errorResponse("BAD_REQUEST", "directory snapshot ID mismatch")
		}
		value, ok := s.directories.Load(snapshotID)
		if ok {
			inventory = value.(*directoryInventory)
		}
	}
	if inventory == nil {
		// An older backend, an expired capture or a restarted Helper requires
		// a fresh complete read before reporting any matches.
		inventory, err = readDirectoryInventory(ctx, cfg)
		if err != nil {
			return errorResponse("DSM_SNAPSHOT_FAILED", err.Error())
		}
	}
	states := make([]byte, len(names))
	err = withFileLockContext(ctx, cfg.ShadowLockPath, func() error {
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
		current, err := readDirectoryStamp(cfg)
		if err != nil {
			return err
		}
		sameGeneration := inventory.stamp.matches(current)
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
				captured, existed := inventory.users[name]
				if found != existed || (found && captured.id != user.id) {
					continue
				}
				if !found {
					states[i] = 'm'
					continue
				}
				profile, visible := inventory.profiles[name]
				if !sameGeneration || !visible || !profile.matches(user, rows[i].(map[string]any)) {
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
	if _, pending := policy.SyncDisables[name]; pending {
		return false
	}
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
