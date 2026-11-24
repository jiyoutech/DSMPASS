package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

func (s *Server) addGroupMembers(cfg config.HelperConfig, payload map[string]any) map[string]any {
	group, err := requiredString(payload, "dsm_groupname")
	if err == nil {
		err = assertAllowedGroup(group)
	}
	if err != nil {
		return errorResponse("BAD_REQUEST", err.Error())
	}
	raw, ok := payload["dsm_usernames"].([]any)
	if !ok || len(raw) == 0 || len(raw) > helperclient.GroupMemberBatchSize {
		return errorResponse("BAD_REQUEST", "invalid group member batch size")
	}
	users := make([]string, 0, len(raw))
	for _, value := range raw {
		name, ok := value.(string)
		if !ok || assertAllowed(cfg, name) != nil || slices.Contains(users, name) {
			return errorResponse("BAD_REQUEST", "invalid or duplicate DSM username")
		}
		users = append(users, name)
	}
	if cfg.AccountPolicyPath == "" || cfg.GroupPath == "" {
		return errorResponse("GROUP_BATCH_UNSUPPORTED", "DSM group membership readback is unavailable")
	}
	confirmed := []string{}
	err = withFileLock(cfg.ShadowLockPath, func() error {
		var err error
		confirmed, err = s.applyGroupMembers(cfg, group, users)
		return err
	})
	if errors.Is(err, helperclient.ErrGroupBatchUnsupported) {
		return errorResponse("GROUP_BATCH_UNSUPPORTED", err.Error())
	}
	response := map[string]any{"success": true, "confirmed": append([]string{}, confirmed...)}
	if err != nil {
		response["batch_error"] = err.Error()
	}
	return response
}

// Caller holds the existing DSM writer lock. Membership snapshots are scoped to this batch.
func (s *Server) applyGroupMembers(cfg config.HelperConfig, group string, users []string) ([]string, error) {
	before, lookupErr := normalGroup(cfg, group)
	// normalGroup returns bare ErrNotExist for a missing group; a failure to open
	// the system account database is a PathError and must never initiate creation.
	creating := lookupErr == os.ErrNotExist
	if lookupErr != nil && !creating {
		return nil, lookupErr
	}
	target := creationTarget{cfg: cfg, name: group, group: true}
	if !creating {
		if err := target.resume(); err != nil {
			return nil, err
		}
		if err := requireManagedGroup(cfg, group); err != nil {
			return nil, err
		}
	}
	localUsers, err := systemAccounts(cfg.PasswdPath, false)
	if err != nil {
		return nil, err
	}
	localGroups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return nil, err
	}
	policy, err := readAccountPolicy(cfg)
	if err != nil {
		return nil, err
	}
	var scopes []db.HelperMemberScope
	newPins := false
	for _, name := range users {
		grant, err := enrolledLocalUser(policy, name, localUsers, localGroups)
		if err != nil {
			return nil, err
		}
		if grant == nil {
			continue
		}
		if creating {
			return nil, helperclient.ErrGroupBatchUnsupported
		}
		pinned := grant.Groups[group] == before.id
		if !pinned && grant.DingTalk == nil {
			if err := s.pinMatchedMembership(cfg, &policy, name, before); err != nil {
				return nil, err
			}
			newPins = true
			pinned = true
		}
		if !isLocalDirectoryGroup(group, before.id) || (!pinned && grant.DingTalk == nil) {
			return nil, errors.New("通讯录成员关系与当前 DSM 群组不符")
		}
		scopes = append(scopes, db.HelperMemberScope{Username: name, DingTalk: grant.DingTalk, OtherGroup: pinned})
	}
	if len(scopes) != 0 {
		if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "directory_member_batch", Groupname: group, Members: scopes}); err != nil {
			return nil, err
		}
	}
	if newPins {
		if err := saveAccountPolicy(cfg, policy); err != nil {
			return nil, err
		}
	}
	if !creating {
		// DSM administrators can change the group while mappings are being verified.
		current, err := normalGroup(cfg, group)
		if err != nil {
			return nil, err
		}
		if current.id != before.id {
			return nil, errors.New("DSM group GID changed during membership validation")
		}
		before = current
	}
	var missing []string
	for _, name := range users {
		if !slices.Contains(before.members, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return users, nil
	}
	if creating {
		if err := target.begin(); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := runAccountCommand(ctx, cfg.SynoGroupPath, append([]string{"--add", group}, missing...)...); err != nil {
			return nil, err
		}
		if err := target.confirm(); err != nil {
			return nil, err
		}
	} else {
		err = appendNativeGroupMembers(cfg, group, missing)
		if errors.Is(err, helperclient.ErrGroupBatchUnsupported) {
			return nil, err
		}
	}
	after, readErr := normalGroup(cfg, group)
	if readErr != nil {
		return nil, errors.Join(err, readErr)
	}
	if !creating && before.id != after.id {
		return nil, errors.New("DSM group GID changed during membership update")
	}
	if enrollmentErr := requireManagedGroup(cfg, group); enrollmentErr != nil {
		return nil, errors.Join(err, enrollmentErr)
	}
	var confirmed []string
	for _, name := range users {
		if slices.Contains(after.members, name) {
			confirmed = append(confirmed, name)
		}
	}
	if len(confirmed) != len(users) {
		err = errors.Join(err, fmt.Errorf("DSM confirmed %d of %d group members", len(confirmed), len(users)))
	}
	return confirmed, err
}

func appendNativeGroupMembers(cfg config.HelperConfig, group string, names []string) error {
	if cfg.SynoWebAPIPath == "" {
		return helperclient.ErrGroupBatchUnsupported
	}
	groupArg, _ := json.Marshal(group)
	membersArg, _ := json.Marshal(names)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.SynoWebAPIPath, "--exec", "api=SYNO.Core.Group.Member", "version=1", "method=change", "group="+string(groupArg), "add_member="+string(membersArg), "remove_member=[]")
	cmd.WaitDelay = time.Second
	data, commandErr := cmd.Output()
	if ctx.Err() != nil {
		return fmt.Errorf("DSM group change timed out: %w", ctx.Err())
	}
	if errors.Is(commandErr, os.ErrNotExist) {
		return helperclient.ErrGroupBatchUnsupported
	}
	var result struct {
		Success *bool `json:"success"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &result) != nil || result.Success == nil {
		return errors.Join(commandErr, errors.New("invalid DSM group change response"))
	}
	if !*result.Success {
		switch result.Error.Code {
		case 102, 103, 104: // DSM API, method, or version is unavailable.
			return helperclient.ErrGroupBatchUnsupported
		}
		return fmt.Errorf("DSM group change rejected (code %d)", result.Error.Code)
	}
	return commandErr
}
