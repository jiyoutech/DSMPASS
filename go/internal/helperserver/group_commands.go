package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) mutateGroup(cfg config.HelperConfig, action string, payload map[string]any) map[string]any {
	groupname, err := requiredString(payload, "dsm_groupname")
	if err != nil {
		return errorResponse("BAD_REQUEST", err.Error())
	}
	if err := assertAllowedGroup(groupname); err != nil {
		return errorResponse("GROUPNAME_NOT_ALLOWED", err.Error())
	}
	username := ""
	if action != "scoped_provision_group" {
		username, err = requiredString(payload, "dsm_username")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := assertAllowed(cfg, username); err != nil {
			return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
		}
		if err := s.requireMemberEnrollment(cfg, action, username, groupname); err != nil {
			return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
		}
		if _, err := getSynoUser(cfg.SynoUserPath, username); err != nil {
			return errorResponse("SYNOUSER_MISSING", "DSM user is unavailable")
		}
	}
	target := creationTarget{cfg: cfg, name: groupname, group: true}
	response := map[string]any{"success": true, "created": false}
	err = withFileLock(cfg.ShadowLockPath, func() error {
		if username != "" {
			if err := s.requireMemberEnrollment(cfg, action, username, groupname); err != nil {
				return err
			}
		}
		exists := false
		if cfg.AccountPolicyPath != "" || cfg.Privileged {
			_, err := normalGroup(cfg, groupname)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			exists = err == nil
		} else {
			exists = run(cfg.SynoGroupPath, "--get", groupname) == nil
		}
		if exists {
			if action != "scoped_remove_group_member" {
				if err := target.resume(); err != nil {
					return err
				}
			}
			var mapped func() (bool, error)
			if action == "scoped_provision_group" {
				mapped = func() (bool, error) {
					return s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "directory_group", Groupname: groupname})
				}
			}
			if err := checkGroupEnrollment(cfg, groupname, mapped); err != nil {
				return err
			}
		}
		switch action {
		case "scoped_provision_group":
			if exists {
				response["created"] = true
				return nil
			}
			if err := target.begin(); err != nil {
				return err
			}
			if err := run(cfg.SynoGroupPath, "--add", groupname); err != nil {
				if isSynoNoSuchGroupError(err) {
					response["deferred"] = true
					response["warning"] = "DSM requires a first member to create this group"
					return nil
				}
				return err
			}
			if err := target.confirm(); err != nil {
				return err
			}
			response["created"] = true
		case "scoped_add_group_member":
			if !exists {
				grant, err := userEnrollment(cfg, username)
				if err != nil {
					return err
				}
				if grant != nil {
					return fmt.Errorf("无法为当前用户创建 DSM 群组 %q", groupname)
				}
				if err := target.begin(); err != nil {
					return err
				}
				if err := run(cfg.SynoGroupPath, "--add", groupname, username); err != nil {
					return err
				}
				if err := target.confirm(); err != nil {
					return err
				}
			} else if err := run(cfg.SynoGroupPath, "--memberadd", groupname, username); err != nil && !isSynoGroupMemberPresent(err, groupname, username) {
				return err
			}
			response["created"] = true
		case "scoped_remove_group_member":
			response["removed"] = false
			if !exists {
				return nil
			}
			if err := removeNativeGroupMember(cfg, groupname, username); err != nil {
				return err
			}
			response["removed"] = true
		default:
			return errors.New("unsupported group operation")
		}
		return nil
	})
	if err != nil {
		return errorResponse("SYNOGROUP_FAILED", err.Error())
	}
	return response
}

// A directory-only account may join its bound DingTalk departments or use
// individual membership grants recorded by the installer.
func (s *Server) requireMemberEnrollment(cfg config.HelperConfig, action, username, groupname string) error {
	grant, err := userEnrollment(cfg, username)
	if err != nil || grant == nil {
		return err
	}
	group, err := normalGroup(cfg, groupname)
	if err != nil {
		return err
	}
	if grant.DingTalk != nil && action == "scoped_add_group_member" {
		if !isLocalDirectoryGroup(groupname, group.id) {
			return errors.New("仅可同步普通 DSM 部门群组")
		}
		if err := requireManagedGroup(cfg, groupname); err != nil {
			return err
		}
		mapped, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "dingtalk_member", Username: username, Groupname: groupname, SourceSlug: grant.DingTalk.SourceSlug, Subject: grant.DingTalk.Subject})
		if err != nil {
			return err
		}
		if mapped {
			return nil
		}
		// Preserve an independently pinned membership supplied by another provider.
		if grant.Groups[groupname] == group.id {
			ok, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "other_directory_member", Username: username, Groupname: groupname})
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
		return errors.New("未找到与已登记钉钉用户一致的有效部门成员关系")
	}
	if gid, allowed := grant.Groups[groupname]; !allowed || gid != group.id || !isLocalDirectoryGroup(groupname, group.id) {
		return fmt.Errorf("DSM 用户 %q 的通讯录同步授权未包含当前群组 %q", username, groupname)
	}
	if action == "scoped_add_group_member" || action == "scoped_remove_group_member" {
		mapped, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "directory_member", Username: username, Groupname: groupname})
		if err != nil {
			return err
		}
		if mapped != (action == "scoped_add_group_member") {
			return errors.New("当前通讯录成员关系与请求不符")
		}
	}
	return nil
}

// DSM synogroup has no --memberdel. Use the native single-member API instead
// of reading and replacing the whole group membership list in this process.
func removeNativeGroupMember(cfg config.HelperConfig, groupname, username string) error {
	if cfg.SynoWebAPIPath == "" {
		return errors.New("DSM group member API command is not configured")
	}
	groupJSON, err := json.Marshal(groupname)
	if err != nil {
		return err
	}
	memberJSON, err := json.Marshal([]string{username})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, cfg.SynoWebAPIPath, "--exec", "api=SYNO.Core.Group.Member", "method=remove", "version=1", "group="+string(groupJSON), "name="+string(memberJSON)).Output()
	if err != nil {
		return fmt.Errorf("DSM group member removal command failed: %w", err)
	}
	var response struct {
		Success bool `json:"success"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return errors.New("DSM group member API returned invalid JSON")
	}
	if !response.Success {
		return fmt.Errorf("DSM group member API rejected removal (code %d)", response.Error.Code)
	}
	return nil
}
