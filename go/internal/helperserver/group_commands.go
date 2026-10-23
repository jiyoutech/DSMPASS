package helperserver

import (
	"errors"
	"os"

	"github.com/dsmpass/dsmpass/go/internal/config"
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
		if err := requireManagedUser(cfg, username); err != nil {
			return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
		}
		if _, err := getSynoUser(cfg.SynoUserPath, username); err != nil {
			return errorResponse("SYNOUSER_MISSING", "DSM user is unavailable")
		}
	}
	response := map[string]any{"success": true, "created": false}
	err = withFileLock(cfg.ShadowLockPath, func() error {
		if username != "" {
			if err := requireManagedUser(cfg, username); err != nil {
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
			if err := requireManagedGroup(cfg, groupname); err != nil {
				return err
			}
		}
		switch action {
		case "scoped_provision_group":
			if exists {
				response["created"] = true
				return nil
			}
			if err := run(cfg.SynoGroupPath, "--add", groupname); err != nil {
				if isSynoNoSuchGroupError(err) {
					response["deferred"] = true
					response["warning"] = "DSM requires a first member to create this group"
					return nil
				}
				return err
			}
			if err := updateAccountPolicy(cfg, groupname, true, false); err != nil {
				return err
			}
			response["created"] = true
		case "scoped_add_group_member":
			if !exists {
				if err := run(cfg.SynoGroupPath, "--add", groupname, username); err != nil {
					return err
				}
				if err := updateAccountPolicy(cfg, groupname, true, false); err != nil {
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
			if err := run(cfg.SynoGroupPath, "--memberdel", groupname, username); err != nil {
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
