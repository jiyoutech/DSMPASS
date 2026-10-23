package helperserver

import (
	"context"
	"fmt"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) provisionAccount(cfg config.HelperConfig, payload map[string]any) map[string]any {
	username, err := requiredString(payload, "dsm_username")
	if err != nil {
		return errorResponse("BAD_REQUEST", err.Error())
	}
	if err := assertAllowed(cfg, username); err != nil {
		return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
	}
	if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "provision", Username: username}); err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	created := false
	err = withAccountMutation(cfg, username, false, func() error {
		displayName, _ := optionalString(payload, "display_name")
		email, _ := optionalString(payload, "email")
		if info, err := getSynoUser(cfg.SynoUserPath, username); err == nil {
			if err := requireManagedUser(cfg, username); err != nil {
				return err
			}
			if displayName == "" {
				displayName = info.FullName
			}
			if email == "" {
				email = info.Mail
			}
			if info.Expired || displayName != info.FullName || email != info.Mail {
				return modifySynoUser(cfg.SynoUserPath, username, displayName, false, email)
			}
			return nil
		}
		if err := verifyAccountAbsent(cfg, username); err != nil {
			return err
		}
		password, _ := optionalString(payload, "initial_password")
		if password == "" {
			password = randomPassword(cfg.InitialPasswordLength)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := runAccountCommand(ctx, cfg.SynoUserPath, synouserAddArgs(username, password, displayName, email)...); err != nil {
			return err
		}
		if _, err := getSynoUser(cfg.SynoUserPath, username); err != nil {
			return fmt.Errorf("DSM 用户创建命令已返回成功，但随后无法查询到该用户: %w", err)
		}
		if err := updateAccountPolicy(cfg, username, false, false); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return errorResponse("SYNOUSER_FAILED", err.Error())
	}
	return map[string]any{"success": true, "created": created}
}

func (s *Server) disableAccount(cfg config.HelperConfig, payload map[string]any) map[string]any {
	username, err := requiredString(payload, "dsm_username")
	if err != nil {
		return errorResponse("BAD_REQUEST", err.Error())
	}
	if err := assertAllowed(cfg, username); err != nil {
		return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
	}
	if err := requireManagedUser(cfg, username); err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	if err := s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "mapped", Username: username}); err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	disabled := false
	err = withAccountMutation(cfg, username, true, func() error {
		if err := requireManagedUser(cfg, username); err != nil {
			return err
		}
		info, err := getSynoUser(cfg.SynoUserPath, username)
		if err != nil {
			return err
		}
		if err := modifySynoUser(cfg.SynoUserPath, username, info.FullName, true, info.Mail); err != nil {
			return err
		}
		disabled = true
		return nil
	})
	if err != nil {
		return errorResponse("SYNOUSER_FAILED", err.Error())
	}
	return map[string]any{"success": true, "disabled": disabled}
}
