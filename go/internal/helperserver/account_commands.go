package helperserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) provisionAccount(ctx context.Context, cfg config.HelperConfig, payload map[string]any) map[string]any {
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
	target := creationTarget{cfg: cfg, name: username}
	created := false
	initialPasswordApplied := false
	err = withAccountMutation(cfg, username, false, func() error {
		displayName, _ := optionalString(payload, "display_name")
		email, _ := optionalString(payload, "email")
		info, lookupErr := getSynoUser(cfg.SynoUserPath, username)
		if lookupErr == nil {
			if err := target.resume(); err != nil {
				return err
			}
			grant, err := userEnrollment(cfg, username)
			if (grant != nil || errors.Is(err, errUserNotEnrolled)) && !info.Expired && info.Mail != "" {
				linked, linkErr := s.linkVerifiedDirectoryUser(cfg, username, info.Mail, grant, db.HelperAuthorizationQuery{Action: "verify_existing_owner", Username: username})
				if linkErr != nil {
					return linkErr
				}
				if linked {
					return nil
				}
			}
			if errors.Is(err, errUserNotEnrolled) && !info.Expired {
				grant, err = s.linkDingTalkDirectoryUser(cfg, username)
			}
			if err != nil {
				return err
			}
			if grant != nil {
				if info.Expired {
					return fmt.Errorf("DSM 用户 %q 已停用", username)
				}
				return nil
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
		if !dsmUserNotFound(lookupErr) {
			return fmt.Errorf("无法确认 DSM 用户 %q 是否存在: %w", username, lookupErr)
		}
		if err := verifyAccountAbsent(cfg, username); err != nil {
			return err
		}
		password, _ := optionalString(payload, "initial_password")
		suppliedPassword := password != ""
		if password == "" {
			password = randomPassword(cfg.InitialPasswordLength)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := target.begin(); err != nil {
			return err
		}
		user := newDSMUser{name: username, display: displayName, email: email}
		err := createNativeUser(cfg, user, password)
		if err := s.retryAbsentCreate(ctx, cfg, user, password, err); err != nil {
			return err
		}
		// confirm reads the actual local UID and checks privileged group membership.
		// Setups without a policy file still need the native existence check.
		if cfg.AccountPolicyPath == "" && !cfg.Privileged {
			if _, err := getSynoUser(cfg.SynoUserPath, username); err != nil {
				return fmt.Errorf("DSM 用户创建命令已返回成功，但随后无法查询到该用户: %w", err)
			}
		}
		if err := target.confirm(); err != nil {
			return err
		}
		created = true
		// An unresolved permanent reset still needs its normal coordinated repair.
		// Only acknowledge a supplied password after native creation and UID enrollment.
		initialPasswordApplied = suppliedPassword && cfg.AccountPolicyPath != "" && cfg.JournalDir != "" && checkPasswordResetPending(cfg, username) == nil
		return nil
	})
	if err != nil {
		return errorResponse("SYNOUSER_FAILED", err.Error())
	}
	return map[string]any{"success": true, "created": created, "initial_password_applied": initialPasswordApplied}
}

func (s *Server) disableAccount(cfg config.HelperConfig, payload map[string]any) map[string]any {
	username, err := requiredString(payload, "dsm_username")
	if err != nil {
		return errorResponse("BAD_REQUEST", err.Error())
	}
	if err := assertAllowed(cfg, username); err != nil {
		return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
	}
	dingTalk := payload["action"] == "scoped_disable_dingtalk_user"
	authorize := func() error {
		if !dingTalk {
			if err := requireManagedUser(cfg, username); err != nil {
				return err
			}
			return s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "mapped", Username: username})
		}
		source, _ := payload["source_slug"].(string)
		subject, _ := payload["subject"].(string)
		accountID, _ := payload["account_id"].(string)
		runID, _ := payload["run_id"].(string)
		if source == "" || subject == "" || accountID == "" || runID == "" {
			return errors.New("钉钉停用请求缺少身份或同步记录")
		}
		grant, err := userEnrollment(cfg, username)
		if err != nil {
			return err
		}
		if grant != nil && (grant.DingTalk == nil || grant.DingTalk.SourceSlug != source || grant.DingTalk.Subject != subject) {
			return errors.New("DSM 用户缺少对应的钉钉身份绑定")
		}
		return s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "dingtalk_offboard", SourceSlug: source, Subject: subject, AccountID: accountID, Username: username, RunID: runID})
	}
	if err := authorize(); err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	disabled := false
	err = withAccountMutation(cfg, username, true, func() error {
		if err := authorize(); err != nil {
			return err
		}
		info, err := getSynoUser(cfg.SynoUserPath, username)
		if err != nil {
			return err
		}
		if !info.Expired {
			if err := modifySynoUser(cfg.SynoUserPath, username, info.FullName, true, info.Mail); err != nil {
				return err
			}
			if dingTalk {
				verified, err := getSynoUser(cfg.SynoUserPath, username)
				if err != nil {
					return fmt.Errorf("读取停用后的 DSM 账号状态: %w", err)
				}
				if !verified.Expired {
					return errors.New("DSM 未确认账号已停用")
				}
			}
		}
		disabled = true
		return nil
	})
	if err != nil {
		return errorResponse("SYNOUSER_FAILED", err.Error())
	}
	return map[string]any{"success": true, "disabled": disabled}
}
