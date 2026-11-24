package helperserver

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

var errAccountDisabled = errors.New("DSM 账号已停用，需核实后恢复")

// An unambiguous directory account can be linked read-only. No password, local
// group or credential owner is granted by the package's choice record.
// The caller holds the account and policy write locks.
func (s *Server) recordDirectoryMatch(cfg config.HelperConfig, name string) (bool, error) {
	user, err := normalUser(cfg, name)
	if err != nil {
		return false, err
	}
	matched, err := s.mappingAllowed(cfg, db.HelperAuthorizationQuery{Action: "directory_account_match", Username: name, LocalUID: user.id})
	if err != nil || !matched {
		return false, err
	}
	groups, err := systemAccounts(cfg.GroupPath, true)
	if err != nil {
		return false, err
	}
	if !ordinaryInstallUser(user, groups) {
		return false, errors.New("仅普通 DSM 本地账号可选择归属")
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return false, err
	}
	if candidate, ok := p.CredentialCandidates[name]; ok && candidate.UID != user.id {
		return false, errors.New("DSM 用户的原始 UID 已变化")
	}
	if scope := p.DingTalkScope; scope != nil {
		if uid, ok := scope.Users[name]; ok && uid != user.id {
			return false, errors.New("DSM 用户的原始 UID 已变化")
		}
	}
	if p.DirectoryUsers == nil {
		p.DirectoryUsers = make(map[string]directoryUserGrant)
	}
	p.DirectoryUsers[name] = directoryUserGrant{UID: user.id}
	return true, saveAccountPolicy(cfg, p)
}

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
			if restored, err := s.reconcileSyncDisable(cfg, username, info); err != nil || restored {
				return err
			}
			grant, err := userEnrollment(cfg, username)
			if (grant != nil || errors.Is(err, errUserNotEnrolled)) && !info.Expired {
				linked, linkErr := s.linkExistingDirectoryUser(cfg, db.HelperAuthorizationQuery{Action: "provision", Username: username}, grant, &info)
				if linkErr != nil {
					return linkErr
				}
				if linked {
					return nil
				}
			}
			if errors.Is(err, errUserNotEnrolled) && info.ExpiryKnown && !info.Expired {
				linked, linkErr := s.recordDirectoryMatch(cfg, username)
				if linkErr != nil || linked {
					return linkErr
				}
			}
			if errors.Is(err, errUserNotEnrolled) && !info.Expired {
				grant, err = s.linkDingTalkDirectoryUser(cfg, username)
			}
			if err != nil {
				return err
			}
			if grant != nil {
				return nil
			}
			if displayName == "" {
				displayName = info.FullName
			}
			if email == "" {
				email = info.Mail
			}
			if displayName != info.FullName || email != info.Mail {
				// Keep the native profile of an existing directory-owned account on retries.
				if cfg.AccountPolicyPath != "" {
					p, err := readAccountPolicy(cfg)
					if err != nil {
						return err
					}
					if owner, ok := p.CredentialOwners[username]; ok {
						binding, err := s.dingTalkLoginBinding(cfg, username, p.Users[username])
						if err != nil {
							return err
						}
						if binding != nil && binding.SourceSlug == owner.SourceSlug && binding.Subject == owner.Subject {
							return nil
						}
					}
				}
				if !info.ExpiryKnown {
					return errors.New("无法确认 DSM 账号启用状态，资料更新已暂停")
				}
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
	if errors.Is(err, errAccountDisabled) {
		return errorResponse("DSM_ACCOUNT_DISABLED", err.Error())
	}
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
	scoped := dingTalk || payload["action"] == "scoped_disable_missing_user"
	outcome := "disabled"
	authorize := func() error {
		outcome = "disabled"
		if !scoped {
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
		request := db.HelperAuthorizationQuery{Action: "dingtalk_offboard", SourceSlug: source, Subject: subject, AccountID: accountID, Username: username, RunID: runID}
		grant, err := userEnrollment(cfg, username)
		if !dingTalk {
			request.Action = "disable_missing_user"
		}
		if errors.Is(err, os.ErrNotExist) {
			outcome = "absent"
			if dingTalk {
				request.Action = "dingtalk_offboard_absent"
			} else {
				request.Action = "disable_missing_absent"
			}
			return s.authorizeAccount(cfg, request)
		}
		if err != nil {
			return err
		}
		if !dingTalk && grant != nil {
			outcome = "membership_only"
			return s.authorizeAccount(cfg, request)
		}
		if grant != nil {
			if grant.DingTalk == nil || grant.DingTalk.SourceSlug != source || grant.DingTalk.Subject != subject {
				return errors.New("DSM 用户缺少对应的钉钉身份绑定")
			}
			request.CredentialOwner = &db.CredentialIdentity{Username: username, SourceSlug: source, Subject: subject}
		}
		return s.authorizeAccount(cfg, request)
	}
	if err := authorize(); err != nil {
		return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
	}
	expected := outcome
	disabled, absent := false, false
	err = withAccountMutation(cfg, username, expected == "disabled", func() error {
		if err := authorize(); err != nil {
			return err
		}
		if outcome != expected {
			return errors.New("DSM 账号归属已变化，请重试")
		}
		if outcome == "membership_only" {
			return nil
		}
		info, err := getSynoUser(cfg.SynoUserPath, username)
		if outcome == "absent" {
			if !dsmUserNotFound(err) {
				return errors.New("DSM 未确认账号不存在")
			}
			if err := verifyAccountAbsent(cfg, username); err != nil {
				return err
			}
			if _, found, err := (creationTarget{cfg: cfg, name: username}).receiptID(); err != nil || found {
				return errors.Join(errors.New("DSM 账号创建回执待核实"), err)
			}
			absent = true
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Expired {
			if err := modifySynoUser(cfg.SynoUserPath, username, info.FullName, true, info.Mail); err != nil {
				return err
			}
			if scoped {
				verified, err := getSynoUser(cfg.SynoUserPath, username)
				if err != nil {
					return fmt.Errorf("读取停用后的 DSM 账号状态: %w", err)
				}
				if !verified.ExpiryKnown || !verified.Expired {
					return errors.New("DSM 未确认账号已停用")
				}
				if info.ExpiryKnown && cfg.AccountPolicyPath != "" {
					user, err := normalUser(cfg, username)
					if err != nil {
						return err
					}
					p, err := readAccountPolicy(cfg)
					if err != nil {
						return err
					}
					if p.SyncDisables == nil {
						p.SyncDisables = make(map[string]syncDisableReceipt)
					}
					p.SyncDisables[username] = syncDisableReceipt{UID: user.id, Source: payload["source_slug"].(string), Subject: payload["subject"].(string), AccountID: payload["account_id"].(string), RunID: payload["run_id"].(string)}
					disabled = true
					return saveAccountPolicy(cfg, p)
				}
			}
		}
		disabled = true
		return nil
	})
	if err != nil {
		return errorResponse("SYNOUSER_FAILED", err.Error())
	}
	return map[string]any{"success": true, "disabled": disabled, "absent": absent, "membership_only": outcome == "membership_only"}
}
