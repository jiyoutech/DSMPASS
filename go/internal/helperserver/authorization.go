package helperserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func (s *Server) authorizeAccount(cfg config.HelperConfig, request db.HelperAuthorizationQuery) error {
	if request.Username != "" && cfg.AccountPolicyPath != "" {
		p, err := readAccountPolicy(cfg)
		if err != nil {
			return err
		}
		if owner, ok := p.CredentialOwners[request.Username]; ok {
			request.CredentialOwner = &owner
		}
	}
	allowed, err := s.mappingAllowed(cfg, request)
	if err != nil {
		return fmt.Errorf("verify DSM account authorization: %w", err)
	}
	if !allowed {
		return errors.New("DSM account is not authorized for this identity and operation")
	}
	return nil
}

func (s *Server) mappingAllowed(cfg config.HelperConfig, request db.HelperAuthorizationQuery) (bool, error) {
	if cfg.Privileged {
		request.DatabasePath = strings.TrimPrefix(cfg.DatabaseURL, "sqlite://")
		return queryAccountAsPackage(cfg, request)
	}
	return db.HelperAccountAllowed(context.Background(), s.store, request)
}

func (s *Server) authorizeLogin(cfg config.HelperConfig, payload map[string]any) error {
	username, err := requiredString(payload, "dsm_username")
	if err != nil {
		return err
	}
	identityID, err := requiredString(payload, "identity_id")
	if err != nil {
		return err
	}
	source, err := requiredString(payload, "login_source")
	if err != nil {
		return err
	}
	req := db.HelperAuthorizationQuery{Action: "login", Username: username, IdentityID: identityID, SourceSlug: source}
	denied := requireManagedUser(cfg, username)
	if denied == nil {
		return s.authorizeAccount(cfg, req)
	}
	if !errors.Is(denied, errDingTalkMembershipOnly) && !errors.Is(denied, errDirectoryMembershipOnly) && !errors.Is(denied, errUserNotEnrolled) {
		return denied
	}
	p, err := readAccountPolicy(cfg)
	if err != nil {
		return err
	}
	candidate, ok := p.CredentialCandidates[username]
	if !ok || candidate.Owner.SourceSlug != source {
		return denied
	}
	return withAccountMutation(cfg, username, false, func() error {
		grant, err := userEnrollment(cfg, username)
		if grant == nil && err == nil { // Another request completed enrollment.
			return s.authorizeAccount(cfg, req)
		}
		if err != nil && !errors.Is(err, errUserNotEnrolled) {
			return err
		}
		info, err := getSynoUser(cfg.SynoUserPath, username)
		if err != nil {
			return err
		}
		if !info.ExpiryKnown {
			return errors.New("无法确认 DSM 账号是否启用")
		}
		if info.Expired {
			return fmt.Errorf("DSM 用户 %q 已停用", username)
		}
		linked, err := s.linkVerifiedDirectoryUser(cfg, username, info.Mail, grant, req)
		if err != nil {
			return err
		}
		if !linked {
			return denied
		}
		return nil
	})
}

func loginDeniedResponse(err error) map[string]any {
	if errors.Is(err, errDingTalkMembershipOnly) {
		return errorResponse("LOGIN_OWNER_VERIFICATION_REQUIRED", err.Error()+"。管理员可在此身份源的登录审计中批量关联已有账号，或核实这条绑定")
	}
	if errors.Is(err, errDirectoryMembershipOnly) {
		return errorResponse("LOGIN_OWNER_VERIFICATION_REQUIRED", err.Error()+"。管理员可在此身份源的登录审计中核实这条绑定")
	}
	return errorResponse("ACCOUNT_FORBIDDEN", err.Error())
}

func queryAccountAsPackage(cfg config.HelperConfig, request db.HelperAuthorizationQuery) (bool, error) {
	result, err := queryHelperAsPackage(cfg, request)
	return result.Allowed, err
}

func queryHelperAsPackage(cfg config.HelperConfig, request db.HelperAuthorizationQuery) (db.HelperAuthorizationResult, error) {
	var result db.HelperAuthorizationResult
	if cfg.PackageUID <= 0 || uint64(cfg.PackageUID) >= 1<<32-1 || cfg.PackageGID <= 0 || uint64(cfg.PackageGID) >= 1<<32-1 {
		return result, errors.New("unprivileged query identity is unavailable")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	timeout := 3 * time.Second
	if request.Action == "directory_member_batch" || request.Action == "provision_users" {
		timeout = 20 * time.Second
	}
	var output limitedAuthorizationOutput
	if request.Action == "enrollment_snapshot" || request.Action == "dingtalk_login_roster" {
		timeout = 30 * time.Second
		output.limit = 8 << 20
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.HelperBinaryPath, "query-account")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(cfg.PackageUID), Gid: uint32(cfg.PackageGID), Groups: []uint32{}}}
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return result, errors.New("unprivileged account query failed")
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		return result, errors.New("invalid account query response")
	}
	if result.Error == "source_conflict" {
		return result, db.ErrSyncedPasswordSourceConflict
	}
	if result.Error != "" {
		return result, errors.New("account query could not verify authorization")
	}
	return result, nil
}

type limitedAuthorizationOutput struct {
	bytes.Buffer
	limit int
}

func (b *limitedAuthorizationOutput) Write(data []byte) (int, error) {
	limit := b.limit
	if limit == 0 {
		limit = 8192
	}
	if b.Len()+len(data) > limit {
		return 0, errors.New("account query response exceeds limit")
	}
	return b.Buffer.Write(data)
}
