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

// loginAuthorization returns the same account check for each lock boundary.
func (s *Server) loginAuthorization(cfg config.HelperConfig, payload map[string]any) (func() error, error) {
	username, err := requiredString(payload, "dsm_username")
	if err != nil {
		return nil, err
	}
	identityID, err := requiredString(payload, "identity_id")
	if err != nil {
		return nil, err
	}
	source, err := requiredString(payload, "login_source")
	if err != nil {
		return nil, err
	}
	request := db.HelperAuthorizationQuery{Action: "login", Username: username, IdentityID: identityID, SourceSlug: source}
	grant, err := userEnrollment(cfg, username)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return func() error { return requireManagedUser(cfg, username) }, s.authorizeAccount(cfg, request)
	}
	if grant.DingTalk == nil {
		return nil, fmt.Errorf("DSM 用户 %q 只有通讯录同步授权", username)
	}
	if grant.DingTalk.SourceSlug != source || grant.DingTalk.Subject == "" {
		return nil, errors.New("登录身份源与已登记的钉钉绑定不匹配")
	}
	if grant.LoginEmail == "" {
		return nil, fmt.Errorf("DSM 用户 %q 仅已关联通讯录，请同步钉钉企业邮箱并由 NAS 管理员批量登记登录绑定", username)
	}
	request.Action = "dingtalk_login"
	request.Subject = grant.DingTalk.Subject
	request.LoginEmail = grant.LoginEmail
	check := func() error {
		current, err := userEnrollment(cfg, username)
		if err != nil {
			return err
		}
		if current == nil || current.UID != grant.UID || current.DingTalk == nil || *current.DingTalk != *grant.DingTalk || current.LoginEmail != grant.LoginEmail {
			return errors.New("钉钉登录绑定已变更，请重新登录")
		}
		info, err := getSynoUser(cfg.SynoUserPath, username)
		if err != nil {
			return fmt.Errorf("读取 DSM 登录账号资料: %w", err)
		}
		if info.Expired || !strings.EqualFold(strings.TrimSpace(info.Mail), grant.LoginEmail) {
			return errors.New("DSM 账号已停用或已有邮箱与钉钉企业邮箱不符")
		}
		return s.authorizeAccount(cfg, request)
	}
	return check, check()
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
	var output limitedAuthorizationOutput
	if request.Action == "enrollment_snapshot" {
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
