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
	var allowed bool
	var err error
	if cfg.Privileged {
		request.DatabasePath = strings.TrimPrefix(cfg.DatabaseURL, "sqlite://")
		allowed, err = queryAccountAsPackage(cfg, request)
	} else {
		allowed, err = db.HelperAccountAllowed(context.Background(), s.store, request)
	}
	if err != nil {
		return fmt.Errorf("verify DSM account authorization: %w", err)
	}
	if !allowed {
		return errors.New("DSM account is not authorized for this identity and operation")
	}
	return nil
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
	if err := requireManagedUser(cfg, username); err != nil {
		return err
	}
	return s.authorizeAccount(cfg, db.HelperAuthorizationQuery{Action: "login", Username: username, IdentityID: identityID, SourceSlug: source})
}

func queryAccountAsPackage(cfg config.HelperConfig, request db.HelperAuthorizationQuery) (bool, error) {
	if cfg.PackageUID <= 0 || uint64(cfg.PackageUID) >= 1<<32-1 || cfg.PackageGID <= 0 || uint64(cfg.PackageGID) >= 1<<32-1 {
		return false, errors.New("unprivileged query identity is unavailable")
	}
	data, err := json.Marshal(request)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.HelperBinaryPath, "query-account")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(cfg.PackageUID), Gid: uint32(cfg.PackageGID), Groups: []uint32{}}}
	cmd.Stdin = bytes.NewReader(data)
	var output limitedAuthorizationOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return false, errors.New("unprivileged account query failed")
	}
	var result db.HelperAuthorizationResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		return false, errors.New("invalid account query response")
	}
	if result.Error == "source_conflict" {
		return false, db.ErrSyncedPasswordSourceConflict
	}
	if result.Error != "" {
		return false, errors.New("account query could not verify authorization")
	}
	return result.Allowed, nil
}

type limitedAuthorizationOutput struct{ bytes.Buffer }

func (b *limitedAuthorizationOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 8192 {
		return 0, errors.New("account query response exceeds limit")
	}
	return b.Buffer.Write(data)
}
