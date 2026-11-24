package helperclient

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/diaglog"
	"github.com/dsmpass/dsmpass/go/internal/signing"
)

var ErrAccountAbsent = errors.New("DSM 已确认账号不存在")
var ErrAccountDisabled = errors.New("DSM 账号已停用，需核实后恢复")
var ErrDirectoryMembershipOnly = errors.New("此账号仅同步部门成员，保留原密码")
var ErrDingTalkMembershipOnly = ErrDirectoryMembershipOnly

// GroupMemberBatchSize bounds both the socket payload and time under the DSM writer lock.
const GroupMemberBatchSize = db.MaxGroupMembers

var ErrGroupBatchUnsupported = errors.New("DSM group member batching is unavailable")

type GroupMemberBatchClient interface {
	AddGroupMembers(context.Context, string, string, []string) ([]string, error)
}

// GroupWithMembersClient can leave a missing group for its first member batch.
type GroupWithMembersClient interface {
	PrepareGroupForMembers(context.Context, string, string) (bool, error)
	GroupMemberBatchClient
}

// ProvisionUserResult distinguishes a fresh native creation with an explicitly
// supplied password from a reconciliation of an existing DSM account.
type ProvisionUserResult struct {
	Created                bool
	InitialPasswordApplied bool
}

type UserProvisionResultClient interface {
	ProvisionUserWithResult(ctx context.Context, requestID, username, displayName, email, initialPassword string) (ProvisionUserResult, error)
}

type Client interface {
	HealthCheck(ctx context.Context) (map[string]any, error)
	RelayLogin(ctx context.Context, requestID, username, identityID, loginSource string) (RelayLoginResult, error)
	PrepareBrowserLogin(ctx context.Context, requestID, username, identityID, loginSource string) (BrowserLoginResult, error)
	CompleteBrowserLogin(ctx context.Context, requestID string) error
	ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error)
	ResetSyncedUserPassword(ctx context.Context, requestID, sourceSlug, accountID, username, password string) error
	DisableUser(ctx context.Context, requestID, username string) (bool, error)
	DisableDingTalkUser(ctx context.Context, requestID, runID, source, accountID, subject, username string) error
	ProvisionGroup(ctx context.Context, requestID, groupname string) (bool, error)
	WebGroupApproval(ctx context.Context, requestID, groupname string, verify bool) (map[string]any, error)
	AddGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error)
	RemoveGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error)
}

type RelayCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	MaxAge   int    `json:"max_age"`
	HTTPOnly bool   `json:"http_only"`
}

type RelayLoginResult struct {
	SID     string        `json:"sid"`
	Cookies []RelayCookie `json:"cookies"`
}

type BrowserLoginResult struct {
	Username     string `json:"username"`
	TempPassword string `json:"temp_password"`
	ExpiresAt    string `json:"expires_at"`
	TTLSeconds   int    `json:"ttl_seconds"`
}

type UnixSocketClient struct {
	SocketPath         string
	Secret             string
	Timeout            time.Duration
	DataDir            string
	DiagnosticsEnabled bool
}

func NewUnixSocketClient(cfg config.BackendConfig) UnixSocketClient {
	return UnixSocketClient{
		SocketPath:         cfg.RelayHelperSocket,
		Secret:             cfg.RelayHelperHMACSecret,
		Timeout:            time.Duration(cfg.RelayHelperTimeoutSeconds) * time.Second,
		DataDir:            cfg.DataDir,
		DiagnosticsEnabled: cfg.LoginDiagnosticsEnabled,
	}
}

func (c UnixSocketClient) HealthCheck(ctx context.Context) (map[string]any, error) {
	return c.send(ctx, map[string]any{"action": "health_check"})
}

func (c UnixSocketClient) RelayLogin(ctx context.Context, requestID, username, identityID, loginSource string) (RelayLoginResult, error) {
	diaglog.Append(c.DataDir, requestID, "backend.helper.relay_login.request", c.DiagnosticsEnabled, diaglog.Event{
		"dsm_username": username,
		"identity_id":  identityID,
		"login_source": loginSource,
		"socket_path":  c.SocketPath,
		"timeout_ms":   c.Timeout.Milliseconds(),
	})
	response, err := c.send(ctx, map[string]any{
		"action":       "scoped_relay_login",
		"request_id":   requestID,
		"dsm_username": username,
		"identity_id":  identityID,
		"login_source": loginSource,
	})
	if err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.relay_login.error", c.DiagnosticsEnabled, diaglog.Event{
			"dsm_username": username,
			"error":        err.Error(),
		})
		return RelayLoginResult{}, err
	}
	sid, ok := response["sid"].(string)
	if !ok || sid == "" {
		diaglog.Append(c.DataDir, requestID, "backend.helper.relay_login.missing_sid", c.DiagnosticsEnabled, diaglog.Event{"response": response})
		return RelayLoginResult{}, errors.New("helper response missing sid")
	}
	result := RelayLoginResult{SID: sid, Cookies: relayCookiesFromResponse(response)}
	diaglog.Append(c.DataDir, requestID, "backend.helper.relay_login.success", c.DiagnosticsEnabled, diaglog.Event{
		"dsm_username": username,
		"sid":          sid,
		"cookies":      result.Cookies,
	})
	return result, nil
}

func (c UnixSocketClient) PrepareBrowserLogin(ctx context.Context, requestID, username, identityID, loginSource string) (BrowserLoginResult, error) {
	diaglog.Append(c.DataDir, requestID, "backend.helper.prepare_browser_login.request", c.DiagnosticsEnabled, diaglog.Event{
		"dsm_username": username,
		"identity_id":  identityID,
		"login_source": loginSource,
		"socket_path":  c.SocketPath,
		"timeout_ms":   c.Timeout.Milliseconds(),
	})
	response, err := c.send(ctx, map[string]any{
		"action":       "scoped_prepare_browser_login",
		"request_id":   requestID,
		"dsm_username": username,
		"identity_id":  identityID,
		"login_source": loginSource,
	})
	if err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.prepare_browser_login.error", c.DiagnosticsEnabled, diaglog.Event{
			"dsm_username": username,
			"error":        err.Error(),
		})
		return BrowserLoginResult{}, err
	}
	result := BrowserLoginResult{}
	result.Username, _ = response["username"].(string)
	result.TempPassword, _ = response["temp_password"].(string)
	result.ExpiresAt, _ = response["expires_at"].(string)
	if ttl, ok := response["ttl_seconds"].(float64); ok {
		result.TTLSeconds = int(ttl)
	}
	if result.Username == "" || result.TempPassword == "" {
		diaglog.Append(c.DataDir, requestID, "backend.helper.prepare_browser_login.bad_response", c.DiagnosticsEnabled, diaglog.Event{"response": response})
		return BrowserLoginResult{}, errors.New("helper response missing browser login credentials")
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.prepare_browser_login.success", c.DiagnosticsEnabled, diaglog.Event{
		"dsm_username": result.Username,
		"expires_at":   result.ExpiresAt,
		"ttl_seconds":  result.TTLSeconds,
	})
	return result, nil
}

func (c UnixSocketClient) CompleteBrowserLogin(ctx context.Context, requestID string) error {
	diaglog.Append(c.DataDir, requestID, "backend.helper.complete_browser_login.request", c.DiagnosticsEnabled, diaglog.Event{
		"socket_path": c.SocketPath,
		"timeout_ms":  c.Timeout.Milliseconds(),
	})
	_, err := c.send(ctx, map[string]any{
		"action":     "complete_browser_login",
		"request_id": requestID,
	})
	if err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.complete_browser_login.error", c.DiagnosticsEnabled, diaglog.Event{"error": err.Error()})
		return err
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.complete_browser_login.success", c.DiagnosticsEnabled, diaglog.Event{})
	return nil
}

func relayCookiesFromResponse(response map[string]any) []RelayCookie {
	raw, ok := response["cookies"].([]any)
	if !ok {
		return nil
	}
	cookies := make([]RelayCookie, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		cookie := RelayCookie{}
		cookie.Name, _ = entry["name"].(string)
		cookie.Value, _ = entry["value"].(string)
		cookie.Path, _ = entry["path"].(string)
		cookie.HTTPOnly, _ = entry["http_only"].(bool)
		if maxAge, ok := entry["max_age"].(float64); ok {
			cookie.MaxAge = int(maxAge)
		}
		if cookie.Name != "" && cookie.Value != "" {
			cookies = append(cookies, cookie)
		}
	}
	return cookies
}

func (c UnixSocketClient) ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error) {
	result, err := c.ProvisionUserWithResult(ctx, requestID, username, displayName, email, initialPassword)
	return result.Created, err
}

func (c UnixSocketClient) ProvisionUserWithResult(ctx context.Context, requestID, username, displayName, email, initialPassword string) (ProvisionUserResult, error) {
	response, err := c.send(ctx, map[string]any{
		"action":           "scoped_provision_user",
		"request_id":       requestID,
		"dsm_username":     username,
		"display_name":     displayName,
		"email":            email,
		"initial_password": initialPassword,
	})
	return provisionUserResult(response, initialPassword, err)
}

func provisionUserResult(response map[string]any, initialPassword string, err error) (ProvisionUserResult, error) {
	created, err := boolResponse(response, err)
	explicit, _ := response["created"].(bool)
	applied, _ := response["initial_password_applied"].(bool)
	return ProvisionUserResult{Created: created, InitialPasswordApplied: err == nil && explicit && applied && initialPassword != ""}, err
}

func (c UnixSocketClient) DisableDingTalkUser(ctx context.Context, requestID, runID, source, accountID, subject, username string) error {
	response, err := c.send(ctx, map[string]any{"action": "scoped_disable_dingtalk_user", "request_id": requestID, "run_id": runID, "source_slug": source, "account_id": accountID, "subject": subject, "dsm_username": username})
	if err != nil {
		return err
	}
	if response["absent"] == true && response["disabled"] == false {
		return ErrAccountAbsent
	}
	if confirmed, _ := response["disabled"].(bool); !confirmed {
		return errors.New("Helper 未确认 DSM 账号已停用")
	}
	return nil
}

func (c UnixSocketClient) DisableUser(ctx context.Context, requestID, username string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":       "scoped_disable_user",
		"request_id":   requestID,
		"dsm_username": username,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) ResetSyncedUserPassword(ctx context.Context, requestID, sourceSlug, accountID, username, password string) error {
	// The Helper bounds synouser to 20 seconds; allow its result to arrive before
	// treating a permanent reset as failed due to the usual short login timeout.
	if c.Timeout < 30*time.Second {
		c.Timeout = 30 * time.Second
	}
	_, err := c.send(ctx, map[string]any{
		"action": "scoped_reset_synced_user_password", "request_id": requestID,
		"source_slug": sourceSlug, "account_id": accountID,
		"dsm_username": username, "password": password,
	})
	return err
}

func (c UnixSocketClient) ProvisionGroup(ctx context.Context, requestID, groupname string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":        "scoped_provision_group",
		"request_id":    requestID,
		"dsm_groupname": groupname,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) PrepareGroupForMembers(ctx context.Context, requestID, groupname string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action": "scoped_provision_group", "request_id": requestID,
		"dsm_groupname": groupname, "defer_if_missing": true,
	})
	return boolResponse(response, err)
}

type LoginApprovalClient interface {
	WebLoginApproval(ctx context.Context, requestID string, owner db.CredentialIdentity, identityID string, verify bool) (map[string]any, error)
}

func (c UnixSocketClient) WebLoginApproval(ctx context.Context, requestID string, owner db.CredentialIdentity, identityID string, verify bool) (map[string]any, error) {
	if c.Timeout < 15*time.Second {
		c.Timeout = 15 * time.Second
	}
	return c.send(ctx, map[string]any{"action": "scoped_web_login_approval", "request_id": requestID, "dsm_username": owner.Username, "source_slug": owner.SourceSlug, "subject": owner.Subject, "identity_id": identityID, "verify": verify})
}

func (c UnixSocketClient) WebGroupApproval(ctx context.Context, requestID, groupname string, verify bool) (map[string]any, error) {
	if c.Timeout < 15*time.Second {
		c.Timeout = 15 * time.Second
	}
	return c.send(ctx, map[string]any{"action": "scoped_web_group_approval", "request_id": requestID, "dsm_groupname": groupname, "verify": verify})
}

func (c UnixSocketClient) AddGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":        "scoped_add_group_member",
		"request_id":    requestID,
		"dsm_groupname": groupname,
		"dsm_username":  username,
	})
	return boolResponse(response, err)
}

// AddGroupMembers returns only names the Helper confirmed by reading the group.
func (c UnixSocketClient) AddGroupMembers(ctx context.Context, requestID, groupname string, usernames []string) ([]string, error) {
	response, err := c.send(ctx, map[string]any{
		"action": "scoped_add_group_members", "request_id": requestID,
		"dsm_groupname": groupname, "dsm_usernames": usernames,
	})
	if err != nil {
		return nil, err
	}
	values, ok := response["confirmed"].([]any)
	if !ok {
		return nil, errors.New("missing confirmed DSM group members")
	}
	wanted := make(map[string]bool, len(usernames))
	for _, name := range usernames {
		wanted[name] = true
	}
	confirmed := make([]string, 0, len(values))
	for _, value := range values {
		name, ok := value.(string)
		if !ok || !wanted[name] {
			return nil, errors.New("invalid confirmed DSM group members")
		}
		delete(wanted, name)
		confirmed = append(confirmed, name)
	}
	if message, _ := response["batch_error"].(string); message != "" {
		return confirmed, errors.New(message)
	}
	if len(wanted) != 0 {
		return confirmed, errors.New("DSM did not confirm all requested group members")
	}
	return confirmed, nil
}

func (c UnixSocketClient) RemoveGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":        "scoped_remove_group_member",
		"request_id":    requestID,
		"dsm_groupname": groupname,
		"dsm_username":  username,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) send(ctx context.Context, payload map[string]any) (map[string]any, error) {
	requestID, _ := payload["request_id"].(string)
	action, _ := payload["action"].(string)
	if action != "health_check" && buildinfo.Version != "dev" {
		health, err := c.HealthCheck(ctx)
		if err != nil {
			return nil, fmt.Errorf("Helper 不可连接，请在管理页面检查安装或升级状态: %w", err)
		}
		if err := CheckCompatibility(health, buildinfo.Version, buildinfo.Revision, buildinfo.BuildEpoch); err != nil {
			return nil, err
		}
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.socket.send.start", c.DiagnosticsEnabled, diaglog.Event{
		"action":      action,
		"socket_path": c.SocketPath,
		"timeout_ms":  c.Timeout.Milliseconds(),
		"payload":     payload,
	})
	payload["timestamp"] = time.Now().Unix()
	payload["nonce"] = randomNonce()
	signature, err := signing.Sign(payload, c.Secret)
	if err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.sign.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "payload": payload})
		return nil, err
	}
	payload["signature"] = signature

	dialer := net.Dialer{Timeout: c.Timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.dial.error", c.DiagnosticsEnabled, diaglog.Event{
			"action":      action,
			"socket_path": c.SocketPath,
			"error":       err.Error(),
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return nil, err
	}
	defer conn.Close()
	if action == "scoped_reset_synced_user_passwords" {
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
	}
	// Include account/global lock waits, hashing and (for relay) DSM HTTP and
	// recovery. Health checks and unrelated actions retain their short timeout.
	timeout := c.Timeout
	switch action {
	case "capture_directory_snapshot", "scoped_directory_snapshot":
		timeout = max(timeout, 3*time.Minute)
	case "scoped_provision_users":
		timeout = max(timeout, 16*time.Minute)
	case "scoped_add_group_members":
		timeout = max(timeout, 120*time.Second)
	case "scoped_prepare_browser_login", "complete_browser_login":
		if timeout < 75*time.Second {
			timeout = 75 * time.Second
		}
	case "scoped_relay_login":
		if timeout < 120*time.Second {
			timeout = 120 * time.Second
		}
	}
	deadline := time.Now().Add(timeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	_ = conn.SetDeadline(deadline)
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.write.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "payload": payload})
		return nil, err
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.socket.write.success", c.DiagnosticsEnabled, diaglog.Event{"action": action, "payload": payload})
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.read.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "duration_ms": time.Since(start).Milliseconds()})
		return nil, err
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.socket.read.success", c.DiagnosticsEnabled, diaglog.Event{"action": action, "raw_response": diagnosticRawResponse(line), "duration_ms": time.Since(start).Milliseconds()})
	var response map[string]any
	if err := json.Unmarshal(line, &response); err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.decode.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "raw_response": diagnosticRawResponse(line)})
		return nil, err
	}
	if success, _ := response["success"].(bool); !success {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.response.failure", c.DiagnosticsEnabled, diaglog.Event{"action": action, "response": response})
		if code, _ := response["error_code"].(string); code != "" {
			if action == "scoped_provision_users" && code == "BAD_REQUEST" && response["error"] == "unsupported action" {
				return nil, ErrUserBatchUnsupported
			}
			if action == "scoped_add_group_members" && (code == "GROUP_BATCH_UNSUPPORTED" || (code == "BAD_REQUEST" && response["error"] == "unsupported action")) {
				return nil, ErrGroupBatchUnsupported
			}
			if action == "scoped_reset_synced_user_passwords" && code == "BAD_REQUEST" && response["error"] == "unsupported action" {
				return nil, ErrPasswordBatchUnsupported
			}
			if action == "scoped_provision_user" && code == "DSM_ACCOUNT_DISABLED" {
				return nil, ErrAccountDisabled
			}
			if action == "scoped_reset_synced_user_password" && (code == "DINGTALK_MEMBERSHIP_ONLY" || code == "DIRECTORY_MEMBERSHIP_ONLY") {
				return nil, ErrDingTalkMembershipOnly
			}
			if message, _ := response["error"].(string); message != "" {
				return nil, fmt.Errorf("%s: %s", code, message)
			}
			return nil, errors.New(code)
		}
		return nil, errors.New("helper error")
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.socket.response.success", c.DiagnosticsEnabled, diaglog.Event{"action": action, "response": response})
	return response, nil
}

func diagnosticRawResponse(line []byte) any {
	var response map[string]any
	if err := json.Unmarshal(line, &response); err != nil {
		return map[string]any{"valid_json": false, "bytes": len(line)}
	}
	return response
}

func randomNonce() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func boolResponse(response map[string]any, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	created, ok := response["created"].(bool)
	if !ok {
		return true, nil
	}
	return created, nil
}
