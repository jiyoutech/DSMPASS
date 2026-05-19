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

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/diaglog"
	"github.com/dsmpass/dsmpass/go/internal/signing"
)

type Client interface {
	HealthCheck(ctx context.Context) (map[string]any, error)
	RelayLogin(ctx context.Context, requestID, username, identityID, loginSource string) (RelayLoginResult, error)
	PrepareBrowserLogin(ctx context.Context, requestID, username, identityID, loginSource string) (BrowserLoginResult, error)
	CompleteBrowserLogin(ctx context.Context, requestID string) error
	ProvisionUser(ctx context.Context, requestID, username, displayName, email, initialPassword string) (bool, error)
	DisableUser(ctx context.Context, requestID, username string) (bool, error)
	ProvisionGroup(ctx context.Context, requestID, groupname string) (bool, error)
	AddGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error)
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
		"action":       "relay_login",
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
		"action":       "prepare_browser_login",
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
	response, err := c.send(ctx, map[string]any{
		"action":           "provision_user",
		"request_id":       requestID,
		"dsm_username":     username,
		"display_name":     displayName,
		"email":            email,
		"initial_password": initialPassword,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) DisableUser(ctx context.Context, requestID, username string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":       "disable_user",
		"request_id":   requestID,
		"dsm_username": username,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) ProvisionGroup(ctx context.Context, requestID, groupname string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":        "provision_group",
		"request_id":    requestID,
		"dsm_groupname": groupname,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) AddGroupMember(ctx context.Context, requestID, groupname, username string) (bool, error) {
	response, err := c.send(ctx, map[string]any{
		"action":        "add_group_member",
		"request_id":    requestID,
		"dsm_groupname": groupname,
		"dsm_username":  username,
	})
	return boolResponse(response, err)
}

func (c UnixSocketClient) send(ctx context.Context, payload map[string]any) (map[string]any, error) {
	requestID, _ := payload["request_id"].(string)
	action, _ := payload["action"].(string)
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
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))

	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.write.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "payload": payload})
		return nil, err
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.socket.write.success", c.DiagnosticsEnabled, diaglog.Event{"action": action, "payload": payload})
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.read.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "duration_ms": time.Since(start).Milliseconds()})
		return nil, err
	}
	diaglog.Append(c.DataDir, requestID, "backend.helper.socket.read.success", c.DiagnosticsEnabled, diaglog.Event{"action": action, "raw_response": string(line), "duration_ms": time.Since(start).Milliseconds()})
	var response map[string]any
	if err := json.Unmarshal(line, &response); err != nil {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.decode.error", c.DiagnosticsEnabled, diaglog.Event{"action": action, "error": err.Error(), "raw_response": string(line)})
		return nil, err
	}
	if success, _ := response["success"].(bool); !success {
		diaglog.Append(c.DataDir, requestID, "backend.helper.socket.response.failure", c.DiagnosticsEnabled, diaglog.Event{"action": action, "response": response})
		if code, _ := response["error_code"].(string); code != "" {
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
