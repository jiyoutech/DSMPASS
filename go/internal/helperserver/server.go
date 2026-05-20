package helperserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/diaglog"
	"github.com/dsmpass/dsmpass/go/internal/settings"
	"github.com/dsmpass/dsmpass/go/internal/signing"
)

type Server struct {
	cfg       config.HelperConfig
	store     *db.Queries
	replayMu  sync.Mutex
	seenNonce map[string]int64
}

func New(cfg config.HelperConfig) *Server {
	return &Server{cfg: cfg, seenNonce: map[string]int64{}}
}

func NewWithStore(cfg config.HelperConfig, store *db.Queries) *Server {
	return &Server{cfg: cfg, store: store, seenNonce: map[string]int64{}}
}

func (s *Server) Serve() error {
	startupCfg := settings.ApplyHelperRuntime(context.Background(), s.cfg, s.store)
	if err := os.MkdirAll(filepath.Dir(startupCfg.SocketPath), 0o700); err != nil {
		return err
	}
	if err := removeStaleSocket(startupCfg.SocketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", startupCfg.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := setSocketPermissions(startupCfg.SocketPath); err != nil {
		return err
	}
	recoverPending(startupCfg)
	log.Printf("DSM Pass helper listening on %s", startupCfg.SocketPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func removeStaleSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket helper path: %s", socketPath)
	}
	return os.Remove(socketPath)
}

func setSocketPermissions(socketPath string) error {
	if os.Geteuid() == 0 {
		var parentStat syscall.Stat_t
		if err := syscall.Stat(filepath.Dir(socketPath), &parentStat); err == nil {
			_ = os.Chown(socketPath, int(parentStat.Uid), int(parentStat.Gid))
		}
	}
	return os.Chmod(socketPath, 0o660)
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		_ = json.NewEncoder(conn).Encode(errorResponse("BAD_REQUEST", "failed to read request"))
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(line, &payload); err != nil {
		_ = json.NewEncoder(conn).Encode(errorResponse("BAD_REQUEST", "invalid json"))
		return
	}
	response := s.handlePayload(payload)
	_ = json.NewEncoder(conn).Encode(response)
}

func (s *Server) handlePayload(payload map[string]any) map[string]any {
	cfg := settings.ApplyHelperRuntime(context.Background(), s.cfg, s.store)
	requestID, _ := payload["request_id"].(string)
	action, _ := payload["action"].(string)
	diaglog.Append(cfg.DataDir, requestID, "helper.socket.request.received", cfg.LoginDiagnosticsEnabled, diaglog.Event{
		"action":  action,
		"payload": payload,
	})
	if err := signing.Verify(payload, cfg.HMACSecret, cfg.TimestampSkewSeconds); err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.socket.signature.invalid", cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"action": action,
			"error":  err.Error(),
		})
		return errorResponse("BAD_SIGNATURE", err.Error())
	}
	if err := s.rejectReplay(payload, cfg.TimestampSkewSeconds); err != nil {
		diaglog.Append(cfg.DataDir, requestID, "helper.socket.replay.rejected", cfg.LoginDiagnosticsEnabled, diaglog.Event{
			"action": action,
			"error":  err.Error(),
		})
		return errorResponse("REPLAY_REJECTED", err.Error())
	}
	diaglog.Append(cfg.DataDir, requestID, "helper.socket.signature.valid", cfg.LoginDiagnosticsEnabled, diaglog.Event{"action": action})
	switch action {
	case "health_check":
		return map[string]any{
			"success":          true,
			"version":          buildinfo.Version,
			"socket_path":      cfg.SocketPath,
			"euid":             os.Geteuid(),
			"egid":             os.Getegid(),
			"synouser_path":    cfg.SynoUserPath,
			"synouser_status":  helperCommandStatus(cfg.SynoUserPath),
			"synogroup_path":   cfg.SynoGroupPath,
			"synogroup_status": helperCommandStatus(cfg.SynoGroupPath),
		}
	case "relay_login":
		username, err := requiredString(payload, "dsm_username")
		if err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.bad_request", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "payload": payload})
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := assertAllowed(cfg, username); err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.username_not_allowed", cfg.LoginDiagnosticsEnabled, diaglog.Event{"dsm_username": username, "error": err.Error()})
			return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
		}
		requestID, err := requiredString(payload, "request_id")
		if err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.missing_request_id", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "payload": payload})
			return errorResponse("BAD_REQUEST", err.Error())
		}
		result, err := relayLoginReal(cfg, requestID, username)
		if err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.error_response", cfg.LoginDiagnosticsEnabled, diaglog.Event{"dsm_username": username, "error": err.Error()})
			return errorResponse("RELAY_LOGIN_FAILED", err.Error())
		}
		diaglog.Append(cfg.DataDir, requestID, "helper.relay_login.success_response", cfg.LoginDiagnosticsEnabled, diaglog.Event{"dsm_username": username, "sid": result.SID, "cookies": result.Cookies})
		return map[string]any{"success": true, "sid": result.SID, "cookies": result.Cookies}
	case "prepare_browser_login":
		username, err := requiredString(payload, "dsm_username")
		if err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.bad_request", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error(), "payload": payload})
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := assertAllowed(cfg, username); err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.username_not_allowed", cfg.LoginDiagnosticsEnabled, diaglog.Event{"dsm_username": username, "error": err.Error()})
			return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
		}
		requestID, err := requiredString(payload, "request_id")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		result, err := prepareBrowserLogin(cfg, requestID, username)
		if err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.error_response", cfg.LoginDiagnosticsEnabled, diaglog.Event{"dsm_username": username, "error": err.Error()})
			return errorResponse("PREPARE_BROWSER_LOGIN_FAILED", err.Error())
		}
		diaglog.Append(cfg.DataDir, requestID, "helper.prepare_browser_login.success_response", cfg.LoginDiagnosticsEnabled, diaglog.Event{"dsm_username": username, "expires_at": result.ExpiresAt, "ttl_seconds": result.TTLSeconds})
		return map[string]any{"success": true, "username": result.Username, "temp_password": result.TempPassword, "expires_at": result.ExpiresAt, "ttl_seconds": result.TTLSeconds}
	case "complete_browser_login":
		requestID, err := requiredString(payload, "request_id")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := restorePendingJournal(cfg, requestID, "browser_login_complete"); err != nil {
			diaglog.Append(cfg.DataDir, requestID, "helper.complete_browser_login.error_response", cfg.LoginDiagnosticsEnabled, diaglog.Event{"error": err.Error()})
			return errorResponse("COMPLETE_BROWSER_LOGIN_FAILED", err.Error())
		}
		diaglog.Append(cfg.DataDir, requestID, "helper.complete_browser_login.success_response", cfg.LoginDiagnosticsEnabled, diaglog.Event{})
		return map[string]any{"success": true}
	case "provision_user":
		username, err := requiredString(payload, "dsm_username")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := assertAllowed(cfg, username); err != nil {
			return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
		}
		displayName, _ := optionalString(payload, "display_name")
		email, _ := optionalString(payload, "email")
		if info, err := getSynoUser(cfg.SynoUserPath, username); err == nil {
			if displayName == "" {
				displayName = info.FullName
			}
			if email == "" {
				email = info.Mail
			}
			if info.Expired || displayName != info.FullName || email != info.Mail {
				if err := modifySynoUser(cfg.SynoUserPath, username, displayName, false, email); err != nil {
					return errorResponse("SYNOUSER_ENABLE_FAILED", "DSM 用户已存在，但恢复启用或更新资料失败："+err.Error())
				}
			}
			return map[string]any{"success": true, "created": false}
		}
		password, _ := optionalString(payload, "initial_password")
		if password == "" {
			password = randomPassword(cfg.InitialPasswordLength)
		}
		if err := run(cfg.SynoUserPath, synouserAddArgs(username, password, displayName, email)...); err != nil {
			return errorResponse("SYNOUSER_FAILED", err.Error())
		}
		if err := run(cfg.SynoUserPath, "--get", username); err != nil {
			return errorResponse("SYNOUSER_VERIFY_FAILED", "DSM 用户创建命令已返回成功，但随后无法查询到该用户："+err.Error())
		}
		return map[string]any{"success": true, "created": true}
	case "provision_group":
		groupname, err := requiredString(payload, "dsm_groupname")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := run(cfg.SynoGroupPath, "--get", groupname); err == nil {
			return map[string]any{"success": true, "created": true}
		}
		if err := run(cfg.SynoGroupPath, "--add", groupname); err != nil {
			if isSynoNoSuchGroupError(err) {
				return map[string]any{
					"success":  true,
					"created":  false,
					"deferred": true,
					"warning":  "DSM synogroup cannot create this group without members; it will be created when the first member is added",
				}
			}
			return errorResponse("SYNOGROUP_FAILED", synoGroupError("create", groupname, "", err))
		}
		return map[string]any{"success": true, "created": true}
	case "disable_user":
		username, err := requiredString(payload, "dsm_username")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := assertAllowed(cfg, username); err != nil {
			return errorResponse("USERNAME_NOT_ALLOWED", err.Error())
		}
		info, err := getSynoUser(cfg.SynoUserPath, username)
		if err != nil {
			return map[string]any{"success": true, "disabled": false}
		}
		if err := modifySynoUser(cfg.SynoUserPath, username, info.FullName, true, info.Mail); err != nil {
			return errorResponse("SYNOUSER_FAILED", err.Error())
		}
		return map[string]any{"success": true, "disabled": true}
	case "add_group_member":
		groupname, err := requiredString(payload, "dsm_groupname")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		username, err := requiredString(payload, "dsm_username")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := run(cfg.SynoGroupPath, "--memberadd", groupname, username); err != nil {
			if isSynoGroupMemberPresent(err, groupname, username) {
				return map[string]any{"success": true, "created": false}
			}
			if isSynoNoSuchGroupError(err) {
				if createErr := run(cfg.SynoGroupPath, "--add", groupname, username); createErr == nil {
					return map[string]any{"success": true, "created": true}
				} else if isSynoGroupMemberPresent(createErr, groupname, username) {
					return map[string]any{"success": true, "created": false}
				} else {
					return errorResponse("SYNOGROUP_FAILED", synoGroupError("create_with_member", groupname, username, createErr))
				}
			}
			return errorResponse("SYNOGROUP_FAILED", synoGroupError("add_member", groupname, username, err))
		}
		return map[string]any{"success": true, "created": true}
	case "remove_group_member":
		groupname, err := requiredString(payload, "dsm_groupname")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		username, err := requiredString(payload, "dsm_username")
		if err != nil {
			return errorResponse("BAD_REQUEST", err.Error())
		}
		if err := run(cfg.SynoGroupPath, "--memberdel", groupname, username); err != nil {
			if isSynoNoSuchGroupError(err) {
				return map[string]any{"success": true, "removed": false}
			}
			return errorResponse("SYNOGROUP_FAILED", synoGroupError("remove_member", groupname, username, err))
		}
		return map[string]any{"success": true, "removed": true}
	default:
		return errorResponse("BAD_REQUEST", "unsupported action")
	}
}

func (s *Server) rejectReplay(payload map[string]any, skewSeconds int64) error {
	nonce, _ := payload["nonce"].(string)
	if nonce == "" {
		return errors.New("missing nonce")
	}
	timestamp, ok := payload["timestamp"].(float64)
	if !ok {
		return errors.New("missing timestamp")
	}
	now := time.Now().Unix()
	ttl := skewSeconds
	if ttl <= 0 {
		ttl = 60
	}
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for key, expires := range s.seenNonce {
		if expires <= now {
			delete(s.seenNonce, key)
		}
	}
	if _, exists := s.seenNonce[nonce]; exists {
		return errors.New("nonce already used")
	}
	s.seenNonce[nonce] = int64(timestamp) + ttl
	return nil
}

func helperCommandStatus(path string) map[string]any {
	status := map[string]any{
		"path":       path,
		"exists":     false,
		"executable": false,
	}
	info, err := os.Stat(path)
	if err != nil {
		status["error"] = err.Error()
		return status
	}
	status["exists"] = true
	status["mode"] = info.Mode().String()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		status["uid"] = stat.Uid
		status["gid"] = stat.Gid
	}
	status["executable"] = canExecute(info)
	if !status["executable"].(bool) {
		status["error"] = "current helper process cannot execute this file"
	}
	return status
}

func canExecute(info os.FileInfo) bool {
	if os.Geteuid() == 0 {
		return info.Mode()&0o111 != 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return info.Mode()&0o001 != 0
	}
	mode := info.Mode().Perm()
	if uint32(os.Geteuid()) == stat.Uid {
		return mode&0o100 != 0
	}
	if uint32(os.Getegid()) == stat.Gid && mode&0o010 != 0 {
		return true
	}
	groups, err := os.Getgroups()
	if err == nil {
		for _, group := range groups {
			if uint32(group) == stat.Gid && mode&0o010 != 0 {
				return true
			}
		}
	}
	return mode&0o001 != 0
}

func requiredString(payload map[string]any, key string) (string, error) {
	value, ok := payload[key].(string)
	if !ok || value == "" {
		return "", errors.New("missing " + key)
	}
	return value, nil
}

func optionalString(payload map[string]any, key string) (string, bool) {
	value, ok := payload[key].(string)
	return value, ok
}

func synouserAddArgs(username, password, displayName, email string) []string {
	return []string{"--add", username, password, displayName, "0", email, ""}
}

type synoUserInfo struct {
	FullName string
	Mail     string
	Expired  bool
}

func getSynoUser(path, username string) (synoUserInfo, error) {
	output, err := runOutput(path, "--get", username)
	if err != nil {
		return synoUserInfo{}, err
	}
	return parseSynoUserInfo(output), nil
}

func modifySynoUser(path, username, displayName string, expired bool, email string) error {
	expiredValue := "0"
	if expired {
		expiredValue = "1"
	}
	return run(path, "--modify", username, displayName, expiredValue, email)
}

func parseSynoUserInfo(output string) synoUserInfo {
	info := synoUserInfo{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := parseSynoUserField(line)
		if !ok {
			continue
		}
		switch key {
		case "Fullname":
			info.FullName = value
		case "User Mail":
			info.Mail = value
		case "Expired":
			info.Expired = strings.EqualFold(value, "true") || value == "1"
		}
	}
	return info
}

func parseSynoUserField(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	return key, value, true
}

func isSynoNoSuchGroupError(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "synoerr=0x1800") ||
		strings.Contains(text, "synoerr=[0x1800]") ||
		strings.Contains(strings.ToLower(text), "no such group") ||
		strings.Contains(text, "SYNOGroupGet failed")
}

func isSynoGroupMemberPresent(err error, groupname, username string) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, fmt.Sprintf("Group Name: [%s]", groupname)) &&
		strings.Contains(text, fmt.Sprintf("[%s]", username))
}

func synoGroupError(action, groupname, username string, err error) string {
	message := "DSM 群组操作失败"
	switch action {
	case "create":
		message = "DSM 群组创建失败"
	case "add_member":
		message = "DSM 群组成员添加失败"
	case "remove_member":
		message = "DSM 群组成员移除失败"
	case "create_with_member":
		message = "DSM 群组不存在，尝试创建并添加成员也失败"
	}
	detail := fmt.Sprintf("%s：群组=%q", message, groupname)
	if username != "" {
		detail += fmt.Sprintf("，用户=%q", username)
	}
	if isSynoNoSuchGroupError(err) {
		detail += "。DSM 返回 0x1800，含义是群组不存在；如果这是创建群组阶段，通常是因为 synogroup CLI 不支持不带成员创建空群组"
	}
	if isSynoGroupMemberPresent(err, groupname, username) {
		detail += "。DSM 输出里已经包含该成员，说明目标成员关系已存在，但 synogroup 仍返回了非 0 退出码"
	}
	return detail + "。原始错误：" + err.Error()
}

func assertAllowed(cfg config.HelperConfig, username string) error {
	if strings.ContainsAny(username, "\\/:*?\"<>|[];=,+") {
		return errors.New("invalid DSM username")
	}
	return nil
}

func run(name string, args ...string) error {
	_, err := runOutput(name, args...)
	return err
}

func runOutput(name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), errors.New(strings.TrimSpace(string(output)) + ": " + err.Error())
	}
	return string(output), nil
}

func errorResponse(code, message string) map[string]any {
	return map[string]any{"success": false, "error_code": code, "error": message}
}
