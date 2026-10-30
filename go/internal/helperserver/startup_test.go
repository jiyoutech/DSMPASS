package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

func startRecoveryTestServer(t *testing.T, cfg config.HelperConfig) (*Server, helperclient.UnixSocketClient) {
	t.Helper()
	cfg.SocketPath = shortSocketPath(t)
	cfg.TimestampSkewSeconds = 60
	s := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("server stopped unexpectedly: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server recovery worker did not stop")
		}
	})
	waitForSocket(t, cfg.SocketPath)
	return s, helperclient.UnixSocketClient{SocketPath: cfg.SocketPath, Secret: cfg.HMACSecret, Timeout: time.Second}
}

func awaitStartupHealth(t *testing.T, c helperclient.UnixSocketClient, predicate func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		health, err := c.HealthCheck(context.Background())
		if err != nil {
			t.Fatalf("startup health must remain responsive: %v", err)
		}
		if predicate(health) {
			return health
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("startup state did not progress")
	return nil
}

func TestHealthRemainsAvailableBeyondOldControllerStartupDeadline(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	if _, err := prepareBrowserLogin(cfg, "legacy-active", "alice"); err != nil {
		t.Fatal(err)
	}
	// Recreate the old flat layout, including an outstanding temporary password.
	if err := os.Remove(filepath.Join(cfg.JournalDir, "layout-v1")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(cfg.JournalDir, "active-index")); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(journal{RequestID: "legacy-done", DSMUsername: "bob", Status: "restored"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.JournalDir, "legacy-done.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := openLockFile(filepath.Join(cfg.JournalDir, "layout.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	s, client := startRecoveryTestServer(t, cfg)
	// Simulate disk migration held up longer than the deployed controller's
	// ten-second deadline, without depending on the test machine's disk speed.
	deadline := time.Now().Add(11 * time.Second)
	for time.Now().Before(deadline) {
		health, err := client.HealthCheck(context.Background())
		if err != nil || health["success"] != true || health["startup_ready"] != false || health["version"] != buildinfo.Version || health["revision"] != buildinfo.Revision {
			t.Fatalf("liveness failed during migration: %v, %#v", err, health)
		}
		response := s.handlePayload(signedPayload(t, cfg.HMACSecret, map[string]any{"action": "complete_browser_login", "request_id": "legacy-active"}))
		if response["error_code"] != "HELPER_INITIALIZING" {
			t.Fatalf("password operation entered during migration: %#v", response)
		}
		time.Sleep(time.Second)
	}
	if line, err := shadowLine(cfg.ShadowPath, "alice"); err != nil || line == original {
		t.Fatalf("password changed before migration finished: %v", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	health := awaitStartupHealth(t, client, func(h map[string]any) bool { return h["startup_ready"] == true })
	if health["startup_error"] != "" {
		t.Fatal("startup error was not cleared after successful retry")
	}
	if line, err := shadowLine(cfg.ShadowPath, "alice"); err != nil || line != original {
		t.Fatalf("writes enabled before original password recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.JournalDir, "completed", "legacy-done.json")); err != nil {
		t.Fatalf("legacy completed journal not archived: %v", err)
	}
	response := s.handlePayload(signedPayload(t, cfg.HMACSecret, map[string]any{"action": "complete_browser_login", "request_id": "legacy-active"}))
	if response["success"] != true {
		t.Fatalf("idempotent callback did not resume: %#v", response)
	}
}

func TestStartupRetriesUnidentifiableLegacyJournalWithoutRestart(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	if err := os.MkdirAll(cfg.JournalDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.JournalDir, "legacy-bad.json")
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	_, client := startRecoveryTestServer(t, cfg)
	awaitStartupHealth(t, client, func(h map[string]any) bool {
		message, _ := h["startup_error"].(string)
		return h["startup_ready"] == false && strings.Contains(message, "no trustworthy account identity")
	})
	if data, err := os.ReadFile(path); err != nil || string(data) != "broken" {
		t.Fatal("unidentified recovery evidence changed")
	}
	data, err := json.Marshal(journal{RequestID: "legacy-bad", DSMUsername: "alice", Status: "restored"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomically(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	awaitStartupHealth(t, client, func(h map[string]any) bool { return h["startup_ready"] == true && h["startup_error"] == "" })
}

func TestStartupRecoveryKeepsCorruptionScopedToItsAccount(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	bobBefore, err := shadowLine(cfg.ShadowPath, "bob")
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"alice", "bob"} {
		if _, err := prepareBrowserLogin(cfg, username+"-active", username); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cfg.JournalDir, "alice-active.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	_, client := startRecoveryTestServer(t, cfg)
	awaitStartupHealth(t, client, func(h map[string]any) bool { return h["startup_ready"] == true })
	if _, _, err := browserLeaseForUser(cfg, "alice"); err == nil {
		t.Fatal("damaged account allowed to proceed")
	}
	if line, err := shadowLine(cfg.ShadowPath, "bob"); err != nil || line != bobBefore {
		t.Fatalf("healthy account was not recovered: %v", err)
	}
	if _, found, err := browserLeaseForUser(cfg, "bob"); err != nil || found {
		t.Fatalf("unrelated account blocked after startup: %v", err)
	}
}

func TestInitializingHelperAuthenticatesAndBlocksEveryNonHealthAction(t *testing.T) {
	s := New(config.HelperConfig{HMACSecret: "test-secret", TimestampSkewSeconds: 60})
	s.setStartupState(true, nil)
	if response := s.handlePayload(map[string]any{"action": "health_check"}); response["error_code"] != "BAD_SIGNATURE" {
		t.Fatalf("startup bypassed authentication: %#v", response)
	}
	for _, action := range []string{"scoped_relay_login", "scoped_prepare_browser_login", "complete_browser_login", "scoped_reset_synced_user_password", "scoped_provision_user", "scoped_disable_user", "scoped_provision_group", "scoped_add_group_member", "scoped_remove_group_member", "", "unknown"} {
		response := s.handlePayload(signedPayload(t, s.cfg.HMACSecret, map[string]any{"action": action}))
		if response["error_code"] != "HELPER_INITIALIZING" {
			t.Fatalf("action %q passed startup gate: %#v", action, response)
		}
	}
	payload := signedPayload(t, s.cfg.HMACSecret, map[string]any{"action": "health_check"})
	if response := s.handlePayload(payload); response["success"] != true || response["startup_ready"] != false {
		t.Fatalf("authenticated health unavailable: %#v", response)
	}
	if response := s.handlePayload(payload); response["error_code"] != "REPLAY_REJECTED" {
		t.Fatalf("startup bypassed replay protection: %#v", response)
	}
}
