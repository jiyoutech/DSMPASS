package helperclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/signing"
)

func TestUnixSocketClientHealthCheck(t *testing.T) {
	socketPath := shortSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if isSocketSandboxError(err) {
			t.Skipf("unix socket bind blocked by sandbox: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadBytes('\n')
		if err != nil {
			return
		}
		var payload map[string]any
		_ = json.Unmarshal(line, &payload)
		if signing.Verify(payload, "secret", 60) != nil {
			_ = json.NewEncoder(conn).Encode(map[string]any{"success": false})
			return
		}
		_ = json.NewEncoder(conn).Encode(map[string]any{"success": true, "version": "test"})
	}()

	client := UnixSocketClient{SocketPath: socketPath, Secret: "secret", Timeout: time.Second}
	response, err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response["version"] != "test" {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestUnixSocketClientIncludesHelperErrorMessage(t *testing.T) {
	socketPath := shortSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if isSocketSandboxError(err) {
			t.Skipf("unix socket bind blocked by sandbox: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadBytes('\n')
		_ = json.NewEncoder(conn).Encode(map[string]any{
			"success":    false,
			"error_code": "SYNOUSER_FAILED",
			"error":      "user already exists",
		})
	}()

	client := UnixSocketClient{SocketPath: socketPath, Secret: "secret", Timeout: time.Second}
	_, err = client.ProvisionUser(context.Background(), "req", "user_0001", "User", "", "123456")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "SYNOUSER_FAILED: user already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnixSocketClientDiagnosticsRedactsRawResponse(t *testing.T) {
	socketPath := shortSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if isSocketSandboxError(err) {
			t.Skipf("unix socket bind blocked by sandbox: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadBytes('\n')
		_ = json.NewEncoder(conn).Encode(map[string]any{
			"success": true,
			"sid":     "sid-secret-value",
			"cookies": []map[string]any{
				{"name": "id", "value": "cookie-secret-value", "path": "/"},
			},
		})
	}()

	dataDir := t.TempDir()
	client := UnixSocketClient{SocketPath: socketPath, Secret: "secret", Timeout: time.Second, DataDir: dataDir, DiagnosticsEnabled: true}
	result, err := client.RelayLogin(context.Background(), "req-raw", "user_0001", "identity-1", "source-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.SID != "sid-secret-value" {
		t.Fatalf("unexpected sid: %q", result.SID)
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, "login-diagnostics.log"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	for _, leaked := range []string{"sid-secret-value", "cookie-secret-value"} {
		if strings.Contains(line, leaked) {
			t.Fatalf("diagnostic log leaked %q: %s", leaked, line)
		}
	}
	for _, want := range []string{
		"raw_response=",
		`"sid":"[REDACTED]"`,
		`"cookies":"[REDACTED]"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("diagnostic log missing %q: %s", want, line)
		}
	}
}

func TestUnixSocketClientDiagnosticsDoesNotLogInvalidRawResponse(t *testing.T) {
	socketPath := shortSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if isSocketSandboxError(err) {
			t.Skipf("unix socket bind blocked by sandbox: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadBytes('\n')
		_, _ = conn.Write([]byte(`{"success":true,"sid":"sid-secret-value"` + "\n"))
	}()

	dataDir := t.TempDir()
	client := UnixSocketClient{SocketPath: socketPath, Secret: "secret", Timeout: time.Second, DataDir: dataDir, DiagnosticsEnabled: true}
	_, err = client.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected decode error")
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, "login-diagnostics.log"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	if strings.Contains(line, "sid-secret-value") {
		t.Fatalf("diagnostic log leaked invalid raw response: %s", line)
	}
	for _, want := range []string{
		`"valid_json":false`,
		`"bytes":`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("diagnostic log missing %q: %s", want, line)
		}
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dsmrelay-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, "h.sock")
}

func isSocketSandboxError(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted")
}
