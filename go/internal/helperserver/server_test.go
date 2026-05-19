package helperserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/signing"
)

func TestHelperHealthCheck(t *testing.T) {
	socketPath := shortSocketPath(t)
	server := New(config.HelperConfig{
		SocketPath:           socketPath,
		HMACSecret:           "secret",
		TimestampSkewSeconds: 60,
	})
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve()
	}()
	skipIfSocketServeBlocked(t, errCh)
	waitForSocket(t, socketPath)

	response := send(t, socketPath, "secret", map[string]any{"action": "health_check"})
	if response["success"] != true {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestSynouserAddArgsMatchDSM(t *testing.T) {
	args := synouserAddArgs("zhangwei_1234", "secret", "张伟", "zhangwei@example.test")
	want := []string{"--add", "zhangwei_1234", "secret", "张伟", "0", "zhangwei@example.test", ""}
	if len(args) != len(want) {
		t.Fatalf("arg length got %d want %d: %#v", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d got %q want %q: %#v", i, args[i], want[i], args)
		}
	}
}

func TestParseSynoUserInfo(t *testing.T) {
	info := parseSynoUserInfo(`User Name   : [zay]
User Type   : [AUTH_LOCAL]
Fullname    : [zay]
Expired     : [false]
User Mail   : [zay@example.test]`)
	if info.FullName != "zay" || info.Mail != "zay@example.test" || info.Expired {
		t.Fatalf("unexpected user info: %#v", info)
	}
	expired := parseSynoUserInfo("Expired     : [true]")
	if !expired.Expired {
		t.Fatalf("expected expired user: %#v", expired)
	}
}

func TestSynoNoSuchGroupErrorIsRecognized(t *testing.T) {
	err := errors.New("Lastest SynoErr=[group_db_get.c:26]\nSYNOGroupGet failed, synoerr=0x1800: exit status 255")
	if !isSynoNoSuchGroupError(err) {
		t.Fatalf("expected no such group error to be recognized")
	}
	message := synoGroupError("create", "Engineering", "", err)
	if !strings.Contains(message, "DSM 返回 0x1800") || !strings.Contains(message, "群组不存在") {
		t.Fatalf("unexpected message: %s", message)
	}
}

func TestSynoGroupMemberPresentErrorIsIdempotentSuccess(t *testing.T) {
	err := errors.New("Group Name: [group] Group Type: [AUTH_LOCAL] Group ID: [65536] Group Members: 0:[user_0598] 1:[user_4782]: exit status 1")
	if !isSynoGroupMemberPresent(err, "group", "user_4782") {
		t.Fatalf("expected member-present output to be recognized")
	}
	if isSynoGroupMemberPresent(err, "group", "user_0000") {
		t.Fatalf("unexpected member-present match")
	}
	message := synoGroupError("add_member", "group", "user_4782", err)
	if !strings.Contains(message, "目标成员关系已存在") {
		t.Fatalf("unexpected message: %s", message)
	}
}

func TestDSMHTTPClientCanSkipTLSVerification(t *testing.T) {
	client := dsmHTTPClient(config.HelperConfig{
		DSMLoginAPI:       "https://192.0.2.10:5001/webapi/entry.cgi",
		DSMTimeoutSeconds: 5,
		DSMTLSSkipVerify:  true,
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected insecure TLS transport, got %#v", client.Transport)
	}
}

func TestDSMHTTPClientDoesNotSkipTLSVerificationByDefault(t *testing.T) {
	client := dsmHTTPClient(config.HelperConfig{
		DSMLoginAPI:       "https://192.0.2.10:5001/webapi/entry.cgi",
		DSMTimeoutSeconds: 5,
	})
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("unexpected insecure TLS transport: %#v", transport.TLSClientConfig)
	}
}

func TestDSMHTTPClientStillSkipsLoopbackTLSVerification(t *testing.T) {
	client := dsmHTTPClient(config.HelperConfig{
		DSMLoginAPI:       "https://127.0.0.1:5001/webapi/entry.cgi",
		DSMTimeoutSeconds: 5,
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("expected loopback insecure TLS transport, got %#v", client.Transport)
	}
	if transport.TLSClientConfig.MinVersion != 0 {
		t.Fatalf("unexpected tls config mutation: %#v", transport.TLSClientConfig)
	}
}

func TestSaveJournalEncryptsOriginalShadowLine(t *testing.T) {
	dir := t.TempDir()
	cfg := config.HelperConfig{JournalDir: dir, HMACSecret: "journal-secret"}
	original := "alice:$y$j9T$hash-with-secret:19000:0:99999:7:::"
	j := journal{
		RequestID:        "request-1",
		DSMUsername:      "alice",
		Status:           "pending",
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempLineHash:     "temp-hash",
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "request-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), original) || strings.Contains(string(data), "original_line\"") {
		t.Fatalf("journal leaked original shadow line: %s", string(data))
	}
	var stored journal
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	decrypted, err := stored.decryptedOriginalLine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != original {
		t.Fatalf("decrypted original line got %q want %q", decrypted, original)
	}
}

func TestRestoreIfCurrentMatchesRewritesShadowWithoutSedPatterns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	original := "alice:$y$j9T$abc#def&ghi\\jkl:19000:0:99999:7:::"
	temp := "alice:$y$j9T$temp#def&ghi\\jkl:19000:0:99999:7:::"
	other := "bob:$y$j9T$unchanged:19000:0:99999:7:::"
	if err := os.WriteFile(path, []byte(temp+"\n"+other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreIfCurrentMatches(path, "alice", original, temp); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := original + "\n" + other + "\n"
	if string(data) != want {
		t.Fatalf("shadow content got %q want %q", string(data), want)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatalf("shadow restore changed inode: before=%#v after=%#v", before, after)
	}
}

func TestRedactedURLHidesDSMLoginSecrets(t *testing.T) {
	raw := "https://nas.example.com/webapi/entry.cgi?account=alice&passwd=temp-secret&otp_code=123456&device_id=device-secret"
	got := redactedURL(raw, "passwd", "otp_code", "device_id")
	for _, leaked := range []string{"temp-secret", "123456", "device-secret"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted URL leaked %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "account=alice") {
		t.Fatalf("redacted URL lost non-sensitive fields: %s", got)
	}
}

func send(t *testing.T, socketPath, secret string, payload map[string]any) map[string]any {
	t.Helper()
	payload["timestamp"] = time.Now().Unix()
	payload["nonce"] = time.Now().Format(time.RFC3339Nano)
	signature, err := signing.Sign(payload, secret)
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = signature
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("unix", path)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket did not appear: %s", path)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := osWriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

var osWriteFile = func(name string, data []byte, perm uint32) error {
	return os.WriteFile(name, data, os.FileMode(perm))
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

func skipIfSocketServeBlocked(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if isSocketSandboxError(err) {
			t.Skipf("unix socket bind blocked by sandbox: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Millisecond):
	}
}

func isSocketSandboxError(err error) bool {
	return err != nil && (errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "operation not permitted"))
}
