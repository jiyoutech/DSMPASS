package helperserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestRemoveStaleSocketRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := removeStaleSocket(dir); err == nil {
		t.Fatal("expected directory removal to be rejected")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory should remain: %v", err)
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

func TestReservedDSMNamesAreRejectedAtHelperBoundary(t *testing.T) {
	for _, username := range []string{"admin", "ROOT", "Administrator", "administrators"} {
		if err := assertAllowed(config.HelperConfig{}, username); err == nil {
			t.Errorf("username %q should be rejected", username)
		}
	}
	for _, groupname := range []string{"admin", "root", "administrator", "Administrators"} {
		if err := assertAllowedGroup(groupname); err == nil {
			t.Errorf("group name %q should be rejected", groupname)
		}
	}
	if err := assertAllowed(config.HelperConfig{}, "alice"); err != nil {
		t.Fatalf("normal username rejected: %v", err)
	}
	if err := assertAllowedGroup("engineering"); err != nil {
		t.Fatalf("normal group name rejected: %v", err)
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

func TestAddGroupMemberRejectsMissingDSMUser(t *testing.T) {
	dir := t.TempDir()
	synouserPath := filepath.Join(dir, "synouser")
	synogroupPath := filepath.Join(dir, "synogroup")
	groupCalledPath := filepath.Join(dir, "group-called")
	if err := os.WriteFile(synouserPath, []byte("#!/bin/sh\necho 'SYNOUserGet failed, synoerr=[0x1D00]' >&2\nexit 255\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(synogroupPath, []byte("#!/bin/sh\ntouch '"+groupCalledPath+"'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := "secret"
	server := New(config.HelperConfig{
		HMACSecret:           secret,
		TimestampSkewSeconds: 60,
		SynoUserPath:         synouserPath,
		SynoGroupPath:        synogroupPath,
	})

	response := server.handlePayload(signedPayload(t, secret, map[string]any{
		"action":        "add_group_member",
		"dsm_groupname": "engineering",
		"dsm_username":  "alice",
	}))

	if response["success"] != false || response["error_code"] != "SYNOUSER_MISSING" {
		t.Fatalf("unexpected response %#v", response)
	}
	if _, err := os.Stat(groupCalledPath); !os.IsNotExist(err) {
		t.Fatalf("synogroup should not be called when user is missing, stat err=%v", err)
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

func TestPrepareBrowserLoginRejectsConcurrentRequestForSameUser(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	countPath := filepath.Join(dir, "setpw-count")
	synouserPath := filepath.Join(dir, "synouser")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(original+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nprintf '%s\\n' '" + temporary + "' > '" + shadowPath + "'\n"
	if err := os.WriteFile(synouserPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := browserLoginTestConfig(shadowPath, journalDir, lockDir, synouserPath)

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, requestID := range []string{"request-a", "request-b"} {
		requestID := requestID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := prepareBrowserLogin(cfg, requestID, "alice")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	succeeded := 0
	rejected := 0
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errBrowserLoginInProgress):
			rejected++
		default:
			t.Fatalf("unexpected prepare error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent prepare results success=%d rejected=%d", succeeded, rejected)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "x" {
		t.Fatalf("synouser called %d times, content=%q", len(count), string(count))
	}
}

func TestPrepareBrowserLoginIsIdempotentForSameRequest(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	countPath := filepath.Join(dir, "setpw-count")
	synouserPath := filepath.Join(dir, "synouser")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(original+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nprintf '%s\\n' '" + temporary + "' > '" + shadowPath + "'\n"
	if err := os.WriteFile(synouserPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := browserLoginTestConfig(shadowPath, journalDir, lockDir, synouserPath)

	first, err := prepareBrowserLogin(cfg, "request-idempotent", "alice")
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareBrowserLogin(cfg, "request-idempotent", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if first.Username != second.Username || first.TempPassword != second.TempPassword || first.ExpiresAt != second.ExpiresAt {
		t.Fatalf("idempotent result changed: first=%#v second=%#v", first, second)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "x" {
		t.Fatalf("synouser called %d times, content=%q", len(count), string(count))
	}
	data, err := os.ReadFile(filepath.Join(journalDir, "request-idempotent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), first.TempPassword) || strings.Contains(string(data), `"temp_password"`) {
		t.Fatalf("journal leaked temporary password: %s", string(data))
	}
}

func TestRelayLoginRejectsActiveBrowserLeaseForSameUser(t *testing.T) {
	dir := t.TempDir()
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	cfg := config.HelperConfig{
		HMACSecret:     "journal-secret",
		JournalDir:     journalDir,
		LockDir:        lockDir,
		ShadowLockPath: filepath.Join(lockDir, "shadow.lock"),
	}
	original := "alice:$original:19000:0:99999:7:::"
	j := journal{
		RequestID:        "browser-request",
		DSMUsername:      "alice",
		Status:           journalStatusActiveBrowser,
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempPassword:     "temporary-password",
		TempLineHash:     lineHash("alice:$temporary:19000:0:99999:7:::"),
		ExpiresAt:        time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if _, err := relayLoginReal(cfg, "relay-request", "alice"); !errors.Is(err, errBrowserLoginInProgress) {
		t.Fatalf("expected relay login to be blocked, got %v", err)
	}
}

func TestRestorePendingJournalIsIdempotentUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(temporary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.HelperConfig{
		HMACSecret:     "journal-secret",
		JournalDir:     journalDir,
		LockDir:        lockDir,
		ShadowLockPath: filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:     shadowPath,
	}
	j := journal{
		RequestID:        "request-restore",
		DSMUsername:      "alice",
		Status:           journalStatusActiveBrowser,
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempPassword:     "temporary-password",
		TempLineHash:     lineHash(temporary),
		ExpiresAt:        time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- restorePendingJournal(cfg, j.RequestID, "test")
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent restore failed: %v", err)
		}
	}
	line, err := shadowLine(shadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if line != original {
		t.Fatalf("shadow line got %q want %q", line, original)
	}
	stored, err := loadJournal(cfg, j.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "restored" {
		t.Fatalf("journal status got %q want restored", stored.Status)
	}
	if stored.TempPassword != "" || stored.TempPasswordEncrypted != "" || stored.TempPasswordNonce != "" {
		t.Fatalf("restored journal retained temporary password material: %#v", stored)
	}
}

func browserLoginTestConfig(shadowPath, journalDir, lockDir, synouserPath string) config.HelperConfig {
	return config.HelperConfig{
		HMACSecret:                "journal-secret",
		JournalDir:                journalDir,
		LockDir:                   lockDir,
		ShadowLockPath:            filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:                shadowPath,
		SynoUserPath:              synouserPath,
		TempPasswordLength:        32,
		DSMBrowserLoginTTLSeconds: 3600,
	}
}

func TestRestoreIfCurrentMatchesAtomicallyReplacesShadowWithoutSedPatterns(t *testing.T) {
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
	if os.SameFile(before, after) {
		t.Fatalf("shadow restore did not atomically replace inode: before=%#v after=%#v", before, after)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("shadow permissions changed: before=%v after=%v", before.Mode().Perm(), after.Mode().Perm())
	}
}

func TestRestoreIfCurrentMatchesRejectsDuplicateUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	temporary := "alice:$temporary:19000:0:99999:7:::"
	original := "alice:$original:19000:0:99999:7:::"
	content := temporary + "\n" + temporary + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreIfCurrentMatches(path, "alice", original, temporary); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate-user rejection, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("shadow changed after duplicate rejection: %q", string(data))
	}
}

func TestRewriteShadowAtomicallyRejectsStaleSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow")
	current := []byte("alice:$current:19000:0:99999:7:::\n")
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}
	err := rewriteShadowAtomically(path, []byte("stale\n"), []byte("replacement\n"))
	if !errors.Is(err, errShadowChanged) {
		t.Fatalf("expected stale snapshot error, got %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != string(current) {
		t.Fatalf("shadow changed after stale snapshot: %q", string(data))
	}
}

func TestRestorePendingJournalPreservesExternalPasswordChange(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary:19000:0:99999:7:::"
	changed := "alice:$changed-by-user:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(changed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.HelperConfig{
		HMACSecret:     "journal-secret",
		JournalDir:     journalDir,
		LockDir:        lockDir,
		ShadowLockPath: filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:     shadowPath,
	}
	j := journal{
		RequestID:        "request-external-change",
		DSMUsername:      "alice",
		Status:           journalStatusActiveBrowser,
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempPassword:     "temporary-password",
		TempLineHash:     lineHash(temporary),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, j.RequestID, "expired"); err != nil {
		t.Fatal(err)
	}
	line, err := shadowLine(shadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if line != changed {
		t.Fatalf("external password change was overwritten: %q", line)
	}
	stored, err := loadJournal(cfg, j.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != journalStatusSuperseded {
		t.Fatalf("journal status got %q want %q", stored.Status, journalStatusSuperseded)
	}
	if stored.TempPasswordEncrypted != "" || stored.TempPasswordNonce != "" {
		t.Fatalf("superseded journal retained temporary password material: %#v", stored)
	}
	if _, found, err := browserLeaseForUser(cfg, "alice"); err != nil || found {
		t.Fatalf("superseded lease still blocked new login: found=%v err=%v", found, err)
	}
}

func TestRelayLoginPreservesPasswordChangedBeforeRestore(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	synouserPath := filepath.Join(dir, "synouser")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary:19000:0:99999:7:::"
	changed := "alice:$changed-before-restore:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(original+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' '" + temporary + "' > '" + shadowPath + "'\n"
	if err := os.WriteFile(synouserPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api") == "SYNO.API.Auth" {
			if err := os.WriteFile(shadowPath, []byte(changed+"\n"), 0o600); err != nil {
				http.Error(w, "failed to simulate external password change", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"relay-session"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"isLogined" : true}`))
	}))
	defer auth.Close()
	cfg := config.HelperConfig{
		HMACSecret:         "journal-secret",
		JournalDir:         journalDir,
		LockDir:            lockDir,
		ShadowLockPath:     filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:         shadowPath,
		SynoUserPath:       synouserPath,
		TempPasswordLength: 32,
		DSMLoginAPI:        auth.URL,
		DSMSession:         "webui",
		DSMTimeoutSeconds:  2,
	}
	if _, err := relayLoginReal(cfg, "relay-external-change", "alice"); err != nil {
		t.Fatal(err)
	}
	line, err := shadowLine(shadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if line != changed {
		t.Fatalf("external password change was overwritten: %q", line)
	}
	stored, err := loadJournal(cfg, "relay-external-change")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != journalStatusSuperseded {
		t.Fatalf("journal status got %q want %q", stored.Status, journalStatusSuperseded)
	}
}

func TestRelayLoginAllowsDifferentUsersToAuthenticateConcurrently(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	synouserPath := filepath.Join(dir, "synouser")
	synouserTempPath := filepath.Join(dir, "shadow-synouser-temp")
	aliceOriginal := "alice:$alice-original:19000:0:99999:7:::"
	bobOriginal := "bob:$bob-original:19000:0:99999:7:::"
	aliceTemporary := "alice:$alice-temporary:19000:0:99999:7:::"
	bobTemporary := "bob:$bob-temporary:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(aliceOriginal+"\n"+bobOriginal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"username=\"$2\"\n" +
		"case \"$username\" in\n" +
		"  alice) replacement='" + aliceTemporary + "' ;;\n" +
		"  bob) replacement='" + bobTemporary + "' ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n" +
		"awk -F: -v username=\"$username\" -v replacement=\"$replacement\" '$1 == username { print replacement; next } { print }' '" + shadowPath + "' > '" + synouserTempPath + "'\n" +
		"chmod 600 '" + synouserTempPath + "'\n" +
		"mv '" + synouserTempPath + "' '" + shadowPath + "'\n"
	if err := os.WriteFile(synouserPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	authArrivals := make(chan string, 2)
	releaseAuth := make(chan struct{})
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api") != "SYNO.API.Auth" {
			_, _ = w.Write([]byte(`{"isLogined" : true}`))
			return
		}
		account := r.URL.Query().Get("account")
		authArrivals <- account
		<-releaseAuth
		_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"relay-session-` + account + `"}}`))
	}))
	defer auth.Close()
	cfg := config.HelperConfig{
		HMACSecret:         "journal-secret",
		JournalDir:         journalDir,
		LockDir:            lockDir,
		ShadowLockPath:     filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:         shadowPath,
		SynoUserPath:       synouserPath,
		TempPasswordLength: 32,
		DSMLoginAPI:        auth.URL,
		DSMSession:         "webui",
		DSMTimeoutSeconds:  2,
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, username := range []string{"alice", "bob"} {
		username := username
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := relayLoginReal(cfg, "relay-"+username, username)
			errs <- err
		}()
	}
	close(start)

	seen := map[string]bool{}
	overlapped := true
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

waitForAuthentication:
	for len(seen) < 2 {
		select {
		case username := <-authArrivals:
			seen[username] = true
		case <-timer.C:
			overlapped = false
			break waitForAuthentication
		}
	}
	close(releaseAuth)

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("parallel relay login failed: %v", err)
		}
	}
	if !overlapped {
		t.Fatal("different users did not reach DSM authentication concurrently")
	}
	if !seen["alice"] || !seen["bob"] {
		t.Fatalf("unexpected DSM authentication arrivals: %#v", seen)
	}
	data, err := os.ReadFile(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	want := aliceOriginal + "\n" + bobOriginal + "\n"
	if string(data) != want {
		t.Fatalf("shadow content got %q want %q", string(data), want)
	}
	for _, requestID := range []string{"relay-alice", "relay-bob"} {
		stored, err := loadJournal(cfg, requestID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Status != "restored" {
			t.Fatalf("journal %s status got %q want restored", requestID, stored.Status)
		}
	}
}

func TestRestorePendingJournalVerifiesTempPasswordWhenHashWasNotSaved(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary-after-setpw:19000:0:99999:7:::"
	tempPassword := "known-temporary-password"
	if err := os.WriteFile(shadowPath, []byte(temporary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("account") != "alice" || r.URL.Query().Get("passwd") != tempPassword {
			http.Error(w, "unexpected recovery credentials", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"recovery-session"}}`))
	}))
	defer auth.Close()
	cfg := config.HelperConfig{
		HMACSecret:        "journal-secret",
		JournalDir:        journalDir,
		LockDir:           lockDir,
		ShadowLockPath:    filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:        shadowPath,
		DSMLoginAPI:       auth.URL,
		DSMSession:        "webui",
		DSMTimeoutSeconds: 2,
	}
	j := journal{
		RequestID:        "request-interrupted-after-setpw",
		DSMUsername:      "alice",
		Status:           journalStatusPendingBrowser,
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempPassword:     tempPassword,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, j.RequestID, "startup"); err != nil {
		t.Fatal(err)
	}
	line, err := shadowLine(shadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if line != original {
		t.Fatalf("interrupted temporary password was not restored: %q", line)
	}
	stored, err := loadJournal(cfg, j.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "restored" {
		t.Fatalf("journal status got %q want restored", stored.Status)
	}
}

func TestRestorePendingJournalPreservesPasswordChangedDuringVerification(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	original := "alice:$original:19000:0:99999:7:::"
	temporary := "alice:$temporary-after-setpw:19000:0:99999:7:::"
	changed := "alice:$changed-during-verification:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(temporary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := os.WriteFile(shadowPath, []byte(changed+"\n"), 0o600); err != nil {
			http.Error(w, "failed to simulate external password change", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"recovery-session"}}`))
	}))
	defer auth.Close()
	cfg := config.HelperConfig{
		HMACSecret:        "journal-secret",
		JournalDir:        journalDir,
		LockDir:           lockDir,
		ShadowLockPath:    filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:        shadowPath,
		DSMLoginAPI:       auth.URL,
		DSMSession:        "webui",
		DSMTimeoutSeconds: 2,
	}
	j := journal{
		RequestID:        "request-change-during-verification",
		DSMUsername:      "alice",
		Status:           journalStatusPendingBrowser,
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempPassword:     "temporary-password",
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, j.RequestID, "startup"); err != nil {
		t.Fatal(err)
	}
	line, err := shadowLine(shadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if line != changed {
		t.Fatalf("password changed during verification was overwritten: %q", line)
	}
	stored, err := loadJournal(cfg, j.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != journalStatusSuperseded {
		t.Fatalf("journal status got %q want %q", stored.Status, journalStatusSuperseded)
	}
}

func TestRestorePendingJournalFailsClosedWhenTempPasswordCannotBeVerified(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	original := "alice:$original:19000:0:99999:7:::"
	unknown := "alice:$unknown-current-password:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(unknown+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":400}}`))
	}))
	defer auth.Close()
	cfg := config.HelperConfig{
		HMACSecret:        "journal-secret",
		JournalDir:        journalDir,
		LockDir:           lockDir,
		ShadowLockPath:    filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:        shadowPath,
		DSMLoginAPI:       auth.URL,
		DSMSession:        "webui",
		DSMTimeoutSeconds: 2,
	}
	j := journal{
		RequestID:        "request-unresolved",
		DSMUsername:      "alice",
		Status:           journalStatusPendingBrowser,
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		TempPassword:     "temporary-password",
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, j.RequestID, "startup"); !errors.Is(err, errBrowserLoginUnresolved) {
		t.Fatalf("expected unresolved recovery, got %v", err)
	}
	line, err := shadowLine(shadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if line != unknown {
		t.Fatalf("unverified current password was overwritten: %q", line)
	}
	stored, err := loadJournal(cfg, j.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != journalStatusUnresolvedBrowser {
		t.Fatalf("journal status got %q want %q", stored.Status, journalStatusUnresolvedBrowser)
	}
	if _, found, err := browserLeaseForUser(cfg, "alice"); err != nil || !found {
		t.Fatalf("unresolved lease did not block new login: found=%v err=%v", found, err)
	}
}

func TestRestorePendingJournalResolvesLegacyFailedJournalAlreadyRestored(t *testing.T) {
	dir := t.TempDir()
	shadowPath := filepath.Join(dir, "shadow")
	journalDir := filepath.Join(dir, "journal")
	lockDir := filepath.Join(dir, "locks")
	original := "alice:$original:19000:0:99999:7:::"
	if err := os.WriteFile(shadowPath, []byte(original+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.HelperConfig{
		HMACSecret:     "journal-secret",
		JournalDir:     journalDir,
		LockDir:        lockDir,
		ShadowLockPath: filepath.Join(lockDir, "shadow.lock"),
		ShadowPath:     shadowPath,
	}
	j := journal{
		RequestID:        "legacy-failed-request",
		DSMUsername:      "alice",
		Status:           "failed",
		OriginalLine:     original,
		OriginalLineHash: lineHash(original),
		CreatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, j.RequestID, "startup"); err != nil {
		t.Fatal(err)
	}
	stored, err := loadJournal(cfg, j.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "restored" {
		t.Fatalf("legacy journal status got %q want restored", stored.Status)
	}
}

func TestRewriteShadowAtomicallyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-shadow")
	linkPath := filepath.Join(dir, "shadow")
	content := []byte("alice:$current:19000:0:99999:7:::\n")
	if err := os.WriteFile(realPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if err := rewriteShadowAtomically(linkPath, content, []byte("replacement\n")); err == nil {
		t.Fatal("expected symlink replacement to be rejected")
	}
	data, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(content) {
		t.Fatalf("symlink target changed: %q", string(data))
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
	payload["timestamp"] = float64(time.Now().Unix())
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

func signedPayload(t *testing.T, secret string, payload map[string]any) map[string]any {
	t.Helper()
	payload["timestamp"] = float64(time.Now().Unix())
	payload["nonce"] = time.Now().Format(time.RFC3339Nano)
	signature, err := signing.Sign(payload, secret)
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = signature
	return payload
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
