//go:build dsm_integration && linux

package helperserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

const (
	dsmIntegrationShadowPath   = "/etc/shadow"
	dsmIntegrationSynouserPath = "/usr/syno/sbin/synouser"
	dsmIntegrationSMBClient    = "/var/packages/SMBService/target/usr/bin/smbclient"
	dsmIntegrationPDBEdit      = "/var/packages/SMBService/target/usr/bin/pdbedit"
)

type dsmShadowSnapshot struct {
	data   []byte
	mode   os.FileMode
	uid    uint32
	gid    uint32
	xattrs map[string][]byte
}

type dsmRelayOutcome struct {
	result relayLoginResult
	err    error
}

func TestDSMRealShadowConcurrentRelayAndRecovery(t *testing.T) {
	if os.Getenv("DSMPASS_DSM_INTEGRATION") != "1" {
		t.Skip("set DSMPASS_DSM_INTEGRATION=1 to run against a DSM host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("DSM shadow integration test must run as root")
	}
	version, err := os.ReadFile("/etc.defaults/VERSION")
	if err != nil || !bytes.Contains(version, []byte(`os_name="DSM"`)) {
		t.Fatalf("refusing to run outside DSM: %v", err)
	}
	if _, err := os.Stat(dsmIntegrationSynouserPath); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{dsmIntegrationSMBClient, dsmIntegrationPDBEdit, "/usr/bin/openssl"} {
		if _, err := os.Stat(command); err != nil {
			t.Fatalf("required DSM integration command is unavailable: %s", command)
		}
	}

	suffix := fmt.Sprintf("%x", uint64(time.Now().UnixNano())&0xffffff)
	users := []struct {
		name     string
		password string
	}{
		{name: "dsmpass_it_a_" + suffix, password: randomPassword(48)},
		{name: "dsmpass_it_b_" + suffix, password: randomPassword(48)},
	}
	for _, user := range users {
		if _, err := getSynoUser(dsmIntegrationSynouserPath, user.name); err == nil {
			t.Fatalf("refusing to modify an existing test username: %s", user.name)
		}
		if err := run(dsmIntegrationSynouserPath, synouserAddArgs(user.name, user.password, "DSMPASS integration test", "")...); err != nil {
			t.Fatalf("create DSM integration user %s: %v", user.name, err)
		}
		username := user.name
		t.Cleanup(func() {
			if err := run(dsmIntegrationSynouserPath, "--del", username); err != nil {
				t.Errorf("remove DSM integration user %s: %v", username, err)
			}
		})
	}
	smbBefore := map[string]string{}
	for _, user := range users {
		assertDSMSMBLogin(t, user.name, user.password)
		smbBefore[user.name] = readDSMTestSMBRecord(t, user.name)
	}

	before, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertValidDSMShadow(t, before.data)

	dir, err := os.MkdirTemp("/tmp", "dsmpass-shadow-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := config.HelperConfig{
		HMACSecret:                randomPassword(64),
		JournalDir:                filepath.Join(dir, "journal"),
		LockDir:                   filepath.Join(dir, "locks"),
		ShadowLockPath:            filepath.Join(dir, "locks", "shadow.lock"),
		ShadowPath:                dsmIntegrationShadowPath,
		SynoUserPath:              dsmIntegrationSynouserPath,
		OpenSSLPath:               "/usr/bin/openssl",
		TempPasswordLength:        64,
		DSMLoginAPI:               "https://127.0.0.1:5001/webapi/entry.cgi",
		DSMSession:                "webui",
		DSMTimeoutSeconds:         10,
		DSMTLSSkipVerify:          true,
		DSMBrowserLoginTTLSeconds: 3600,
	}
	// Recover pending leases before deleting test accounts or their journals,
	// including when an assertion terminates the test early.
	t.Cleanup(func() {
		if err := recoverPending(cfg); err != nil {
			t.Errorf("recover pending integration leases: %v", err)
		}
	})

	start := make(chan struct{})
	outcomes := make(chan dsmRelayOutcome, len(users))
	var wg sync.WaitGroup
	for _, user := range users {
		user := user
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := relayLoginReal(cfg, "dsm-integration-relay-"+user.name, user.name)
			outcomes <- dsmRelayOutcome{result: result, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)
	for outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("concurrent DSM relay login: %v", outcome.err)
		}
		registerDSMSessionCleanup(t, cfg, outcome.result.SID)
		assertDSMDesktopSession(t, cfg, outcome.result)
	}

	afterConcurrentRelay, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, before, afterConcurrentRelay)
	for _, user := range users {
		assertDSMSMBUnchanged(t, user.name, user.password, smbBefore[user.name])
		result, err := dsmLogin(cfg, "dsm-integration-password-check-"+user.name, user.name, user.password)
		if err != nil {
			t.Fatalf("original password was not restored for %s: %v", user.name, err)
		}
		registerDSMSessionCleanup(t, cfg, result.SID)
	}
	t.Log("concurrent server relay: DSM original passwords and SMB credentials preserved")

	requestID := "dsm-integration-recovery-" + users[0].name
	browser, err := prepareBrowserLogin(cfg, requestID, users[0].name)
	if err != nil {
		t.Fatalf("prepare interrupted DSM lease: %v", err)
	}
	for _, user := range users {
		assertDSMSMBUnchanged(t, user.name, user.password, smbBefore[user.name])
	}
	result, err := dsmLogin(cfg, "dsm-integration-browser-auth", users[0].name, browser.TempPassword)
	if err != nil {
		t.Fatalf("DSM rejected the shadow-only temporary password: %v", err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	t.Log("active browser lease: temporary DSM authentication succeeded; original SMB passwords still work")
	duringLease, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertValidDSMShadow(t, duringLease.data)
	if bytes.Equal(duringLease.data, before.data) {
		t.Fatal("temporary DSM password lease did not change shadow")
	}
	if err := recoverPending(cfg); err != nil {
		t.Fatalf("restore interrupted DSM lease: %v", err)
	}
	afterRecovery, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, before, afterRecovery)
	assertDSMDesktopSession(t, cfg, result)
	result, err = dsmLogin(cfg, "dsm-integration-recovery-password-check", users[0].name, users[0].password)
	if err != nil {
		t.Fatalf("original password was not restored after recovery: %v", err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	assertDSMSMBUnchanged(t, users[0].name, users[0].password, smbBefore[users[0].name])
	t.Log("startup recovery: original shadow and SMB credentials preserved")

	ttlCfg := cfg
	ttlCfg.DSMBrowserLoginTTLSeconds = 1
	ttlRequest := "dsm-integration-ttl-" + users[1].name
	if _, err := prepareBrowserLogin(ttlCfg, ttlRequest, users[1].name); err != nil {
		t.Fatal(err)
	}
	assertDSMSMBUnchanged(t, users[1].name, users[1].password, smbBefore[users[1].name])
	deadline := time.Now().Add(5 * time.Second)
	for {
		j, err := loadJournal(cfg, ttlRequest)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status == "restored" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DSM browser lease was not restored after TTL")
		}
		time.Sleep(25 * time.Millisecond)
	}
	afterTTL, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, before, afterTTL)
	assertDSMSMBUnchanged(t, users[1].name, users[1].password, smbBefore[users[1].name])
	t.Log("TTL recovery: original shadow and SMB credentials preserved")

	changeRequest := "dsm-integration-external-change-" + users[1].name
	if _, err := prepareBrowserLogin(cfg, changeRequest, users[1].name); err != nil {
		t.Fatal(err)
	}
	changedPassword := randomPassword(48)
	if err := run(dsmIntegrationSynouserPath, "--setpw", users[1].name, changedPassword); err != nil {
		t.Fatalf("change isolated test user's password during the lease: %v", err)
	}
	changedShadow, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	changedSMB := readDSMTestSMBRecord(t, users[1].name)
	if err := restorePendingJournal(cfg, changeRequest, "browser_login_complete"); err != nil {
		t.Fatal(err)
	}
	j, err := loadJournal(cfg, changeRequest)
	if err != nil || j.Status != journalStatusSuperseded {
		t.Fatalf("external password change was not preserved: %v", err)
	}
	afterChange, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, changedShadow, afterChange)
	assertDSMSMBUnchanged(t, users[1].name, changedPassword, changedSMB)
	t.Log("external password change during a lease: new DSM/SMB credentials preserved")

	completeRequest := "dsm-integration-complete-" + users[1].name
	browser, err = prepareBrowserLogin(cfg, completeRequest, users[1].name)
	if err != nil {
		t.Fatal(err)
	}
	assertDSMSMBUnchanged(t, users[1].name, changedPassword, changedSMB)
	result, err = dsmLogin(cfg, "dsm-integration-after-user-change", users[1].name, browser.TempPassword)
	if err != nil {
		t.Fatal(err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	if err := restorePendingJournal(cfg, completeRequest, "browser_login_complete"); err != nil {
		t.Fatal(err)
	}
	afterComplete, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, changedShadow, afterComplete)
	assertDSMSMBUnchanged(t, users[1].name, changedPassword, changedSMB)
	assertDSMDesktopSession(t, cfg, result)
	result, err = dsmLogin(cfg, "dsm-integration-new-password-check", users[1].name, changedPassword)
	if err != nil {
		t.Fatalf("user's new password was not restored after a later login: %v", err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	t.Log("normal browser completion after user password change: DSM session remains valid and new SMB password works")

	// Reproduce the old setpw + shadow-only recovery bug on an isolated user,
	// then exercise the exact Helper action used by a full sync.
	originalLine, err := shadowLine(cfg.ShadowPath, users[0].name)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(cfg.SynoUserPath, "--setpw", users[0].name, randomPassword(48)); err != nil {
		t.Fatal(err)
	}
	brokenLine, err := shadowLine(cfg.ShadowPath, users[0].name)
	if err != nil {
		t.Fatal(err)
	}
	if err := withShadowWrite(cfg, func() error {
		return replaceShadowLineIfCurrentMatches(cfg.ShadowPath, users[0].name, originalLine, brokenLine)
	}); err != nil {
		t.Fatal(err)
	}
	if readDSMTestSMBRecord(t, users[0].name) == smbBefore[users[0].name] {
		t.Fatal("failed to reproduce legacy SMB mismatch")
	}
	repairPassword := randomPassword(48)
	repairHelper := NewWithStore(cfg, syncedPasswordTestStore(t, users[0].name))
	if _, err := repairHelper.store.DBTX().ExecContext(context.Background(), `UPDATE dsm_accounts SET managed = 0`); err != nil {
		t.Fatal(err)
	}
	if err := repairHelper.resetSyncedUserPassword(cfg, syncedPasswordPayload(users[0].name, repairPassword)); err != nil {
		t.Fatal(err)
	}
	assertDSMSMBLogin(t, users[0].name, repairPassword)
	result, err = dsmLogin(cfg, "full-sync-repair-password", users[0].name, repairPassword)
	if err != nil {
		t.Fatalf("DSM rejected full-sync password: %v", err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	repairedSMB := readDSMTestSMBRecord(t, users[0].name)
	result, err = relayLoginReal(cfg, "after-full-sync-repair", users[0].name)
	if err != nil {
		t.Fatal(err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
	assertDSMSMBUnchanged(t, users[0].name, repairPassword, repairedSMB)
	assertDSMSMBUnchanged(t, users[1].name, changedPassword, changedSMB)
	t.Log("full sync repaired legacy DSM/SMB mismatch; subsequent shadow-only login preserved the repaired password; other user unchanged")
}

func assertDSMDesktopSession(t *testing.T, cfg config.HelperConfig, result relayLoginResult) {
	t.Helper()
	values := url.Values{"api": {"SYNO.Core.Desktop.SessionData"}, "version": {"1"}, "method": {"getjs"}, "SynoToken": {""}}
	request, err := http.NewRequest(http.MethodGet, cfg.DSMLoginAPI+"?"+values.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range result.Cookies {
		if cookie.Name != "id" {
			request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	request.AddCookie(&http.Cookie{Name: "id", Value: result.SID})
	client := dsmHTTPClient(cfg)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil || response.StatusCode != http.StatusOK || !regexp.MustCompile(`"isLogined"\s*:\s*true`).Match(body) {
		t.Fatal("DSM desktop session is invalid after shadow restoration")
	}
}

func readDSMTestSMBRecord(t *testing.T, username string) string {
	t.Helper()
	output, err := exec.Command(dsmIntegrationPDBEdit, "-L", "-w", "-u", username).Output()
	if err != nil {
		t.Fatalf("read test user SMB record: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, username+":") {
			return line
		}
	}
	t.Fatal("test user SMB record is missing")
	return ""
}

func assertDSMSMBUnchanged(t *testing.T, username, password, before string) {
	t.Helper()
	if readDSMTestSMBRecord(t, username) != before {
		t.Fatal("DSM temporary login changed the test user's SMB credential record")
	}
	assertDSMSMBLogin(t, username, password)
}

func assertDSMSMBLogin(t *testing.T, username, password string) {
	t.Helper()
	authPath := filepath.Join(t.TempDir(), "smb-auth")
	if err := os.WriteFile(authPath, []byte("username = "+username+"\npassword = "+password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(authPath)
	command := exec.Command(dsmIntegrationSMBClient, "//127.0.0.1/IPC$", "-A", authPath,
		"--use-kerberos=off", "-m", "SMB3", "-t", "5", "-d", "0", "-c", "quit")
	if err := command.Run(); err != nil {
		t.Fatalf("fresh SMB authentication with the original password failed: %v", err)
	}
}

func registerDSMSessionCleanup(t *testing.T, cfg config.HelperConfig, sid string) {
	t.Helper()
	if sid == "" {
		return
	}
	t.Cleanup(func() {
		values := url.Values{}
		values.Set("api", "SYNO.API.Auth")
		values.Set("method", "logout")
		values.Set("version", "7")
		values.Set("session", cfg.DSMSession)
		values.Set("_sid", sid)
		client := dsmHTTPClient(cfg)
		response, err := client.Get(cfg.DSMLoginAPI + "?" + values.Encode())
		if err != nil {
			t.Errorf("logout DSM integration session: %v", err)
			return
		}
		_ = response.Body.Close()
	})
}

func readDSMShadowSnapshot() (dsmShadowSnapshot, error) {
	data, err := os.ReadFile(dsmIntegrationShadowPath)
	if err != nil {
		return dsmShadowSnapshot{}, err
	}
	info, err := os.Lstat(dsmIntegrationShadowPath)
	if err != nil {
		return dsmShadowSnapshot{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return dsmShadowSnapshot{}, fmt.Errorf("shadow stat metadata is unavailable")
	}
	xattrs, err := readExtendedAttributes(dsmIntegrationShadowPath)
	if err != nil {
		return dsmShadowSnapshot{}, err
	}
	return dsmShadowSnapshot{
		data:   data,
		mode:   info.Mode().Perm(),
		uid:    stat.Uid,
		gid:    stat.Gid,
		xattrs: xattrs,
	}, nil
}

func assertDSMShadowUnchanged(t *testing.T, before, after dsmShadowSnapshot) {
	t.Helper()
	assertValidDSMShadow(t, after.data)
	if !bytes.Equal(after.data, before.data) {
		t.Fatal("DSM shadow content changed after password restoration")
	}
	if after.mode != before.mode || after.uid != before.uid || after.gid != before.gid {
		t.Fatalf(
			"DSM shadow metadata changed: before mode=%o uid=%d gid=%d, after mode=%o uid=%d gid=%d",
			before.mode, before.uid, before.gid, after.mode, after.uid, after.gid,
		)
	}
	if !equalExtendedAttributes(before.xattrs, after.xattrs) {
		t.Fatal("DSM shadow extended attributes changed after password restoration")
	}
}

func assertValidDSMShadow(t *testing.T, data []byte) {
	t.Helper()
	seen := map[string]bool{}
	for index, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 9 || fields[0] == "" {
			t.Fatalf("DSM shadow line %d is malformed", index+1)
		}
		if seen[fields[0]] {
			t.Fatalf("DSM shadow user appears more than once on line %d", index+1)
		}
		seen[fields[0]] = true
	}
}

func equalExtendedAttributes(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for name, value := range left {
		if !bytes.Equal(value, right[name]) {
			return false
		}
	}
	return true
}
