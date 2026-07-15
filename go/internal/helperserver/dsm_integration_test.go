//go:build dsm_integration && linux

package helperserver

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

	suffix := fmt.Sprintf("%x", uint64(time.Now().UnixNano())&0xffffff)
	users := []struct {
		name     string
		password string
	}{
		{name: "dsmpass_it_a_" + suffix, password: randomPassword(48)},
		{name: "dsmpass_it_b_" + suffix, password: randomPassword(48)},
	}
	for _, user := range users {
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
		TempPasswordLength:        64,
		DSMLoginAPI:               "https://127.0.0.1:5001/webapi/entry.cgi",
		DSMSession:                "webui",
		DSMTimeoutSeconds:         10,
		DSMTLSSkipVerify:          true,
		DSMBrowserLoginTTLSeconds: 3600,
	}

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
	}

	afterConcurrentRelay, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, before, afterConcurrentRelay)
	for _, user := range users {
		result, err := dsmLogin(cfg, "dsm-integration-password-check-"+user.name, user.name, user.password)
		if err != nil {
			t.Fatalf("original password was not restored for %s: %v", user.name, err)
		}
		registerDSMSessionCleanup(t, cfg, result.SID)
	}

	requestID := "dsm-integration-recovery-" + users[0].name
	if _, err := prepareBrowserLogin(cfg, requestID, users[0].name); err != nil {
		t.Fatalf("prepare interrupted DSM lease: %v", err)
	}
	duringLease, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertValidDSMShadow(t, duringLease.data)
	if bytes.Equal(duringLease.data, before.data) {
		t.Fatal("temporary DSM password lease did not change shadow")
	}
	if err := restorePendingJournal(cfg, requestID, "dsm_integration"); err != nil {
		t.Fatalf("restore interrupted DSM lease: %v", err)
	}
	afterRecovery, err := readDSMShadowSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertDSMShadowUnchanged(t, before, afterRecovery)
	result, err := dsmLogin(cfg, "dsm-integration-recovery-password-check", users[0].name, users[0].password)
	if err != nil {
		t.Fatalf("original password was not restored after recovery: %v", err)
	}
	registerDSMSessionCleanup(t, cfg, result.SID)
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
