//go:build dsm_integration && linux

package helperserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestDSMRealAccountLockCoordination(t *testing.T) {
	if os.Getenv("DSMPASS_DSM_INTEGRATION") != "1" {
		t.Skip("set DSMPASS_DSM_INTEGRATION=1 to run against a DSM host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("DSM account lock integration requires root")
	}
	dir := t.TempDir()
	cfg := config.HelperConfig{
		ShadowPath: dsmIntegrationShadowPath, ShadowLockPath: filepath.Join(dir, "shadow.lock"),
		LockDir: filepath.Join(dir, "locks"), JournalDir: filepath.Join(dir, "journal"),
		SynoUserPath: dsmIntegrationSynouserPath, OpenSSLPath: "/usr/bin/openssl",
		HMACSecret: randomPassword(48), TempPasswordLength: 48, DSMBrowserLoginTTLSeconds: 3600,
	}
	if _, err := shadowSystemLockPath(cfg); err != nil {
		t.Fatal(err)
	}
	username := fmt.Sprintf("dsmpass_lk_%x", uint64(time.Now().UnixNano())&0xffffff)
	before, err := os.ReadFile(cfg.ShadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains("\n"+string(before), "\n"+username+":") {
		t.Fatal("refusing to modify an existing test account")
	}
	t.Cleanup(func() {
		if err := recoverPending(cfg); err != nil {
			t.Errorf("test account recovery: %v", err)
		}
		if _, err := getSynoUser(cfg.SynoUserPath, username); err == nil {
			if err := run(cfg.SynoUserPath, "--del", username); err != nil {
				t.Errorf("test account deletion: %v", err)
			}
		}
	})
	password, changedPassword := "Dsm!7"+randomPassword(43), "Dsm!7"+randomPassword(43)
	probeDSMNativeAccountLock(t, cfg, "create", cfg.SynoUserPath, synouserAddArgs(username, password, "DSMPASS lock integration", "")...)
	probeDSMNativeAccountLock(t, cfg, "setpw", cfg.SynoUserPath, "--setpw", username, changedPassword)
	probeDSMNativeAccountLock(t, cfg, "disable", cfg.SynoUserPath, "--modify", username, "DSMPASS lock integration", "1", "")
	probeDSMNativeAccountLock(t, cfg, "enable", cfg.SynoUserPath, "--modify", username, "DSMPASS lock integration", "0", "")
	probeDSMNativeAccountLock(t, cfg, "webapi", "/usr/syno/bin/synowebapi", "--exec", "api=SYNO.Core.User", "method=set", "version=1", fmt.Sprintf("name=%q", username), fmt.Sprintf("password=%q", password))
	assertDSMSMBLogin(t, username, password)
	beforeLogin, err := shadowLine(cfg.ShadowPath, username)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "native-disable", username); err != nil {
		t.Fatal(err)
	}
	if err := run(cfg.SynoUserPath, "--modify", username, "DSMPASS lock integration", "1", ""); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, "native-disable", "complete"); err != nil {
		t.Fatal(err)
	}
	info, err := getSynoUser(cfg.SynoUserPath, username)
	if err != nil || !info.Expired {
		t.Fatal("temporary-password recovery undid the native disable")
	}
	afterRestore, err := shadowLine(cfg.ShadowPath, username)
	if err != nil || strings.TrimLeft(strings.Split(afterRestore, ":")[1], "!") != strings.Split(beforeLogin, ":")[1] {
		t.Fatal("disabled account retained the temporary password")
	}
	if err := run(cfg.SynoUserPath, "--modify", username, "DSMPASS lock integration", "0", ""); err != nil {
		t.Fatal(err)
	}
	assertDSMSMBLogin(t, username, password)
	probeDSMNativeAccountLock(t, cfg, "delete", cfg.SynoUserPath, "--del", username)
	after, err := os.ReadFile(cfg.ShadowPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("account lock test changed unrelated shadow records")
	}
	t.Log("native CLI and WebAPI honor system lock; recovery preserves disable and original password; test account removed")
}

func probeDSMNativeAccountLock(t *testing.T, cfg config.HelperConfig, action, command string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	finished := make(chan error, 1)
	started := false
	err := withShadowWrite(cfg, func() error {
		before, err := os.ReadFile(cfg.ShadowPath)
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		started = true
		go func() { finished <- cmd.Wait() }()
		select {
		case err := <-finished:
			finished <- err
			return fmt.Errorf("native %s did not wait for account lock", action)
		case <-time.After(500 * time.Millisecond):
		}
		after, err := os.ReadFile(cfg.ShadowPath)
		if err != nil || !bytes.Equal(before, after) {
			return fmt.Errorf("native %s changed shadow while its system lock was held", action)
		}
		return nil
	})
	if started {
		if waitErr := <-finished; waitErr != nil && err == nil {
			err = fmt.Errorf("native %s failed after system lock release: %w", action, waitErr)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if action == "webapi" {
		var response struct {
			Success bool `json:"success"`
			Error   struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(output.Bytes(), &response); err != nil {
			t.Fatal("native account WebAPI returned invalid JSON")
		}
		if !response.Success {
			t.Fatalf("native account WebAPI failed with code %d", response.Error.Code)
		}
	}
	t.Logf("%s waits for the system lock and completes after release", action)
}
