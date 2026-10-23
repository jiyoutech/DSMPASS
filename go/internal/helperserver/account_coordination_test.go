package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func replaceTestAccount(t *testing.T, cfg config.HelperConfig, line string) {
	t.Helper()
	current, err := shadowLine(cfg.ShadowPath, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceShadowLineIfCurrentMatches(cfg.ShadowPath, "alice", line, current); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryPreservesConcurrentAccountChanges(t *testing.T) {
	for _, change := range []string{"expiry", "locked", "new password", "already restored", "unknown lock"} {
		t.Run(change, func(t *testing.T) {
			cfg, original := shadowOnlyTestConfig(t)
			if _, err := prepareBrowserLogin(cfg, "changed-account", "alice"); err != nil {
				t.Fatal(err)
			}
			current, err := shadowLine(cfg.ShadowPath, "alice")
			if err != nil {
				t.Fatal(err)
			}
			fields := strings.Split(current, ":")
			fields[2], fields[7] = "20001", "20002"
			wantPassword := strings.Split(original, ":")[1]
			wantStatus := "restored"
			switch change {
			case "locked":
				fields[1] = "!!" + fields[1]
				wantPassword = "!!" + wantPassword
			case "new password":
				fields[1], wantPassword, wantStatus = "$external", "$external", journalStatusSuperseded
			case "already restored":
				fields[1] = wantPassword
			case "unknown lock":
				fields[1], wantPassword, wantStatus = "*", "*", journalStatusRestoringBrowser
			}
			replaceTestAccount(t, cfg, strings.Join(fields, ":"))
			err = restorePendingJournal(cfg, "changed-account", "test")
			if (err != nil) != (change == "unknown lock") {
				t.Fatalf("unexpected recovery error: %v", err)
			}
			fields[1] = wantPassword
			got, err := shadowLine(cfg.ShadowPath, "alice")
			if err != nil || got != strings.Join(fields, ":") {
				t.Fatalf("recovery overwrote account metadata: %v", err)
			}
			j, err := loadJournal(cfg, "changed-account")
			if err != nil || j.Status != wantStatus {
				t.Fatalf("journal status = %s, error = %v", j.Status, err)
			}
		})
	}
}

func TestRecoveryRefusesRecreatedAccount(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	passwd := filepath.Join(filepath.Dir(cfg.ShadowPath), "passwd")
	if err := os.WriteFile(passwd, []byte("alice:x:1001:100:Alice:/home/alice:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "identity", "alice"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.ShadowPath)
	if err := os.WriteFile(passwd, []byte("alice:x:1002:100:Alice:/home/alice:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, "identity", "test"); !errors.Is(err, errBrowserLoginUnresolved) {
		t.Fatalf("expected identity conflict, got %v", err)
	}
	after, _ := os.ReadFile(cfg.ShadowPath)
	if string(after) != string(before) {
		t.Fatal("recovery modified a recreated account")
	}
}

func TestOldCallbackAndReusedIDCannotOverwriteNewLogin(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	if _, err := prepareBrowserLogin(cfg, "old-request", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "old-request", "bob"); err == nil {
		t.Fatal("same ID was reused for another account")
	}
	if err := restorePendingJournal(cfg, "old-request", "complete"); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "old-request", "alice"); err == nil {
		t.Fatal("completed request ID was reused")
	}
	if _, err := prepareBrowserLogin(cfg, "new-request", "alice"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.ShadowPath)
	if err := restorePendingJournal(cfg, "old-request", "late_callback"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(cfg.ShadowPath)
	if string(after) != string(before) {
		t.Fatal("late callback restored the new operation")
	}
	if err := restorePendingJournal(cfg, "new-request", "cleanup"); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryScanRetriesFailureAndRespectsActiveLease(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	if _, err := prepareBrowserLogin(cfg, "retry-recovery", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournals(cfg, false); err != nil {
		t.Fatal(err)
	}
	j, err := loadJournal(cfg, "retry-recovery")
	if err != nil || j.Status != journalStatusActiveBrowser {
		t.Fatal("periodic recovery expired a live lease")
	}
	temporary, err := os.ReadFile(cfg.ShadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.ShadowPath); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, j.RequestID, "test_io_failure"); err == nil {
		t.Fatal("recovery failure was hidden")
	}
	j, err = loadJournal(cfg, j.RequestID)
	if err != nil || j.RecoveryAttempts != 1 || j.NextRecoveryAt == "" {
		t.Fatal("recovery failure was not durably scheduled")
	}
	if err := os.WriteFile(cfg.ShadowPath, temporary, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, j.RequestID, "alice"); !errors.Is(err, errBrowserLoginUnresolved) {
		t.Fatal("a failed recovery reissued a temporary credential")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runRecoveryLoop(ctx, cfg) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err = loadJournal(cfg, j.RequestID)
		if err == nil && j.Status == "restored" {
			line, err := shadowLine(cfg.ShadowPath, "alice")
			if err != nil || line != original {
				t.Fatal("retry failed to restore original password")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("background recovery did not retry")
}

func TestDisableRevokesBrowserLeaseAndLateCallbackPreservesDisable(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	if _, err := prepareBrowserLogin(cfg, "disable-login", "alice"); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := withAccountMutation(cfg, "alice", false, func() error { called = true; return nil }); !errors.Is(err, errBrowserLoginInProgress) || called {
		t.Fatal("provisioning bypassed an active login")
	}
	want := strings.Split(original, ":")
	want[1] = "!" + want[1]
	want[7] = "1"
	if err := withAccountMutation(cfg, "alice", true, func() error {
		current, err := shadowLine(cfg.ShadowPath, "alice")
		if err != nil || current != original {
			return errors.New("disable ran before recovery")
		}
		return replaceShadowLineIfCurrentMatches(cfg.ShadowPath, "alice", strings.Join(want, ":"), current)
	}); err != nil {
		t.Fatal(err)
	}
	if err := restorePendingJournal(cfg, "disable-login", "late_callback"); err != nil {
		t.Fatal(err)
	}
	got, err := shadowLine(cfg.ShadowPath, "alice")
	if err != nil || got != strings.Join(want, ":") {
		t.Fatal("late recovery re-enabled a disabled account")
	}
}

func TestAccountLockCanTimeOutWithoutRunningMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	err := withFileLock(path, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		called := false
		err := withFileLockContext(ctx, path, func() error { called = true; return nil })
		if called || !errors.Is(err, errAccountBusy) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lock timeout executed mutation: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := withFileLock(path, func() error { return nil }); err != nil {
		t.Fatalf("timeout left lock stuck: %v", err)
	}
}

type coordinationChild struct {
	Config config.HelperConfig
	Mode   string
	Ready  string
}

func TestAccountCoordinationChild(t *testing.T) {
	value := os.Getenv("DSMPASS_COORDINATION_CHILD")
	if value == "" {
		return
	}
	var child coordinationChild
	if err := json.Unmarshal([]byte(value), &child); err != nil {
		t.Fatal(err)
	}
	if child.Mode == "login" {
		if _, err := prepareBrowserLogin(child.Config, "killed-login", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(child.Ready, []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	if child.Mode == "login" {
		time.Sleep(time.Hour)
		return
	}
	if err := withFileLock(child.Config.ShadowLockPath+".system", func() error {
		current, err := shadowLine(child.Config.ShadowPath, "bob")
		if err != nil {
			return err
		}
		return replaceShadowLineIfCurrentMatches(child.Config.ShadowPath, "bob", strings.Replace(current, "$untouched", "$external", 1), current)
	}); err != nil {
		t.Fatal(err)
	}
}

func startCoordinationChild(t *testing.T, cfg config.HelperConfig, mode string) (*exec.Cmd, string) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	value, err := json.Marshal(coordinationChild{Config: cfg, Mode: mode, Ready: ready})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAccountCoordinationChild$", "-test.timeout=15s")
	command.Env = append(os.Environ(), "DSMPASS_COORDINATION_CHILD="+string(value))
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	return command, ready
}

func waitForCoordinationChild(t *testing.T, ready string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("child did not reach the synchronization point")
}

func TestKilledLoginProcessIsRecoveredFromJournal(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	command, ready := startCoordinationChild(t, cfg, "login")
	waitForCoordinationChild(t, ready)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if err := recoverPending(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := shadowLine(cfg.ShadowPath, "alice")
	if err != nil || got != original {
		t.Fatal("process death left a temporary password installed")
	}
}

func TestSystemLockPreservesDifferentAccountUpdatesAcrossProcesses(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	var command *exec.Cmd
	err := withShadowWrite(cfg, func() error {
		var ready string
		command, ready = startCoordinationChild(t, cfg, "external")
		waitForCoordinationChild(t, ready)
		return replaceShadowLineIfCurrentMatches(cfg.ShadowPath, "alice", strings.Replace(original, "$original", "$updated", 1), original)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.ShadowPath)
	if err != nil || !strings.Contains(string(data), "alice:$updated:") || !strings.Contains(string(data), "bob:$external:") {
		t.Fatal("one writer overwrote the other account update")
	}
}

func TestProvisionAccountUsesGlobalWriterLock(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "created")
	cfg.SynoUserPath = filepath.Join(dir, "synouser")
	script := "#!/bin/sh\ncase \"$1\" in\n--get) [ -e '" + marker + "' ] || exit 1;;\n--add) printf created > '" + marker + "';;\nesac\n"
	if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	result := make(chan map[string]any, 1)
	if err := withFileLock(cfg.ShadowLockPath, func() error {
		go func() {
			result <- s.provisionAccount(cfg, map[string]any{"dsm_username": "new-account", "initial_password": "test-password"})
		}()
		select {
		case <-result:
			return errors.New("provisioning ignored global writer lock")
		case <-time.After(100 * time.Millisecond):
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			return errors.New("native account creation ran while writer lock was held")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	response := <-result
	if response["success"] != true || response["created"] != true {
		t.Fatalf("provisioning did not resume after writer lock release: %v", response)
	}
}

func TestAccountAliasesAndUnknownJournalStatusFailClosed(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	if lockPath(cfg.LockDir, "Alice") != lockPath(cfg.LockDir, "alice") || passwordResetPath(cfg, "Alice") != passwordResetPath(cfg, "alice") {
		t.Fatal("account case aliases use different operation locks")
	}
	j := journal{RequestID: "unknown-state", DSMUsername: "alice", Status: "unrecognized-status"}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if _, _, err := browserLeaseForUser(cfg, "ALICE"); !errors.Is(err, errBrowserLoginUnresolved) {
		t.Fatal("unknown state allowed a new account mutation")
	}
	if _, found, err := browserLeaseForUser(cfg, "bob"); err != nil || found {
		t.Fatal("another account was blocked by a readable unrelated journal")
	}
}

func TestAccountLocksRejectSymlinks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "target")
	if err := os.WriteFile(file, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "lock")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := withFileLock(link, func() error { t.Fatal("symlink lock acquired"); return nil }); err == nil {
		t.Fatal("lock followed a symlink")
	}
}
