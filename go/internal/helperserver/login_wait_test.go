package helperserver

import (
	"testing"
	"time"
)

func TestLoginWaitsForNativeSyncBeyondOldThreeSecondLimit(t *testing.T) {
	for _, syncUser := range []string{"alice", "bob"} {
		t.Run(syncUser, func(t *testing.T) {
			cfg, original := shadowOnlyTestConfig(t)
			locked := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- withAccountMutation(cfg, syncUser, false, func() error { close(locked); time.Sleep(3200 * time.Millisecond); return nil })
			}()
			select {
			case <-locked:
			case err := <-done:
				t.Fatalf("sync failed before acquiring lock: %v", err)
			case <-time.After(time.Second):
				t.Fatal("sync did not acquire lock")
			}
			if _, err := prepareBrowserLogin(cfg, "queued-login", "alice"); err != nil {
				t.Fatalf("login failed while sync completed: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := restorePendingJournal(cfg, "queued-login", "test"); err != nil {
				t.Fatal(err)
			}
			line, err := shadowLine(cfg.ShadowPath, "alice")
			if err != nil || line != original {
				t.Fatal("queued login failed to restore original password")
			}
		})
	}
}
