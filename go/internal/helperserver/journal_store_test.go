package helperserver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCorruptJournalOnlyBlocksItsAccountAndOtherRecoveryContinues(t *testing.T) {
	for _, damage := range []string{"record", "index"} {
		t.Run(damage, func(t *testing.T) {
			cfg, _ := shadowOnlyTestConfig(t)
			bobBefore, err := shadowLine(cfg.ShadowPath, "bob")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepareBrowserLogin(cfg, "alice-login", "alice"); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareBrowserLogin(cfg, "bob-login", "bob"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(cfg.JournalDir, "alice-login.json")
			if damage == "index" {
				path = journalIndexPath(cfg, "alice")
			}
			if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := browserLeaseForUser(cfg, "alice"); err == nil {
				t.Fatal("damaged account was not blocked")
			}
			if _, found, err := browserLeaseForUser(cfg, "bob"); err != nil || !found {
				t.Fatalf("unrelated account blocked: %v", err)
			}
			if err := recoverPending(cfg); err == nil {
				t.Fatal("corrupt record was silently ignored")
			}
			after, err := shadowLine(cfg.ShadowPath, "bob")
			if err != nil || after != bobBefore {
				t.Fatal("unrelated account was not recovered")
			}
			if _, err := prepareBrowserLogin(cfg, "bob-next-login", "bob"); err != nil {
				t.Fatalf("unrelated login failed: %v", err)
			}
			if err := restorePendingJournal(cfg, "bob-next-login", "test"); err != nil {
				t.Fatal(err)
			}
			if err := assertNoPendingJournals(cfg.JournalDir); err == nil {
				t.Fatal("unresolved account allowed unsafe uninstall")
			}
		})
	}
}

func TestCompletedJournalsAreArchivedAndDoNotEnterLoginScan(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	for n := range 100 {
		if err := saveJournal(cfg, journal{RequestID: fmt.Sprintf("done-%d", n), DSMUsername: "alice", Status: "restored"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(cfg.JournalDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Fatal("completed journal retained in active scan")
		}
	}
	if j, err := loadJournal(cfg, "done-0"); err != nil || j.Status != "restored" {
		t.Fatal("completed request lost idempotency")
	}
	if err := ensureNewLoginJournal(cfg, "done-0", "alice"); err == nil {
		t.Fatal("completed request ID reused")
	}
	if err := os.WriteFile(filepath.Join(cfg.JournalDir, "completed", "done-1.json"), []byte("corrupt archived record"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := browserLeaseForUser(cfg, "alice"); err != nil || found {
		t.Fatalf("archive affected login: %v", err)
	}
	if err := recoverPending(cfg); err != nil {
		t.Fatalf("archive affected recovery: %v", err)
	}
	if err := assertNoPendingJournals(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyJournalMigrationPreservesPendingRecoveryAndIdempotency(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	if err := os.MkdirAll(cfg.JournalDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, j := range []journal{{RequestID: "legacy-done", DSMUsername: "alice", Status: "restored"}, {RequestID: "legacy-active", DSMUsername: "bob", Status: journalStatusActiveBrowser}} {
		data, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.JournalDir, j.RequestID+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := browserLeaseForUser(cfg, "bob"); err != nil || !found {
		t.Fatalf("old active journal lost: %v", err)
	}
	if _, found, err := browserLeaseForUser(cfg, "alice"); err != nil || found {
		t.Fatalf("old terminal journal blocked login: %v", err)
	}
	if _, err := loadJournal(cfg, "legacy-done"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.JournalDir, "legacy-active.json")); err != nil {
		t.Fatal("active recovery material removed")
	}
}

func TestUnidentifiableLegacyJournalRequiresRepairWithoutDeletingEvidence(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	if err := os.MkdirAll(cfg.JournalDir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(cfg.JournalDir, "legacy-bad.json")
	if err := os.WriteFile(p, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureJournalStore(cfg); err == nil {
		t.Fatal("unassigned legacy recovery material ignored")
	}
	if data, err := os.ReadFile(p); err != nil || string(data) != "broken" {
		t.Fatal("legacy recovery evidence removed")
	}
}

func TestJournalRetentionNeverDeletesPendingOrPasswordResetRecords(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	for _, j := range []journal{{RequestID: "recent", DSMUsername: "alice", Status: "restored"}, {RequestID: "expired", DSMUsername: "alice", Status: "superseded"}, {RequestID: "active", DSMUsername: "bob", Status: journalStatusActiveBrowser}} {
		if err := saveJournal(cfg, j); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	old := now.Add(-8 * 24 * time.Hour)
	for _, p := range []string{filepath.Join(cfg.JournalDir, "completed", "expired.json"), filepath.Join(cfg.JournalDir, "active.json")} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	reset := passwordResetRecord{RequestID: "reset", Username: "bob", SourceSlug: "source", AccountID: "account", PasswordDigest: lineHash("fixture"), Status: "completed"}
	if err := savePasswordReset(cfg, reset); err != nil {
		t.Fatal(err)
	}
	if err := pruneCompletedJournals(cfg, now); err != nil {
		t.Fatal(err)
	}
	if _, err := loadJournal(cfg, "expired"); !os.IsNotExist(err) {
		t.Fatal("expired completed journal kept")
	}
	for _, id := range []string{"recent", "active"} {
		if _, err := loadJournal(cfg, id); err != nil {
			t.Fatalf("live record removed: %v", err)
		}
	}
	if _, err := loadPasswordReset(cfg, "bob"); err != nil {
		t.Fatal("permanent password history removed")
	}
}

func TestRecoveryFinishesInterruptedArchive(t *testing.T) {
	cfg, _ := shadowOnlyTestConfig(t)
	j := journal{RequestID: "interrupted-archive", DSMUsername: "alice", Status: journalStatusActiveBrowser}
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	j.Status = "restored"
	data, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(cfg.JournalDir, j.RequestID+".json")
	if err := os.WriteFile(active, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverPending(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(active); !os.IsNotExist(err) {
		t.Fatal("terminal journal still in active directory")
	}
	if _, err := loadJournal(cfg, j.RequestID); err != nil {
		t.Fatal("completion receipt lost")
	}
	if err := assertNoPendingJournals(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
}
