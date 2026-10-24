package helperserver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallNeverDeletesPendingOrUnreadableRecovery(t *testing.T) {
	for _, record := range []string{`{"status":"active_browser_login"}`, `{"status":"restoring_browser_login"}`, `broken`, `{}`} {
		dir := t.TempDir()
		journal := filepath.Join(dir, "journal")
		if err := os.Mkdir(journal, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(journal, "request.json"), []byte(record), 0600); err != nil {
			t.Fatal(err)
		}
		err := cleanupHelperFiles(journal, []string{dir}, func(string) error { return nil })
		if err == nil {
			t.Fatal("uninstall accepted incomplete recovery")
		}
		if _, err := os.Stat(filepath.Join(journal, "request.json")); err != nil {
			t.Fatal("recovery evidence lost", err)
		}
	}
}

func TestUninstallChecksAllPathsBeforeDeletion(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "program")
	b := filepath.Join(dir, "unsafe")
	if err := os.WriteFile(a, []byte("protected program"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	err := cleanupHelperFiles(filepath.Join(dir, "journal"), []string{a, b}, func(path string) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe link")
		}
		return nil
	})
	if err == nil {
		t.Fatal("accepted unsafe cleanup target")
	}
	if data, err := os.ReadFile(a); err != nil || string(data) != "protected program" {
		t.Fatal("partially removed safe target before validation", err)
	}
}

func TestUninstallCompletedRecoveryAndPreservedData(t *testing.T) {
	for _, purge := range []bool{false, true} {
		dir := t.TempDir()
		state := filepath.Join(dir, "state")
		program := filepath.Join(dir, "program")
		journal := filepath.Join(state, "journal")
		if err := os.MkdirAll(journal, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(journal, "request.json"), []byte(`{"status":"restored"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(program, []byte("program"), 0600); err != nil {
			t.Fatal(err)
		}
		paths := []string{program, filepath.Join(dir, "missing")}
		if purge {
			paths = append(paths, state)
		}
		if err := cleanupHelperFiles(journal, paths, func(string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(program); !os.IsNotExist(err) {
			t.Fatal("program retained", err)
		}
		_, err := os.Stat(state)
		if os.IsNotExist(err) != purge {
			t.Fatalf("incorrect state retention purge=%v: %v", purge, err)
		}
		if err := cleanupHelperFiles(journal, paths, func(string) error { return nil }); err != nil {
			t.Fatal("repeated cleanup", err)
		}
	}
}
