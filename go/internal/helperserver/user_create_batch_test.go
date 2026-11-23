package helperserver

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDSMUserNotFoundRequiresNativeEvidence(t *testing.T) {
	for _, tc := range []struct {
		message string
		missing bool
	}{
		{"SYNOUserGet failed. synoerr=[0x1D00]", true}, {"SYNOUserGet failed. synoerr=[0x100]", false}, {"", false},
	} {
		if dsmUserNotFound(&exec.ExitError{Stderr: []byte(tc.message)}) != tc.missing {
			t.Fatal(tc.message)
		}
	}
	if dsmUserNotFound(nil) || dsmUserNotFound(context.DeadlineExceeded) {
		t.Fatal("unconfirmed absence")
	}
}

func TestConcurrentCreatesConfirmEachUIDAndDoNotReplayFailedRows(t *testing.T) {
	cfg := policyTestConfig(t)
	names := []string{"fresh-a", "fresh-b", "fresh-c", "fresh-d", "fresh-e"}
	s := NewWithStore(cfg, batchMemberTestStore(t, names, "engineering"))
	dir := t.TempDir()
	t.Setenv("TEST_DIR", dir)
	t.Setenv("TEST_PASSWD", cfg.PasswdPath)
	cfg.SynoUserPath = filepath.Join(dir, "synouser")
	writeFile(t, cfg.SynoUserPath, `#!/bin/sh
case "$1" in
--get)
  test -f "$TEST_DIR/$2" && { cat "$TEST_DIR/$2"; exit 0; }
  echo 'SYNOUserGet failed. synoerr=[0x1D00]' >&2
  exit 255;;
--add)
  echo "$2" >> "$TEST_DIR/adds"
  case "$2" in
    fresh-a) uid=2071;;
    fresh-b) uid=2072;;
    fresh-c) exit 1;;
    fresh-d) exit 0;;
    fresh-e) uid=2075;;
    *) exit 2;;
  esac
  printf '%s:x:%s:100:%s:/:/bin/false\n' "$2" "$uid" "$4" >> "$TEST_PASSWD"
  email=$6
  if [ "$2" = fresh-b ] && [ -z "$email" ]; then email=default@example.invalid; fi
  printf 'Fullname : [%s]\nUser Mail : [%s]\nExpired : [false]\n' "$4" "$email" > "$TEST_DIR/$2"
  exit 0;;
*) exit 2;;
esac
`)
	if err := os.Chmod(cfg.SynoUserPath, 0700); err != nil {
		t.Fatal(err)
	}
	var rows []any
	for _, name := range names {
		rows = append(rows, map[string]any{"dsm_username": name, "display_name": name, "email": ""})
	}
	r := s.provisionAccounts(context.Background(), cfg, map[string]any{"dsm_users": rows, "initial_password": "fixture-password"})
	out, ok := r["user_results"].([]map[string]any)
	if !ok || len(out) != len(names) {
		t.Fatal(r)
	}
	for i, n := range names {
		created := i < 2 || i == 4
		if out[i]["dsm_username"] != n || out[i]["success"] != created {
			t.Fatal(i, out[i])
		}
		if created && (out[i]["initial_password_applied"] != true || requireManagedUser(cfg, n) != nil) {
			t.Fatal("missing managed UID", n)
		}
		if !created && requireManagedUser(cfg, n) == nil {
			t.Fatal("unconfirmed grant", n)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "adds"))
	if err != nil {
		t.Fatal(err)
	}
	adds := strings.Fields(string(raw))
	slices.Sort(adds)
	if !slices.Equal(adds, names) {
		t.Fatalf("unexpected duplicate or missing native creates: %v", adds)
	}
}

func TestCreateLocksForCollidingNames(t *testing.T) {
	dir := t.TempDir()
	users := []newDSMUser{{name: "王"}, {name: "ordinary"}, {name: "李"}, {name: "ordinary"}}
	paths := userCreateLockPaths(dir, users)
	if !slices.IsSorted(paths) || len(paths) != 2 {
		t.Fatalf("lock paths %v", paths)
	}
	if err := withUserCreateLocks(paths, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
