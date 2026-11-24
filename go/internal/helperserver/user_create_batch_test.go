package helperserver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
	users := []newDSMUser{{name: "王"}, {name: "ordinary"}, {name: "李"}, {name: "ORDINARY"}}
	paths := userCreateLockPaths(dir, users)
	if !slices.IsSorted(paths) || len(paths) != 3 || lockPath(dir, "王") == lockPath(dir, "李") {
		t.Fatalf("lock paths %v", paths)
	}
	if err := withUserCreateLocks(paths, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestCreateBatchReadsBackNativeReceiptsTogether(t *testing.T) {
	for _, broken := range []bool{false, true} {
		cfg := policyTestConfig(t)
		names := []string{"fresh-a", "fresh-b"}
		s := NewWithStore(cfg, batchMemberTestStore(t, names, "engineering"))
		dir := t.TempDir()
		t.Setenv("TEST_PASSWD", cfg.PasswdPath)
		t.Setenv("TEST_DIR", dir)
		cfg.SynoUserPath = filepath.Join(dir, "synouser")
		cfg.SynoWebAPIPath = filepath.Join(dir, "list")
		native := `#!/bin/sh
case "$1" in
--get) echo get >> "$TEST_DIR/gets"; echo 'synoerr=[0x1D00]' >&2; exit 1;;
--add) case "$2" in fresh-a) uid=2071;; fresh-b) uid=2072;; *) exit 1;; esac
  echo add >> "$TEST_DIR/adds"
  printf '%s:x:%s:100:%s:/:/bin/false\n' "$2" "$uid" "$4" >> "$TEST_PASSWD";;
*) exit 1;;
esac
`
		web := `#!/bin/sh
echo read >> "$TEST_DIR/lists"
echo '{"success":true,"data":{"total":2,"offset":0,"users":[{"name":"fresh-b","uid":2072,"description":"fresh-b","email":"","expired":"normal"},{"name":"fresh-a","uid":2071,"description":"fresh-a","email":"","expired":"normal"}]}}'
`
		if broken {
			web = "#!/bin/sh\necho read >> \"$TEST_DIR/lists\"\nexit 1\n"
		}
		if err := os.WriteFile(cfg.SynoUserPath, []byte(native), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg.SynoWebAPIPath, []byte(web), 0700); err != nil {
			t.Fatal(err)
		}
		rows := []any{}
		for _, name := range names {
			rows = append(rows, map[string]any{"dsm_username": name, "display_name": name, "email": ""})
		}
		payload := map[string]any{"dsm_users": rows, "initial_password": "fixture-password"}
		answer := s.provisionAccounts(context.Background(), cfg, payload)
		if broken == (answer["success"] == true) {
			t.Fatal(answer)
		}
		listReads := 1
		if broken {
			listReads++
		}
		for file, n := range map[string]int{"gets": 2, "adds": 2, "lists": listReads} {
			data, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil || len(strings.Fields(string(data))) != n {
				t.Fatalf("%s %q %v", file, data, err)
			}
		}
		for _, name := range names {
			if err := requireManagedUser(cfg, name); err != nil {
				t.Fatal("lost native UID receipt", err)
			}
		}
		if !broken {
			for _, r := range answer["user_results"].([]map[string]any) {
				if r["created"] != true || r["initial_password_applied"] != true {
					t.Fatal(r)
				}
			}
		}
	}
}

func TestRetryNativeCreateOnlyAfterConfirmedAbsence(t *testing.T) {
	names := []string{"transient", "permanent", "partial", "unknown"}
	cfg := policyTestConfig(t)
	s := NewWithStore(cfg, batchMemberTestStore(t, names, "engineering"))
	dir := t.TempDir()
	t.Setenv("FIXTURES", dir)
	t.Setenv("PASSWD_ROWS", cfg.PasswdPath)
	cfg.SynoUserPath = filepath.Join(dir, "synouser")
	cfg.SynoWebAPIPath = ""
	script := `#!/bin/sh
calls="$FIXTURES/$2.calls"
if [ "$1" = --get ]; then
 if [ "$2" = unknown ] && [ -f "$calls" ]; then exit 1; fi
 if grep -q "^$2:" "$PASSWD_ROWS"; then printf 'Fullname : [%s]\nUser Mail : []\nExpired : [false]\n' "$2"; exit 0; fi
 echo 'synoerr=[0x1D00]' >&2; exit 255
fi
[ "$1" = --add ] || exit 1
echo attempt >> "$calls"
case "$2" in
 transient) [ "$(wc -l < "$calls")" -gt 1 ] || exit 255; uid=2100;;
 permanent|unknown) exit 255;;
 partial) uid=2101;;
 *) exit 1;;
esac
printf '%s:x:%s:100:%s:/:/bin/false\n' "$2" "$uid" "$2" >> "$PASSWD_ROWS"
[ "$2" != partial ] || exit 255
`
	if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var rows []any
	for _, name := range names {
		rows = append(rows, map[string]any{"dsm_username": name, "display_name": name, "email": ""})
	}
	payload := map[string]any{"dsm_users": rows, "initial_password": "fixture-password"}
	results := s.provisionAccounts(context.Background(), cfg, payload)["user_results"].([]map[string]any)
	for i, name := range names {
		count := 1
		if name == "transient" || name == "permanent" {
			count = 2
		}
		got, err := os.ReadFile(filepath.Join(dir, name+".calls"))
		if err != nil || len(strings.Fields(string(got))) != count || results[i]["success"] != (name == "transient") {
			t.Fatal(name, string(got), results[i], err)
		}
		_, err = os.Stat((creationTarget{cfg: cfg, name: name}).path())
		pending := name == "partial" || name == "unknown"
		if pending != (err == nil) {
			t.Fatalf("pending receipt for %s: %v", name, err)
		}
		if err := requireManagedUser(cfg, name); (err == nil) != (name == "transient") {
			t.Fatal("unconfirmed UID enrolled", name, err)
		}
	}
}

func TestSingleProvisionPreservesOutstandingReceiptAndRequiresConfirmedAbsence(t *testing.T) {
	for _, tc := range []struct {
		label, receipt string
		unknown        bool
	}{
		{"unknown lookup", "", true}, {"uncertain attempt", "-1", false},
		{"unregistered UID", "2071", false}, {"unreadable receipt", "invalid", false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			cfg := policyTestConfig(t)
			name := "pending-user"
			s := NewWithStore(cfg, batchMemberTestStore(t, []string{name}, "engineering"))
			dir := t.TempDir()
			t.Setenv("CALLS", filepath.Join(dir, "mutations"))
			get := "echo 'synoerr=[0x1D00]' >&2; exit 255"
			if tc.unknown {
				get = "exit 1"
			}
			cfg.SynoUserPath = filepath.Join(dir, "synouser")
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\nif [ \"$1\" = --get ]; then "+get+"; fi\necho write >> \"$CALLS\"\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			receipt := (creationTarget{cfg: cfg, name: name}).path()
			if tc.receipt != "" {
				if err := os.WriteFile(receipt, []byte(tc.receipt), 0600); err != nil {
					t.Fatal(err)
				}
			}
			row := map[string]any{"dsm_username": name, "display_name": name, "email": ""}
			for range 2 {
				r := s.provisionAccounts(context.Background(), cfg, map[string]any{"dsm_users": []any{row}, "initial_password": "fixture"})
				if out := r["user_results"].([]map[string]any); out[0]["success"] != false {
					t.Fatal("uncertain result accepted", out)
				}
			}
			if _, err := os.Stat(os.Getenv("CALLS")); !os.IsNotExist(err) {
				t.Fatal("native mutation attempted", err)
			}
			got, err := os.ReadFile(receipt)
			if tc.receipt == "" {
				if !os.IsNotExist(err) {
					t.Fatal("new receipt on unknown lookup", err)
				}
			} else if err != nil || string(got) != tc.receipt {
				t.Fatal("changed pending receipt", string(got), err)
			}
		})
	}
}

func TestCreationReleasesEarlierAccountLocksBeforeBatchReadback(t *testing.T) {
	cfg := policyTestConfig(t)
	names := []string{"wave0", "wave1", "wave2", "wave3", "wave4", "wave5", "wave6", "wave7"}
	s := NewWithStore(cfg, batchMemberTestStore(t, names, "engineering"))
	dir := t.TempDir()
	t.Setenv("TEST_DIR", dir)
	t.Setenv("TEST_PASSWD", cfg.PasswdPath)
	cfg.SynoUserPath = filepath.Join(dir, "user")
	native := `#!/bin/sh
if [ "$1" = --get ]; then
  if [ "$2" = wave4 ]; then
    touch "$TEST_DIR/second"
    while [ ! -e "$TEST_DIR/continue" ]; do sleep 0.02; done
  fi
  echo 'synoerr=[0x1D00]' >&2
  exit 255
fi
[ "$1" = --add ] || exit 1
printf '%s:x:%s:100:%s:/:/bin/false\n' "$2" "201${2#wave}" "$4" >> "$TEST_PASSWD"
`
	if err := os.WriteFile(cfg.SynoUserPath, []byte(native), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.SynoWebAPIPath = filepath.Join(dir, "webapi")
	var profiles []map[string]any
	var rows []any
	for i, n := range names {
		profiles = append(profiles, map[string]any{"name": n, "uid": 2010 + i, "email": "", "description": n, "expired": "normal"})
		rows = append(rows, map[string]any{"dsm_username": n, "display_name": n, "email": ""})
	}
	list, err := json.Marshal(map[string]any{"success": true, "data": map[string]any{"offset": 0, "total": len(rows), "users": profiles}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SynoWebAPIPath, []byte("#!/bin/sh\necho '"+string(list)+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	done := make(chan map[string]any, 1)
	go func() {
		done <- s.provisionAccounts(context.Background(), cfg, map[string]any{"dsm_users": rows, "initial_password": "fixture"})
	}()
	release := func() {
		if err := os.WriteFile(filepath.Join(dir, "continue"), nil, 0600); err != nil {
			t.Error(err)
		}
	}
	defer release()
	until := time.Now().Add(4 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "second")); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("second wave did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = withFileLockContext(ctx, lockPath(cfg.LockDir, names[0]), func() error {
		if err := requireManagedUser(cfg, names[0]); err != nil {
			return err
		}
		return savePasswordReset(cfg, passwordResetRecord{RequestID: "intervening-reset", Username: names[0], SourceSlug: "source", AccountID: "account", Status: "completed", PasswordDigest: lineHash("updated")})
	})
	release()
	response := <-done
	if err != nil {
		t.Fatal("first account remained locked during second wave", err)
	}
	out, ok := response["user_results"].([]map[string]any)
	if !ok || len(out) != len(names) {
		t.Fatal(response)
	}
	for i, result := range out {
		if result["created"] != true || result["initial_password_applied"] != (i != 0) {
			t.Fatalf("incorrect post-create result %s: %v", names[i], result)
		}
	}
}
