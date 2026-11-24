package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestProvisionUsersAuthorizationRequiresEveryActiveIdentity(t *testing.T) {
	ctx := context.Background()
	q := syncedPasswordTestStore(t, "alice")
	check := func(names []string, want bool, wantErr bool) {
		t.Helper()
		got, err := db.HelperAccountAllowed(ctx, q, db.HelperAuthorizationQuery{Action: "provision_users", Usernames: names})
		if got != want || (err != nil) != wantErr {
			t.Fatalf("batch length %d: allowed=%v, error=%v", len(names), got, err)
		}
	}
	check(nil, false, true)
	check(make([]string, 201), false, true)
	check([]string{"unknown", "alice"}, false, false)
	check([]string{"alice", "unknown"}, false, false)
	check([]string{"alice"}, true, false)
	if _, err := q.DBTX().ExecContext(ctx, "UPDATE identity_sources SET directory_sync_enabled=0"); err != nil {
		t.Fatal(err)
	}
	check([]string{"alice"}, false, false)
}

func TestProvisionUsersRetainsUIDConfirmationAndPerAccountFailures(t *testing.T) {
	for _, persist := range []bool{true, false} {
		cfg := policyTestConfig(t)
		s := NewWithStore(cfg, syncedPasswordTestStore(t, "newuser"))
		cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
		logPath := filepath.Join(t.TempDir(), "calls")
		t.Setenv("TEST_CALLS", logPath)
		t.Setenv("TEST_PASSWD", cfg.PasswdPath)
		script := "#!/bin/sh\necho \"$1\" >> \"$TEST_CALLS\"\ncase \"$1\" in\n --get) echo 'synoerr=[0x1D00]' >&2; exit 255;;\n --add) "
		if persist {
			script += "echo 'newuser:x:1050:100:New:/:/bin/false' >> \"$TEST_PASSWD\"; "
		}
		script += "exit 0;;\nesac\nexit 2\n"
		if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		row := func(n string) map[string]any {
			return map[string]any{"dsm_username": n, "display_name": "New", "email": ""}
		}
		call := func(ctx context.Context, rows []any) map[string]any {
			return s.provisionAccounts(ctx, cfg, map[string]any{"dsm_users": rows, "initial_password": "fixture-password"})
		}
		for _, invalid := range [][]any{nil, make([]any, 201), {row("newuser"), row("newuser")}, {row("newuser"), false}} {
			if r := call(context.Background(), invalid); r["error_code"] != "BAD_REQUEST" {
				t.Fatal(r)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if r := call(ctx, []any{row("newuser")}); r["error_code"] != "USER_BATCH_INTERRUPTED" {
			t.Fatal(r)
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Fatal("validation wrote a user")
		}
		r := call(context.Background(), []any{row("root"), row("newuser")})
		out, ok := r["user_results"].([]map[string]any)
		if !ok || len(out) != 2 || out[0]["success"] != false || out[1]["success"] != persist {
			t.Fatalf("%v", r)
		}
		if persist && (out[1]["initial_password_applied"] != true || requireManagedUser(cfg, "newuser") != nil) {
			t.Fatal("missing UID enrollment or password confirmation")
		}
		calls, err := os.ReadFile(logPath)
		if err != nil || string(calls) != "--get\n--add\n" {
			t.Fatalf("unexpected native commands %q %v", calls, err)
		}
	}
}
