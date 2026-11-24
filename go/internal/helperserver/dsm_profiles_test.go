package helperserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDSMProfilePagesRequireRequestedOffset(t *testing.T) {
	dir := t.TempDir()
	cmd := filepath.Join(dir, "webapi")
	writeFile(t, cmd, "#!/bin/sh\ncase \" $* \" in *' offset=0 '*) cat \"$TEST_FIRST_PAGE\";; *' offset=200 '*) cat \"$TEST_SECOND_PAGE\";; *) exit 1;; esac\n")
	if err := os.Chmod(cmd, 0700); err != nil {
		t.Fatal(err)
	}
	users := map[string]systemAccount{}
	var rows []map[string]any
	for i := range 201 {
		name := fmt.Sprintf("acct%03d", i)
		users[name] = systemAccount{id: 2000 + i, description: name}
		rows = append(rows, map[string]any{"name": name, "uid": 2000 + i, "description": name, "email": "", "expired": "normal"})
	}
	page := func(path string, offset int, rows []map[string]any) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"success": true, "data": map[string]any{"offset": offset, "total": 201, "users": rows}})
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, string(data))
	}
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	t.Setenv("TEST_FIRST_PAGE", first)
	t.Setenv("TEST_SECOND_PAGE", second)
	page(first, 0, rows[:200])
	candidates := map[string]map[string]any{"acct000": {"display_name": "", "email": ""}, "acct200": {"display_name": "", "email": ""}}
	for _, offset := range []int{200, 0} {
		page(second, offset, rows[200:])
		got, err := readMatchingProfiles(context.Background(), cmd, users, candidates)
		if err != nil || (offset == 200 && !reflect.DeepEqual(got, []string{"acct000", "acct200"})) || (offset == 0 && len(got) != 0) {
			t.Fatalf("offset %d: %v %v", offset, got, err)
		}
	}
}

func TestUnchangedAccountsRequiresLiveProfileUIDAndEnrollment(t *testing.T) {
	cfg := policyTestConfig(t)
	for _, name := range []string{"alice", "bob"} {
		if err := updateAccountPolicy(cfg, name, false, false); err != nil {
			t.Fatal(err)
		}
	}
	cfg.SynoWebAPIPath = filepath.Join(t.TempDir(), "webapi")
	writeFile(t, cfg.SynoWebAPIPath, "#!/bin/sh\necho \"$TEST_DSM_PROFILE_PAGE\"\n")
	if err := os.Chmod(cfg.SynoWebAPIPath, 0700); err != nil {
		t.Fatal(err)
	}
	queries := batchMemberTestStore(t, []string{"alice", "bob"}, "engineering")
	s := NewWithStore(cfg, queries)
	alice := `{"name":"alice","uid":1026,"description":"Alice","email":"a@example.invalid","expired":"normal"}`
	bob := `{"name":"bob","uid":1027,"description":"Bob","email":"","expired":"normal"}`
	check := func(users string, want []string) {
		t.Helper()
		t.Setenv("TEST_DSM_PROFILE_PAGE", `{"success":true,"data":{"offset":0,"total":2,"users":[`+users+`]}}`)
		rows := []map[string]any{{"dsm_username": "alice", "display_name": "Alice", "email": "a@example.invalid"}, {"dsm_username": "bob", "display_name": "", "email": ""}}
		got := s.unchangedAccounts(context.Background(), cfg, rows)
		var names []string
		for _, row := range rows {
			name := row["dsm_username"].(string)
			if got[name] {
				names = append(names, name)
			}
		}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("confirmed %v, want %v", names, want)
		}
	}
	check(bob+","+alice, []string{"alice", "bob"})
	for _, changed := range []string{
		`{"name":"alice","uid":1050,"description":"Alice","email":"a@example.invalid","expired":"normal"}`,
		`{"name":"alice","uid":1026,"description":"Alice","email":"other@example.invalid","expired":"normal"}`,
		`{"name":"alice","uid":1026,"description":"changed","email":"a@example.invalid","expired":"normal"}`,
		`{"name":"alice","uid":1026,"description":"Alice","email":"a@example.invalid","expired":"expired"}`,
		`{"name":"alice","uid":1026}`,
	} {
		check(changed+","+bob, []string{"bob"})
	}
	check(alice+","+alice, nil)
	if _, err := queries.DBTX().ExecContext(context.Background(), "UPDATE identity_sources SET enabled=0"); err != nil {
		t.Fatal(err)
	}
	check(alice+","+bob, nil)
}
