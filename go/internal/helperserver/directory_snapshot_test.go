package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A one-row first page forces traversal even when all requested names appear on it.
func TestCompleteDSMProfilesRetriesOnlyFailedPage(t *testing.T) {
	dir := t.TempDir()
	cmd := filepath.Join(dir, "webapi")
	log := filepath.Join(dir, "calls")
	t.Setenv("CALLS", log)
	t.Setenv("SECOND", filepath.Join(dir, "second"))
	script := `#!/bin/sh
case " $* " in
 *' offset=0 '*) echo 0 >> "$CALLS"; echo '{"success":true,"data":{"offset":0,"total":2,"users":[{"name":"a","uid":1025}]}}';;
 *' offset=1 '*) echo 1 >> "$CALLS"; if [ "$(wc -l < "$CALLS")" -eq 2 ]; then exit 1; fi; cat "$SECOND";;
 *) exit 1;;
esac
`
	if err := os.WriteFile(cmd, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	local := map[string]systemAccount{"a": {id: 1025}, "b": {id: 1026}}
	for _, tc := range []struct {
		label, second string
		good          bool
	}{
		{"complete", `{"offset":1,"total":2,"users":[{"name":"b","uid":1026}]}`, true},
		{"duplicate", `{"offset":1,"total":2,"users":[{"name":"a","uid":1025}]}`, false},
		{"gap", `{"offset":1,"total":2,"users":[]}`, false},
		{"wrong_offset", `{"offset":0,"total":2,"users":[{"name":"b","uid":1026}]}`, false},
		{"changed_total", `{"offset":1,"total":1,"users":[]}`, false},
		{"changed_uid", `{"offset":1,"total":2,"users":[{"name":"b","uid":1034}]}`, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			writeFile(t, log, "")
			writeFile(t, os.Getenv("SECOND"), `{"success":true,"data":`+tc.second+"}")
			rows, err := completeDSMProfiles(context.Background(), cmd, local)
			calls, e := os.ReadFile(log)
			if e != nil || string(calls) != "0\n1\n1\n" || tc.good != (err == nil) || (tc.good && len(rows) != 2) || (!tc.good && rows != nil) {
				t.Fatalf("calls=%q rows=%d err=%v", calls, len(rows), err)
			}
		})
	}
}

func TestDirectoryCaptureMatchesOnlyItsRunAndRechecksCurrentUIDs(t *testing.T) {
	cfg := policyTestConfig(t)
	dir := t.TempDir()
	cfg.SynoWebAPIPath = filepath.Join(dir, "list")
	t.Setenv("PAGE", filepath.Join(dir, "page"))
	t.Setenv("READS", filepath.Join(dir, "reads"))
	if err := os.WriteFile(cfg.SynoWebAPIPath, []byte("#!/bin/sh\necho read >> \"$READS\"\ncat \"$PAGE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	current := func(name string) {
		writeFile(t, os.Getenv("PAGE"), `{"success":true,"data":{"offset":0,"total":1,"users":[{"name":"`+name+`","uid":2020,"email":"","description":"test","expired":"normal"}]}}`)
	}
	local := func(name string) { writeFile(t, cfg.PasswdPath, name+":x:2020:100:test:/:/bin/false\n") }
	local("first")
	current("first")
	s := NewWithStore(cfg, batchMemberTestStore(t, []string{"first", "second", "new"}, "engineering"))
	begin := func(id string) {
		t.Helper()
		if got := s.captureDirectory(context.Background(), cfg, id); got["success"] != true {
			t.Fatal(got)
		}
	}
	request := func(id string) map[string]any {
		return map[string]any{"request_id": id, "snapshot_id": id, "dsm_users": []any{
			map[string]any{"dsm_username": "first", "display_name": "test", "email": ""},
			map[string]any{"dsm_username": "second", "display_name": "test", "email": ""},
			map[string]any{"dsm_username": "new", "display_name": "test", "email": ""},
		}}
	}
	begin("a")
	defer s.releaseDirectory("a")
	local("second")
	current("second")
	begin("b")
	defer s.releaseDirectory("b")
	if got := s.captureDirectory(context.Background(), cfg, "b"); got["success"] != false {
		t.Fatal("overwrote a live capture")
	}
	writeFile(t, os.Getenv("READS"), "")
	for _, tc := range []struct{ id, want string }{{"a", "rrm"}, {"b", "mrm"}} {
		if got := s.directorySnapshot(context.Background(), cfg, request(tc.id)); got["states"] != tc.want {
			t.Fatal(tc, got)
		}
	}
	if reads, err := os.ReadFile(os.Getenv("READS")); err != nil || len(reads) != 0 {
		t.Fatal("captured profiles re-read", string(reads), err)
	}
	s.releaseDirectory("b")
	writeFile(t, os.Getenv("PAGE"), "invalid")
	if got := s.directorySnapshot(context.Background(), cfg, request("b")); got["success"] != false {
		t.Fatal("expired capture used partial data")
	}
	current("second")
	if got := s.directorySnapshot(context.Background(), cfg, request("b")); got["states"] != "mrm" {
		t.Fatal("failed to refresh expired complete capture", got)
	}
}
