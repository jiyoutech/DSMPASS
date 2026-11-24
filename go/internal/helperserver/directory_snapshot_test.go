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
