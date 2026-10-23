package helperserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestNativeGroupRemovalUsesSingleMemberAPIAndChecksResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		allowed    bool
	}{
		{"success", `printf '%s' '{"success":true}'`, true},
		{"api_failure_with_zero_exit", `printf '%s' '{"success":false,"error":{"code":101}}'`, false},
		{"missing_success", `printf '%s' '{}'`, false},
		{"malformed_response", `printf '%s' 'not JSON'`, false},
		{"native_command_failure", `exit 2`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "synowebapi")
			body := `#!/bin/sh
[ "$#" = 6 ] && [ "$1" = --exec ] && [ "$2" = api=SYNO.Core.Group.Member ] && [ "$3" = method=remove ] && [ "$4" = version=1 ] && [ "$5" = 'group="engineering team"' ] && [ "$6" = 'name=["alice"]' ] || exit 9
` + tc.body + "\n"
			if err := os.WriteFile(path, []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			err := removeNativeGroupMember(config.HelperConfig{SynoWebAPIPath: path}, "engineering team", "alice")
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
		})
	}
	if err := removeNativeGroupMember(config.HelperConfig{}, "engineering", "alice"); err == nil {
		t.Fatal("missing API command was silently accepted")
	}
}
