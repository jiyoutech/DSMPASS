package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionPreservesNativeDisable(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	s := NewWithStore(cfg, syncedPasswordTestStore(t, "alice"))
	for _, expiry := range []string{"true", "unknown"} {
		script := "#!/bin/sh\ncase \"$1\" in\n--get) echo 'Expired : [" + expiry + "]';;\n*) touch \"$0.modified\";;\nesac\n"
		if err := os.WriteFile(cfg.SynoUserPath, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		result := s.provisionAccount(context.Background(), cfg, map[string]any{"dsm_username": "alice", "display_name": "New"})
		if result["success"] == true || (expiry == "true" && result["error_code"] != "DSM_ACCOUNT_DISABLED") {
			t.Fatal(result)
		}
		if _, err := os.Stat(cfg.SynoUserPath + ".modified"); !os.IsNotExist(err) {
			t.Fatal("modified an account without a confirmed active state", err)
		}
	}
}
