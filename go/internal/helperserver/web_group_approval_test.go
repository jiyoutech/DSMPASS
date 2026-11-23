package helperserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func webApprovalFixture(t *testing.T) (config.HelperConfig, *db.Queries, *Server) {
	t.Helper()
	cfg := policyTestConfig(t)
	cfg.SynoWebAPIPath = filepath.Join(t.TempDir(), "synowebapi")
	script := "#!/bin/sh\n[ \"$#\" = 5 ] && [ \"$1\" = --exec ] && [ \"$2\" = api=SYNO.Core.Group ] && [ \"$3\" = method=get ] && [ \"$4\" = version=1 ] && [ \"$5\" = 'name=\"engineering\"' ] || exit 3\ncat \"$0.json\"\n"
	if err := os.WriteFile(cfg.SynoWebAPIPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	q := syncedPasswordTestStore(t, "alice")
	addEngineeringMapping(t, q)
	return cfg, q, NewWithStore(cfg, q)
}

func writeNativeGroup(t *testing.T, cfg config.HelperConfig, name string, gid int, description string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"success": true, "data": map[string]any{"errors": []any{}, "groups": []map[string]any{{"name": name, "gid": gid, "description": description}}}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.SynoWebAPIPath+".json", string(data))
}

func TestWebGroupApprovalRequiresNativeConfirmation(t *testing.T) {
	cfg, q, s := webApprovalFixture(t)
	run := func(verify bool) map[string]any {
		return s.webGroupApproval(cfg, map[string]any{"dsm_groupname": "engineering", "verify": verify, "code": "untrusted"})
	}
	if run(true)["success"] == true {
		t.Fatal("granted without a challenge")
	}
	first := run(false)
	code, ok := first["code"].(string)
	if !ok || !strings.HasPrefix(code, "DP-") || first["approved"] != false || first["gid"] != 65536 {
		t.Fatal(first)
	}
	s = NewWithStore(cfg, q)
	if r := run(false); r["code"] != code {
		t.Fatal("lost challenge on restart")
	}
	for _, tc := range []struct {
		name string
		gid  int
		desc string
	}{
		{"engineering", 65536, "existing description"}, {"engineering", 65536, code + "0"}, {"finance", 65536, code}, {"engineering", 65540, code},
	} {
		writeNativeGroup(t, cfg, tc.name, tc.gid, tc.desc)
		if run(true)["success"] == true {
			t.Fatal("wrong group, GID or description accepted")
		}
	}
	writeFile(t, cfg.SynoWebAPIPath+".json", `{"success":true,"data":{"groups":[]}}`)
	if run(true)["success"] == true {
		t.Fatal("accepted empty native result")
	}
	writeFile(t, cfg.SynoWebAPIPath+".json", "invalid")
	if run(true)["success"] == true {
		t.Fatal("accepted invalid native response")
	}
	writeNativeGroup(t, cfg, "engineering", 65536, "原有说明 "+code)
	// Recover a group even when interrupted creation left an unconfirmed receipt.
	target := creationTarget{cfg: cfg, name: "engineering", group: true}
	if err := target.begin(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if r := run(true); r["approved"] != true {
			t.Fatal(r)
		}
	}
	if err := requireManagedGroup(cfg, "engineering"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target.path()); !os.IsNotExist(err) {
		t.Fatalf("receipt remains: %v", err)
	}
	if err := updateAccountPolicy(cfg, "engineering", true, true); err != nil {
		t.Fatal(err)
	}
	if run(true)["success"] == true {
		t.Fatal("old description undid a revocation")
	}
	if r := run(false); r["code"] == code || r["success"] != true {
		t.Fatal(r)
	}
	if run(true)["success"] == true {
		t.Fatal("old approval code accepted")
	}
}

func TestWebGroupApprovalRechecksMappingGIDExpiryAndRevocation(t *testing.T) {
	for _, change := range []string{"mapping", "expired", "recreated", "revoked"} {
		t.Run(change, func(t *testing.T) {
			cfg, q, s := webApprovalFixture(t)
			p := map[string]any{"dsm_groupname": "engineering", "verify": false}
			r := s.webGroupApproval(cfg, p)
			code, ok := r["code"].(string)
			if !ok {
				t.Fatal(r)
			}
			writeNativeGroup(t, cfg, "engineering", 65536, code)
			switch change {
			case "mapping":
				if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_mapping_entries SET active=0"); err != nil {
					t.Fatal(err)
				}
			case "expired":
				policy, err := readAccountPolicy(cfg)
				if err != nil {
					t.Fatal(err)
				}
				ticket := policy.WebApprovals["engineering"]
				ticket.ExpiresAt = 1
				policy.WebApprovals["engineering"] = ticket
				if err := saveAccountPolicy(cfg, policy); err != nil {
					t.Fatal(err)
				}
			case "recreated":
				writeFile(t, cfg.GroupPath, "administrators:x:101:\nengineering:x:65538:\n")
			case "revoked":
				if err := updateAccountPolicy(cfg, "engineering", true, true); err != nil {
					t.Fatal(err)
				}
			}
			p["verify"] = true
			if r := s.webGroupApproval(cfg, p); r["success"] == true {
				t.Fatal(r)
			}
			if err := requireManagedGroup(cfg, "engineering"); err == nil {
				t.Fatal("unexpected grant")
			}
		})
	}
}

func TestWebGroupApprovalSkipsAutomaticGroupsAndRejectsOtherTargets(t *testing.T) {
	cfg, _, s := webApprovalFixture(t)
	if _, err := migrateAccountPolicy(cfg, false, emptyDirectorySnapshot); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "administrators", "users", "finance", "missing"} {
		if r := s.webGroupApproval(cfg, map[string]any{"dsm_groupname": name, "verify": false}); r["success"] == true {
			t.Fatal(r)
		}
	}
	if r := s.webGroupApproval(cfg, map[string]any{"dsm_groupname": "engineering", "verify": false}); r["approved"] != true || r["code"] != nil {
		t.Fatal(r)
	}
}

func TestNormalProvisionFinishesPendingWebGroupApproval(t *testing.T) {
	cfg, _, s := webApprovalFixture(t)
	req := map[string]any{"dsm_groupname": "engineering", "verify": false}
	code, ok := s.webGroupApproval(cfg, req)["code"].(string)
	if !ok {
		t.Fatal("missing ticket")
	}
	writeNativeGroup(t, cfg, "engineering", 65536, "before confirmation")
	if r := s.mutateGroup(cfg, "scoped_provision_group", req); r["success"] == true {
		t.Fatal("unconfirmed group went through")
	}
	writeNativeGroup(t, cfg, "engineering", 65536, "项目资料 "+code)
	if r := s.mutateGroup(cfg, "scoped_provision_group", req); r["success"] != true {
		t.Fatal(r)
	}
	if err := requireManagedGroup(cfg, "engineering"); err != nil {
		t.Fatal(err)
	}
}
