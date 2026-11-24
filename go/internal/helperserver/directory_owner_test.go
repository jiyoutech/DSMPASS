package helperserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryOwnerHelperLinksOnlyOrdinaryLiveAccounts(t *testing.T) {
	for _, tc := range []struct {
		name, kind, username, change, expiry string
		selected, allowed                    bool
	}{
		{name: "selected DingTalk namesake", kind: "dingtalk", selected: true, allowed: true},
		{name: "selected Feishu namesake", kind: "feishu", selected: true, allowed: true},
		{name: "selected WeCom namesake", kind: "wecom", selected: true, allowed: true},
		{name: "unique Feishu", kind: "feishu", allowed: true},
		{name: "unique WeCom", kind: "wecom", allowed: true},
		{name: "ambiguous Feishu", kind: "feishu", change: "INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,display_name,active) VALUES ('other','source','x','x','user','alice',1)"},
		{name: "UID replaced", kind: "feishu", selected: true, change: "UPDATE directory_owner_choices SET uid=1999"},
		{name: "subject replaced", kind: "feishu", selected: true, change: "UPDATE external_accounts SET subject='replacement'"},
		{name: "inactive", kind: "wecom", selected: true, change: "UPDATE external_accounts SET active=0"},
		{name: "administrator", kind: "dingtalk", username: "operator", selected: true},
		{name: "expired account", kind: "wecom", expiry: "true"},
		{name: "unknown account state", kind: "wecom", expiry: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policyTestConfig(t)
			name := tc.username
			if name == "" {
				name = "alice"
			}
			q := syncedPasswordTestStore(t, name)
			exec := func(stmt string, args ...any) {
				t.Helper()
				if _, err := q.DBTX().ExecContext(context.Background(), stmt, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec("UPDATE identity_sources SET provider_type=?", tc.kind)
			exec("UPDATE external_accounts SET display_name=?", name)
			if tc.selected {
				exec("UPDATE dsm_accounts SET managed=0")
				uid := 1026
				if name == "operator" {
					uid = 1028
				}
				exec("INSERT INTO directory_owner_choices(account_id,external_id,source_slug,subject,username,uid) VALUES('account','external','source','subject',?,?)", name, uid)
			}
			if tc.change != "" {
				exec(tc.change)
			}
			expired := tc.expiry
			if expired == "" {
				expired = "false"
			}
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			if err := os.WriteFile(cfg.SynoUserPath, []byte("#!/bin/sh\n[ \"$1\" = --get ] || { touch \"$0.write\"; exit 1; }\necho 'Expired : ["+expired+"]'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			srv := NewWithStore(cfg, q)
			for i := 0; i < 2; i++ {
				result := srv.provisionAccount(context.Background(), cfg, map[string]any{"dsm_username": name, "display_name": "changed"})
				if (result["success"] == true) != tc.allowed || result["created"] == true {
					t.Fatal(result)
				}
			}
			if _, err := os.Stat(cfg.SynoUserPath + ".write"); !os.IsNotExist(err) {
				t.Fatal("unexpected DSM write", err)
			}
			err := srv.authorizeLogin(cfg, map[string]any{"dsm_username": name, "identity_id": "identity", "login_source": "source"})
			if err == nil || (tc.allowed && !errors.Is(err, errDirectoryMembershipOnly)) {
				t.Fatal("unexpected login result", err)
			}
		})
	}
}
