package syncsvc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

func TestDirectoryOwnerChoiceAcrossProviders(t *testing.T) {
	for kind, label := range map[string]string{"dingtalk": "钉钉", "wecom": "企业微信", "feishu": "飞书"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			database, q := openSyncTestDB(t, ctx)
			defer database.Close()
			const slug = dingTalkTestSource
			if _, err := database.Exec("INSERT INTO identity_sources(slug,provider_type,display_name) VALUES(?,?,?)", slug, kind, label); err != nil {
				t.Fatal(err)
			}
			e := NewEngine(config.BackendConfig{}, q)
			e.localPasswd = filepath.Join(t.TempDir(), "passwd")
			e.localGroup = filepath.Join(t.TempDir(), "group")
			if err := os.WriteFile(e.localGroup, []byte("users:x:100:\nadministrators:x:101:localadmin\n"), 0600); err != nil {
				t.Fatal(err)
			}
			inventory := func(uid int) {
				t.Helper()
				if err := os.WriteFile(e.localPasswd, []byte(fmt.Sprintf("张三:x:%d:100::/:/bin/sh\n张三1:x:1802:100::/:/bin/sh\n王五:x:1803:100::/:/bin/sh\n", uid)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			inventory(1801)
			var users []provider.User
			for _, pair := range [][2]string{{"b", "张三"}, {"a", "张三"}, {"k", "同事"}, {"j", "同事"}, {"c", "王五"}, {"d", "新人"}} {
				users = append(users, dingTalkEmployee(pair[0], pair[1]))
			}
			roster := fakeDirectory{slug: slug, name: label, users: users, groups: []provider.Group{{ProviderSlug: slug, Subject: "dept", Name: "部门"}}}
			sync := func() {
				t.Helper()
				if _, err := e.SyncProvider(ctx, roster); err != nil {
					t.Fatal(err)
				}
			}
			sync()
			checkDingTalkNames(t, database, map[string]string{"c": "王五", "d": "新人", "j": "同事1", "k": "同事2"})
			ids := map[string]string{}
			reason := nativeUser{name: "张三", uid: 1801}.choiceReason()
			for _, sub := range []string{"a", "b"} {
				var id, stored string
				var links int
				err := database.QueryRow(`SELECT a.id,a.conflict_reason,(SELECT count(*) FROM dsm_mapping_entries m WHERE m.dsm_account_id=a.id AND m.active=1)
                    FROM dsm_accounts a JOIN external_accounts e ON e.app_identity_id=a.app_identity_id WHERE e.subject=? AND a.provision_status='conflict' AND a.allow_login=0`, sub).Scan(&id, &stored, &links)
				if err != nil || stored != reason || links != 0 {
					t.Fatalf("staged %s: %q, %d mappings, %v", sub, stored, links, err)
				}
				ids[sub] = id
			}
			choose := func(id, sub string) error {
				tx, err := database.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer tx.Rollback()
				worker := NewEngine(e.cfg, db.New(tx))
				worker.localPasswd, worker.localGroup = e.localPasswd, e.localGroup
				if err := worker.ChooseDirectoryOwner(ctx, slug, id, sub, reason); err != nil {
					return err
				}
				return tx.Commit()
			}
			inventory(1810)
			if err := choose(ids["a"], "a"); err == nil {
				t.Fatal("accepted stale NAS UID")
			}
			inventory(1801)
			if err := choose(ids["a"], "b"); err == nil {
				t.Fatal("accepted wrong employee")
			}
			if _, err := database.Exec("UPDATE dsm_accounts SET manual_login_blocked=1 WHERE id=?", ids["a"]); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := choose(ids["a"], "a"); err != nil {
					t.Fatal(err)
				}
			}
			if err := choose(ids["b"], "b"); err == nil {
				t.Fatal("two people selected for one account")
			}
			slices.Reverse(roster.users)
			for i := 0; i < 2; i++ {
				sync()
				checkDingTalkNames(t, database, map[string]string{"a": "张三", "b": "张三2", "c": "王五", "d": "新人", "j": "同事1", "k": "同事2"})
				assertTableCount(t, ctx, database, "directory_owner_choices", 1)
			}
			otherUser := dingTalkEmployee("other-sub", "张三")
			otherUser.ProviderSlug = "other"
			other := fakeDirectory{slug: "other", name: "飞书", users: []provider.User{otherUser}, groups: []provider.Group{{ProviderSlug: "other", Subject: "dept", Name: "部门"}}}
			if _, err := e.SyncProvider(ctx, other); err != nil {
				t.Fatal(err)
			}
			var assigned string
			if err := database.QueryRow("SELECT a.dsm_username FROM dsm_accounts a JOIN external_accounts e ON e.app_identity_id=a.app_identity_id WHERE e.subject='other-sub'").Scan(&assigned); err != nil || assigned != "张三3" {
				t.Fatalf("new namesake from another source: %q %v", assigned, err)
			}
			var allow int
			if err := database.QueryRow("SELECT allow_login FROM dsm_accounts WHERE id=?", ids["a"]).Scan(&allow); err != nil || allow != 0 {
				t.Fatalf("manual block: %d %v", allow, err)
			}
			for _, tc := range []struct {
				uid     int
				allowed bool
			}{{1801, true}, {1888, false}} {
				got, err := db.HelperAccountAllowed(ctx, q, db.HelperAuthorizationQuery{Action: "directory_account_match", Username: "张三", LocalUID: tc.uid})
				if err != nil || got != tc.allowed {
					t.Fatalf("match for UID %d = %v, %v", tc.uid, got, err)
				}
			}
		})
	}
}

func TestUniqueDirectoryNamesRespectExistingCaseAndPrivileges(t *testing.T) {
	ctx := context.Background()
	database, q := openSyncTestDB(t, ctx)
	defer database.Close()
	e := NewEngine(config.BackendConfig{}, q)
	dir := t.TempDir()
	e.localGroup = filepath.Join(dir, "group")
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(e.localGroup, []byte("users:x:100:\nadministrators:x:101:\nadmins-alias:x:101:Boss\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwd, []byte("Boss:x:1800:100::/:/bin/sh\nBOSS1:x:1801:100::/:/bin/sh\nAlice:x:1802:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users := []provider.User{dingTalkEmployee("a", "alice"), dingTalkEmployee("b", "boss")}
	result, err := e.directoryNames(ctx, dingTalkTestSource, "钉钉", users, passwd)
	if err != nil || result["a"].username != "Alice" || result["b"].username != "boss2" {
		t.Fatalf("%v %v", result, err)
	}
}
