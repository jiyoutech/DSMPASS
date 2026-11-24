package syncsvc

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/identity"
	"github.com/dsmpass/dsmpass/go/internal/provider"
)

const dingTalkTestSource = "corp-hr"

func dingTalkEmployee(id, name string) provider.User {
	return provider.User{ProviderSlug: dingTalkTestSource, Subject: id, DisplayName: name, Active: true, DepartmentSubjects: []string{"dept"}}
}

func syncDingTalkEmployees(t *testing.T, e *Engine, users ...provider.User) {
	t.Helper()
	_, err := e.SyncProvider(context.Background(), fakeDirectory{slug: dingTalkTestSource, name: "钉钉", users: users,
		groups: []provider.Group{{ProviderSlug: dingTalkTestSource, Subject: "dept", Name: "部门"}}})
	if err != nil {
		t.Fatal(err)
	}
}

func checkDingTalkNames(t *testing.T, database *sql.DB, names map[string]string) {
	t.Helper()
	for subject, want := range names {
		var name string
		var userLinks, memberLinks int
		err := database.QueryRow(`SELECT a.dsm_username,
 (SELECT COUNT(*) FROM dsm_mapping_entries m WHERE m.dsm_account_id=a.id AND m.external_account_id=e.id AND m.active=1 AND m.mapping_type='user'),
 (SELECT COUNT(*) FROM group_members g WHERE g.dsm_account_id=a.id AND g.active=1)
FROM external_accounts e JOIN dsm_accounts a ON a.app_identity_id=e.app_identity_id WHERE e.provider_slug=? AND e.subject=?`,
			dingTalkTestSource, subject).Scan(&name, &userLinks, &memberLinks)
		if err != nil || name != want || userLinks != 1 || memberLinks != 1 {
			t.Fatalf("subject %s: name=%q links=%d memberships=%d err=%v; want %q with both mappings", subject, name, userLinks, memberLinks, err, want)
		}
	}
}

func TestDingTalkNumbersAreStableAcrossSyncs(t *testing.T) {
	db, q := openSyncTestDB(t, context.Background())
	defer db.Close()
	e := NewEngine(config.BackendConfig{}, q)
	a, b, literal := dingTalkEmployee("a", "张三"), dingTalkEmployee("b", "张三"), dingTalkEmployee("z", "张三1")
	syncDingTalkEmployees(t, e, b, literal, a)
	checkDingTalkNames(t, db, map[string]string{"a": "张三2", "b": "张三3", "z": "张三1"})
	syncDingTalkEmployees(t, e, a, b, literal, dingTalkEmployee("0", "张三"))
	checkDingTalkNames(t, db, map[string]string{"a": "张三2", "b": "张三3", "0": "张三4", "z": "张三1"})

	// A subsequent provider must not link its literal "张三2" to a numbered account.
	other := fakeDirectory{slug: "feishu", users: []provider.User{{ProviderSlug: "feishu", Subject: "f", DisplayName: "张三2", Active: true, DepartmentSubjects: []string{"d"}}},
		groups: []provider.Group{{ProviderSlug: "feishu", Subject: "d", Name: "产品"}}}
	if _, err := e.SyncProvider(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	assertAccountStatusForSubject(t, context.Background(), db, "f", "conflict")
	assertTableCount(t, context.Background(), db, "app_identities", 5)
}

func TestDingTalkNewNamesakesKeepExistingAndManualNames(t *testing.T) {
	db, q := openSyncTestDB(t, context.Background())
	defer db.Close()
	e := NewEngine(config.BackendConfig{}, q)
	a, b, c := dingTalkEmployee("a", "李四"), dingTalkEmployee("b", "李四"), dingTalkEmployee("c", "李四")
	syncDingTalkEmployees(t, e, a)
	syncDingTalkEmployees(t, e, b, a)
	checkDingTalkNames(t, db, map[string]string{"a": "李四", "b": "李四1"})
	if _, err := db.Exec("UPDATE dsm_accounts SET managed=0, dsm_username='手工', dsm_username_norm='手工' WHERE dsm_username='李四'"); err != nil {
		t.Fatal(err)
	}
	syncDingTalkEmployees(t, e, c, a, b)
	checkDingTalkNames(t, db, map[string]string{"a": "手工", "b": "李四1", "c": "李四2"})
	// A newcomer arriving after all earlier employees have left still gets a distinct account.
	syncDingTalkEmployees(t, e, dingTalkEmployee("d", "李四"))
	checkDingTalkNames(t, db, map[string]string{"d": "李四3"})
}

func TestDingTalkRecoversOnlyUnmappedLegacyConflicts(t *testing.T) {
	db, q := openSyncTestDB(t, context.Background())
	defer db.Close()
	e := NewEngine(config.BackendConfig{}, q)
	a, b, c := dingTalkEmployee("a", "赵五"), dingTalkEmployee("b", "赵五"), dingTalkEmployee("c", "赵五")
	syncDingTalkEmployees(t, e, a, b, c)
	for _, stmt := range []string{
		"DELETE FROM dsm_mapping_entries WHERE mapping_type='user' AND dsm_account_id IN (SELECT id FROM dsm_accounts WHERE dsm_username IN ('赵五1','赵五2'))",
		"UPDATE dsm_accounts SET provision_status='conflict',allow_login=0,conflict_reason=?",
		"UPDATE dsm_accounts SET dsm_username='赵五',dsm_username_norm='赵五',manual_login_blocked=1 WHERE dsm_username='赵五1'",
		"UPDATE dsm_accounts SET dsm_username='赵五_conflict_test',dsm_username_norm='赵五_conflict_test' WHERE dsm_username='赵五2'",
	} {
		var args []any
		if strings.Contains(stmt, "?") {
			args = append(args, identity.LegacyDingTalkDuplicateReason)
		}
		if _, err := db.Exec(stmt, args...); err != nil {
			t.Fatal(err)
		}
	}
	syncDingTalkEmployees(t, e, c, b, a)
	checkDingTalkNames(t, db, map[string]string{"a": "赵五1", "b": "赵五2"})
	assertAccountStatusForSubject(t, context.Background(), db, "c", "conflict")
	var allowed int
	if err := db.QueryRow("SELECT allow_login FROM dsm_accounts WHERE dsm_username='赵五1'").Scan(&allowed); err != nil || allowed != 0 {
		t.Fatalf("manual login block was lost: %d %v", allowed, err)
	}
}

func TestDingTalkNumberingChecksNativeNamesAndLength(t *testing.T) {
	ctx := context.Background()
	db, q := openSyncTestDB(t, ctx)
	defer db.Close()
	e := NewEngine(config.BackendConfig{}, q)
	passwd := filepath.Join(t.TempDir(), "passwd")
	base := strings.Repeat("名", identity.DSMUsernameMaxLength)
	prefix := strings.TrimSuffix(base, "名")
	if err := os.WriteFile(passwd, []byte(prefix+"1:x:1026:100::/:/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users := []provider.User{dingTalkEmployee("b", base), dingTalkEmployee("a", base)}
	names, err := e.dingTalkNumberedNames(ctx, dingTalkTestSource, users, passwd)
	if err != nil || names["a"] != prefix+"2" || names["b"] != prefix+"3" {
		t.Fatalf("native collision or length: %v %v", names, err)
	}
	for i := 0; i < 8; i++ {
		users = append(users, dingTalkEmployee("c"+strconv.Itoa(i), base))
	}
	names, err = e.dingTalkNumberedNames(ctx, dingTalkTestSource, users, passwd)
	twoDigitBase := strings.TrimSuffix(prefix, "名")
	if err != nil || names["c6"] != twoDigitBase+"10" || names["c7"] != twoDigitBase+"11" {
		t.Fatalf("two-digit suffix: %v %v", names, err)
	}
	if _, err := e.dingTalkNumberedNames(ctx, dingTalkTestSource, users, passwd+".missing"); err == nil {
		t.Fatal("assigned names without a native account list")
	}
	if _, err := e.dingTalkNumberedNames(ctx, dingTalkTestSource, []provider.User{users[0], users[0]}, passwd); err == nil {
		t.Fatal("accepted non-unique source ID")
	}
	if names, err := e.dingTalkNumberedNames(ctx, dingTalkTestSource, nil, passwd+".missing"); err != nil || len(names) != 0 {
		t.Fatalf("empty input: %v %v", names, err)
	}
}
