package helperserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

func enrollBatchUsers(t *testing.T, cfg config.HelperConfig) {
	t.Helper()
	for _, name := range []string{"alice", "bob", "engineering"} {
		if err := updateAccountPolicy(cfg, name, name == "engineering", false); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGroupBatchCreationAndSelectiveAppend(t *testing.T) {
	cfg := policyTestConfig(t)
	enrollBatchUsers(t, cfg)
	t.Setenv("FIXTURE_GROUP", cfg.GroupPath)
	cfg.SynoGroupPath = filepath.Join(t.TempDir(), "synogroup")
	create := "#!/bin/sh\n[ \"$#\" = 4 ] && [ \"$1:$2:$3:$4\" = '--add:testing:alice:bob' ] || exit 1\necho 'testing:x:65538:alice,bob' >> \"$FIXTURE_GROUP\"\n"
	if err := os.WriteFile(cfg.SynoGroupPath, []byte(create), 0700); err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	names := []string{"alice", "bob"}
	confirmed, err := s.applyGroupMembers(cfg, "testing", names)
	if err != nil || !slices.Equal(confirmed, names) {
		t.Fatalf("create %v %v", confirmed, err)
	}
	if err := requireManagedGroup(cfg, "testing"); err != nil {
		t.Fatal(err)
	}
	cfg.SynoWebAPIPath = filepath.Join(t.TempDir(), "synowebapi")
	script := `#!/bin/sh
[ "$#" = 7 ] && [ "$1" = --exec ] && [ "$2" = api=SYNO.Core.Group.Member ] && [ "$3" = version=1 ] && [ "$4" = method=change ] && [ "$5" = 'group="engineering"' ] && [ "$6" = 'add_member=["bob"]' ] && [ "$7" = 'remove_member=[]' ] || exit 1
sed 's/^engineering:x:65536:alice$/engineering:x:65536:alice,bob/' "$FIXTURE_GROUP" > "$FIXTURE_GROUP.new" && mv "$FIXTURE_GROUP.new" "$FIXTURE_GROUP"
echo '{"success":true}'
`
	if err := os.WriteFile(cfg.SynoWebAPIPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := s.applyGroupMembers(cfg, "engineering", names); err != nil || !slices.Equal(got, names) {
		t.Fatalf("append %v %v", got, err)
	}
	cfg.SynoWebAPIPath = "/missing-command"
	if got, err := s.applyGroupMembers(cfg, "engineering", []string{"bob", "alice"}); err != nil || !slices.Equal(got, []string{"bob", "alice"}) {
		t.Fatalf("repeat %v %v", got, err)
	}
}

func TestGroupBatchPreflightAndPartialReadback(t *testing.T) {
	cfg := policyTestConfig(t)
	enrollBatchUsers(t, cfg)
	s := &Server{}
	for _, names := range [][]any{nil, {"alice", "alice"}, {1}, {"root"}, make([]any, helperclient.GroupMemberBatchSize+1)} {
		resp := s.addGroupMembers(cfg, map[string]any{"dsm_groupname": "engineering", "dsm_usernames": names})
		if resp["error_code"] != "BAD_REQUEST" {
			t.Fatalf("unexpected validation response %v", resp)
		}
	}
	for _, group := range []string{"engineering", "finance", "administrators"} {
		users := []string{"alice", "operator"}
		if group != "engineering" {
			users = []string{"bob"}
		}
		if confirmed, err := s.applyGroupMembers(cfg, group, users); err == nil || len(confirmed) > 0 || errors.Is(err, helperclient.ErrGroupBatchUnsupported) {
			t.Fatalf("invalid batch allowed %s: %v %v", group, confirmed, err)
		}
	}
	cfg.SynoWebAPIPath = filepath.Join(t.TempDir(), "synowebapi")
	for _, tc := range []struct {
		response    string
		unsupported bool
	}{
		{`{"success":false,"error":{"code":103}}`, true},
		{`{"success":false,"error":{"code":105}}`, false},
		{`{"success":true}`, false},
		{"broken-json", false},
	} {
		if err := os.WriteFile(cfg.SynoWebAPIPath, []byte("#!/bin/sh\necho '"+tc.response+"'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		confirmed, err := s.applyGroupMembers(cfg, "engineering", []string{"bob", "alice"})
		if err == nil || errors.Is(err, helperclient.ErrGroupBatchUnsupported) != tc.unsupported {
			t.Fatalf("%s: %v", tc.response, err)
		}
		if !tc.unsupported && !slices.Equal(confirmed, []string{"alice"}) {
			t.Fatalf("incorrect partial confirmation: %v", confirmed)
		}
	}
	noGroupDB := cfg
	noGroupDB.GroupPath = filepath.Join(t.TempDir(), "missing")
	if _, err := s.applyGroupMembers(noGroupDB, "engineering", []string{"alice"}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatal(err)
	}
}

func TestGroupBatchRechecksGroupIdentityAfterDSMWrite(t *testing.T) {
	cfg := policyTestConfig(t)
	enrollBatchUsers(t, cfg)
	t.Setenv("FIXTURE_GROUP", cfg.GroupPath)
	cfg.SynoWebAPIPath = filepath.Join(t.TempDir(), "synowebapi")
	script := `#!/bin/sh
sed 's/^engineering:x:65536:alice$/engineering:x:65539:alice,bob/' "$FIXTURE_GROUP" > "$FIXTURE_GROUP.new" && mv "$FIXTURE_GROUP.new" "$FIXTURE_GROUP"
echo '{"success":true}'
`
	if err := os.WriteFile(cfg.SynoWebAPIPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	confirmed, err := (&Server{}).applyGroupMembers(cfg, "engineering", []string{"bob"})
	if err == nil || !strings.Contains(err.Error(), "GID changed") || len(confirmed) != 0 {
		t.Fatalf("replaced group: %v %v", confirmed, err)
	}
}

func TestGroupBatchRestrictedAccountCannotCreateOrClaimGroup(t *testing.T) {
	cfg := policyTestConfig(t)
	enrollBatchUsers(t, cfg)
	policy, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	delete(policy.Users, "bob")
	policy.DirectoryUsers = map[string]directoryUserGrant{"bob": {UID: 1027, Groups: map[string]int{"finance": 65537}}}
	if err := saveAccountPolicy(cfg, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Server{}).applyGroupMembers(cfg, "newgroup", []string{"alice", "bob"}); !errors.Is(err, helperclient.ErrGroupBatchUnsupported) {
		t.Fatalf("mixed grants must follow single-member creation order: %v", err)
	}
	if _, err := normalGroup(cfg, "newgroup"); err != os.ErrNotExist {
		t.Fatal("group created before authorization")
	}
	if confirmed, err := (&Server{}).applyGroupMembers(cfg, "engineering", []string{"alice", "bob"}); err == nil || errors.Is(err, helperclient.ErrGroupBatchUnsupported) || len(confirmed) > 0 {
		t.Fatalf("unauthorized member: %v %v", confirmed, err)
	}
}

func TestGroupBatchSize200And201(t *testing.T) {
	cfg := policyTestConfig(t)
	var passwd, group strings.Builder
	passwd.WriteString("root:x:0:0::/:/bin/sh\n")
	names := make([]any, 201)
	policy := accountPolicy{Users: map[string]int{}, Groups: map[string]int{"engineering": 65536}}
	for i := range names {
		name := fmt.Sprintf("user%03d", i)
		names[i] = name
		policy.Users[name] = 1026 + i
		fmt.Fprintf(&passwd, "%s:x:%d:100::/:/bin/sh\n", name, 1026+i)
		if i > 0 {
			group.WriteByte(',')
		}
		group.WriteString(name)
	}
	writeFile(t, cfg.PasswdPath, passwd.String())
	writeFile(t, cfg.GroupPath, "users:x:100:\nadministrators:x:101:\nengineering:x:65536:"+group.String()+"\n")
	if err := saveAccountPolicy(cfg, policy); err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	call := func(n int) map[string]any {
		return server.addGroupMembers(cfg, map[string]any{"dsm_groupname": "engineering", "dsm_usernames": names[:n]})
	}
	if r := call(201); r["error_code"] != "BAD_REQUEST" {
		t.Fatal(r)
	}
	if r := call(200); r["success"] != true || r["batch_error"] != nil || len(r["confirmed"].([]string)) != 200 {
		t.Fatal(r)
	}
	delete(policy.Users, "user199")
	policy.DirectoryUsers = map[string]directoryUserGrant{"user199": {UID: 1225}}
	if err := saveAccountPolicy(cfg, policy); err != nil {
		t.Fatal(err)
	}
	if r := call(200); r["batch_error"] == nil || len(r["confirmed"].([]string)) != 0 {
		t.Fatal(r)
	}

	var targets []string
	policy.DirectoryUsers = map[string]directoryUserGrant{}
	for _, v := range names[:200] {
		name := v.(string)
		targets = append(targets, name)
		policy.DirectoryUsers[name] = directoryUserGrant{UID: 1026 + len(targets) - 1, Groups: map[string]int{"engineering": 65536}}
		delete(policy.Users, name)
	}
	if err := saveAccountPolicy(cfg, policy); err != nil {
		t.Fatal(err)
	}
	q := batchMemberTestStore(t, targets, "engineering")
	server = NewWithStore(cfg, q)
	if r := call(200); r["batch_error"] != nil || len(r["confirmed"].([]string)) != 200 {
		t.Fatal(r)
	}
	if _, err := q.DBTX().ExecContext(context.Background(), "UPDATE dsm_mapping_entries SET active=0 WHERE id='member-user199'"); err != nil {
		t.Fatal(err)
	}
	if r := call(200); r["batch_error"] == nil || len(r["confirmed"].([]string)) != 0 {
		t.Fatal(r)
	}
}

func batchMemberTestStore(t *testing.T, names []string, group string) *db.Queries {
	t.Helper()
	q := syncedPasswordTestStore(t, "unused-seed")
	addEngineeringMapping(t, q)
	ctx := context.Background()
	if _, err := q.DBTX().ExecContext(ctx, "UPDATE dsm_groups SET dsm_groupname=?,dsm_groupname_norm=? WHERE id='group'", group, group); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO app_identities(id,status) SELECT value,'active' FROM json_each(?)`,
		`INSERT INTO external_accounts(id,provider_slug,subject,subject_norm,subject_type,app_identity_id,active,display_name) SELECT value,'source',value,value,'directory_subject',value,1,value FROM json_each(?)`,
		`INSERT INTO dsm_accounts(id,app_identity_id,dsm_username,dsm_username_norm,provision_status) SELECT value,value,value,value,'linked_existing' FROM json_each(?)`,
		`INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,dsm_account_id) SELECT 'user-'||value,'user','source',value,value FROM json_each(?)`,
		`INSERT INTO group_members(id,dsm_group_id,dsm_account_id) SELECT value,'group',value FROM json_each(?)`,
		`INSERT INTO dsm_mapping_entries(id,mapping_type,provider_slug,external_account_id,provider_group_id,dsm_group_id,dsm_account_id) SELECT 'member-'||value,'member','source',value,'department','group',value FROM json_each(?)`,
	} {
		if _, err := q.DBTX().ExecContext(ctx, stmt, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	return q
}

func TestBatchMembershipPreservesPinnedSubjectAndSource(t *testing.T) {
	q := batchMemberTestStore(t, []string{"alice", "bob"}, "engineering")
	ctx := context.Background()
	check := func(scope db.HelperMemberScope, want bool) {
		t.Helper()
		ok, err := db.HelperAccountAllowed(ctx, q, db.HelperAuthorizationQuery{Action: "directory_member_batch", Groupname: "engineering", Members: []db.HelperMemberScope{scope}})
		if err != nil || ok != want {
			t.Fatalf("scope %+v: %v %v", scope, ok, err)
		}
	}
	scope := db.HelperMemberScope{Username: "alice", DingTalk: &db.DingTalkUserBinding{SourceSlug: "source", Subject: "alice"}}
	check(scope, false)
	scope.OtherGroup = true
	check(scope, true) // independently pinned non-DingTalk department
	if _, err := q.DBTX().ExecContext(ctx, "UPDATE identity_sources SET provider_type='dingtalk'"); err != nil {
		t.Fatal(err)
	}
	scope.OtherGroup = false
	check(scope, true)
	scope.DingTalk.Subject = "other"
	scope.OtherGroup = true
	check(scope, false)
	scope.DingTalk = nil
	check(scope, true) // existing general department grant still requires an unambiguous identity
	if _, err := q.DBTX().ExecContext(ctx, "UPDATE external_accounts SET display_name='alice' WHERE id='bob'"); err != nil {
		t.Fatal(err)
	}
	check(scope, false)
}

func TestPrepareMissingGroupDefersOnlyUntilMemberBatch(t *testing.T) {
	cfg := policyTestConfig(t)
	enrollBatchUsers(t, cfg)
	cfg.SynoGroupPath = filepath.Join(t.TempDir(), "no-native-command")
	s := &Server{}
	prepare := func(name string) map[string]any {
		return s.mutateGroup(cfg, "scoped_provision_group", map[string]any{"dsm_groupname": name, "defer_if_missing": true})
	}
	if got := prepare("testing"); got["success"] != true || got["deferred"] != true || got["created"] != false {
		t.Fatal(got)
	}
	target := creationTarget{cfg: cfg, name: "testing", group: true}
	if _, err := os.Stat(target.path()); !os.IsNotExist(err) {
		t.Fatalf("unexpected write for missing group: %v", err)
	}
	if got := prepare("engineering"); got["success"] != true || got["created"] != true {
		t.Fatal(got)
	}
	if got := prepare("administrators"); got["success"] != false {
		t.Fatal(got)
	}
}
