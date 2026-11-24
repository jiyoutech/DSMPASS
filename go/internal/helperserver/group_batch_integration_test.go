//go:build dsm_integration && linux

package helperserver

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

type dsmBatchFixtures struct {
	cfg                     config.HelperConfig
	prefix                  string
	ownedUsers, ownedGroups map[string]int
}

func newBatchFixtures(t *testing.T, gate, value string) *dsmBatchFixtures {
	t.Helper()
	if os.Getenv(gate) != value {
		t.Skip("requires explicit DSM group test opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root on a DSM test host")
	}
	dir := t.TempDir()
	cfg := config.HelperConfig{
		PasswdPath: "/etc/passwd", GroupPath: "/etc/group", SynoUserPath: dsmIntegrationSynouserPath,
		SynoGroupPath: "/usr/syno/sbin/synogroup", SynoWebAPIPath: "/usr/syno/bin/synowebapi",
		AccountPolicyPath: filepath.Join(dir, "policy.json"), ShadowLockPath: filepath.Join(dir, "writer.lock"),
	}
	var nonce [5]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	f := &dsmBatchFixtures{cfg: cfg, prefix: fmt.Sprintf("dspbt%x", nonce), ownedUsers: map[string]int{}, ownedGroups: map[string]int{}}
	t.Logf("synthetic fixture prefix %s", f.prefix)
	t.Cleanup(func() {
		start := time.Now()
		for _, isGroup := range []bool{true, false} {
			path, command, records := f.table(isGroup)
			for name, id := range records {
				accounts, err := systemAccounts(path, isGroup)
				if err != nil {
					t.Errorf("cleanup: %v", err)
					break
				}
				a, exists := accounts[name]
				if !exists {
					continue
				}
				if a.id != id {
					t.Errorf("fixture %s changed identity; skipping deletion", name)
					continue
				}
				if err := run(command, "--del", name); err != nil {
					t.Errorf("delete %s: %v", name, err)
				}
			}
			after, err := systemAccounts(path, isGroup)
			if err != nil {
				t.Error(err)
				continue
			}
			for name := range records {
				if _, ok := after[name]; ok {
					t.Errorf("fixture %s still exists", name)
				}
			}
			t.Logf("cleanup verified group=%t count=%d elapsed=%s", isGroup, len(records), time.Since(start).Round(time.Millisecond))
		}
	})
	return f
}

func (f *dsmBatchFixtures) table(group bool) (string, string, map[string]int) {
	if group {
		return f.cfg.GroupPath, f.cfg.SynoGroupPath, f.ownedGroups
	}
	return f.cfg.PasswdPath, f.cfg.SynoUserPath, f.ownedUsers
}

func (f *dsmBatchFixtures) create(t *testing.T, name string, group bool, fn func() error) {
	t.Helper()
	path, _, records := f.table(group)
	before, err := systemAccounts(path, group)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := before[name]; exists {
		t.Fatal("fixture name already in use")
	}
	writeErr := fn()
	after, err := systemAccounts(path, group)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := after[name]; ok {
		records[name] = a.id
	} else if writeErr == nil {
		t.Fatalf("created fixture %s is missing", name)
	}
	if writeErr != nil {
		t.Fatal(writeErr)
	}
}

func (f *dsmBatchFixtures) makeUser(t *testing.T, index int) string {
	t.Helper()
	name := fmt.Sprintf("%su%03d", f.prefix, index)
	f.create(t, name, false, func() error {
		// A disabled synthetic account still has a local UID and group memberships.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return runAccountCommand(ctx, f.cfg.SynoUserPath, "--add", name, "Aa2!"+randomPassword(30), "DSMPASS temporary batch test", "1", "", "")
	})
	if err := updateAccountPolicy(f.cfg, name, false, false); err != nil {
		t.Fatal(err)
	}
	return name
}

func (f *dsmBatchFixtures) members(group string, names, want []string) error {
	raw := make([]any, len(names))
	for i, name := range names {
		raw[i] = name
	}
	result := (&Server{}).addGroupMembers(f.cfg, map[string]any{"dsm_groupname": group, "dsm_usernames": raw})
	confirmed, _ := result["confirmed"].([]string)
	if result["batch_error"] != nil || result["success"] != true || !slices.Equal(confirmed, names) {
		return fmt.Errorf("batch result: %v", result)
	}
	actual, err := normalGroup(f.cfg, group)
	if err != nil {
		return err
	}
	slices.Sort(actual.members)
	if !slices.Equal(actual.members, want) {
		return fmt.Errorf("unexpected group membership for %s", group)
	}
	return nil
}

func TestDSMRealGroupMemberBatch(t *testing.T) {
	f := newBatchFixtures(t, "DSMPASS_DSM_GROUP_BATCH_INTEGRATION", "1")
	var users []string
	for i := range 4 {
		users = append(users, f.makeUser(t, i))
	}
	group := f.prefix + "g"
	start := time.Now()
	f.create(t, group, true, func() error { return f.members(group, users[:2], users[:2]) })
	t.Logf("create with two: %s", time.Since(start))
	start = time.Now()
	if err := f.members(group, users[2:], users); err != nil {
		t.Fatal(err)
	}
	t.Logf("append two preserving original members: %s", time.Since(start))
	start = time.Now()
	if err := f.members(group, users, users); err != nil {
		t.Fatal(err)
	}
	t.Logf("repeat unchanged: %s", time.Since(start))

	// Compare the single-member compatibility path on a second synthetic group.
	legacy := f.prefix + "h"
	f.create(t, legacy, true, func() error { return f.members(legacy, users[:2], users[:2]) })
	single := func(names []string) {
		t.Helper()
		for _, name := range names {
			result := (&Server{}).mutateGroup(f.cfg, "scoped_add_group_member", map[string]any{"dsm_username": name, "dsm_groupname": legacy})
			if result["success"] != true {
				t.Fatal(result)
			}
		}
	}
	start = time.Now()
	single(users[2:])
	t.Logf("single-member path, append two: %s", time.Since(start))
	start = time.Now()
	single(users)
	t.Logf("single-member path, repeat four: %s", time.Since(start))
	actual, err := normalGroup(f.cfg, legacy)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(actual.members)
	if !slices.Equal(actual.members, users) {
		t.Fatal("single-member path did not produce the same membership")
	}
}

func TestDSMRealGroupMemberScale(t *testing.T) {
	f := newBatchFixtures(t, "DSMPASS_DSM_GROUP_SCALE", "100x7")
	start := time.Now()
	users := make([]string, 700)
	for i := range users {
		users[i] = f.makeUser(t, i)
		if (i+1)%50 == 0 {
			t.Logf("created and enrolled %d/700 users, elapsed=%s", i+1, time.Since(start).Round(time.Millisecond))
		}
	}
	for stage := range 3 {
		phase := time.Now()
		for i := range 100 {
			group := fmt.Sprintf("%sg%03d", f.prefix, i)
			names := users[i*7 : (i+1)*7]
			switch stage {
			case 0:
				f.create(t, group, true, func() error { return f.members(group, names[:2], names[:2]) })
			case 1:
				if err := f.members(group, names[2:], names); err != nil {
					t.Fatal(err)
				}
			case 2:
				if err := f.members(group, names, names); err != nil {
					t.Fatal(err)
				}
			}
		}
		t.Logf("%s: %s", []string{"create 100 groups with 200 initial members", "append 500 members in 100 existing groups", "verify 700 unchanged memberships"}[stage], time.Since(phase).Round(time.Millisecond))
	}
	t.Logf("100 groups, 700 users and 700 distinct memberships verified, total=%s", time.Since(start).Round(time.Millisecond))
}
