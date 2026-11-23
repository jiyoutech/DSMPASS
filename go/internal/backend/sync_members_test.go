package backend

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

type batchSyncHelper struct {
	testHelper
	mode             string
	batches, singles []string
}

func (h *batchSyncHelper) AddGroupMembers(_ context.Context, _ string, group string, names []string) ([]string, error) {
	h.batches = append(h.batches, fmt.Sprintf("%s:%d", group, len(names)))
	if group == "alpha" {
		switch h.mode {
		case "fallback":
			return nil, helperclient.ErrGroupBatchUnsupported
		case "partial":
			return names[1:2], errors.New("partial DSM write")
		}
	}
	return names, nil
}

func (h *batchSyncHelper) AddGroupMember(_ context.Context, _ string, group, name string) (bool, error) {
	h.singles = append(h.singles, group+":"+name)
	return true, nil
}

func TestSyncGroupMembersBatchesReadbackAndFallback(t *testing.T) {
	for _, mode := range []string{"success", "fallback", "partial", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			helper := &batchSyncHelper{mode: mode}
			server := NewWithDB(config.BackendConfig{}, helper, database, queries)
			var members []syncMember
			for i := range 202 {
				group := "alpha"
				if i == 201 {
					group = "beta"
				}
				name := fmt.Sprintf("user%03d", i)
				seedSyncedAccount(t, ctx, database, "source", name, "external-"+name, "sub-"+name, name, "2026-10-01")
				if i == 0 || i == 201 {
					seedGroupMember(t, ctx, database, "source", "provider-"+group, group, name, group, group, name, 1, "pending")
				} else if _, err := database.Exec(`INSERT INTO group_members (id,dsm_group_id,dsm_account_id,active,provision_status) VALUES (?,?,?,1,'pending')`, name, group, "account-"+name); err != nil {
					t.Fatal(err)
				}
				members = append(members, syncMember{id: name, groupname: group, username: name, status: "pending"})
			}
			if mode == "rollback" {
				members[10].id = "deleted"
			}
			logs := server.newSyncLogBuffer(ctx)
			if ops, err := server.syncGroupMembers(ctx, "run", "source", nil, logs, nil); err != nil || len(ops) != 0 {
				t.Fatalf("empty batch %v %v", ops, err)
			}
			ops, err := server.syncGroupMembers(ctx, "run", "source", members, logs, nil)
			switch mode {
			case "success":
				if err != nil || len(ops) != 202 || !slices.Equal(helper.batches, []string{"alpha:200", "alpha:1", "beta:1"}) || len(helper.singles) != 0 {
					t.Fatalf("success %v %v", helper, err)
				}
				assertLocalMemberStatus(t, ctx, database, "user201", 1, "created")
			case "fallback":
				if err != nil || len(ops) != 202 || len(helper.singles) != 201 || !slices.Equal(helper.batches, []string{"alpha:200", "beta:1"}) {
					t.Fatalf("fallback %v %v", helper, err)
				}
			case "partial":
				if err == nil || len(ops) != 1 || len(helper.singles) != 0 {
					t.Fatalf("unexpected partial result %v %v", ops, err)
				}
				assertLocalMemberStatus(t, ctx, database, "user000", 1, "failed")
				assertLocalMemberStatus(t, ctx, database, "user001", 1, "created")
				assertLocalMemberStatus(t, ctx, database, "user201", 1, "pending")
			case "rollback":
				if err == nil || len(ops) != 0 {
					t.Fatalf("save error %v %v", ops, err)
				}
				assertLocalMemberStatus(t, ctx, database, "user000", 1, "pending")
			}
		})
	}
}

type firstSyncGroupHelper struct {
	testHelper
	calls    []string
	existing bool
}

func (h *firstSyncGroupHelper) ProvisionUser(_ context.Context, _, name, _, _, _ string) (bool, error) {
	h.calls = append(h.calls, "user:"+name)
	return !h.existing, nil
}
func (h *firstSyncGroupHelper) PrepareGroupForMembers(_ context.Context, _, group string) (bool, error) {
	h.calls = append(h.calls, "prepare:"+group)
	return false, nil
}
func (h *firstSyncGroupHelper) ProvisionGroup(_ context.Context, _, group string) (bool, error) {
	h.calls = append(h.calls, "group:"+group)
	return true, nil
}
func (h *firstSyncGroupHelper) AddGroupMembers(_ context.Context, _, group string, names []string) ([]string, error) {
	h.calls = append(h.calls, fmt.Sprintf("members:%s:%d", group, len(names)))
	return names, nil
}

func TestFirstSyncCreatesNonemptyGroupWithUsers(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	helper := &firstSyncGroupHelper{}
	s := NewWithDB(config.BackendConfig{AdminJWTSecret: "test-key"}, helper, database, queries)
	if _, err := database.Exec("INSERT INTO identity_sources (slug,provider_type,display_name) VALUES ('a','feishu','A')"); err != nil {
		t.Fatal(err)
	}
	seedSyncedAccount(t, ctx, database, "a", "alice", "external-alice", "alice", "alice", "2999-01-01")
	seedGroupMember(t, ctx, database, "a", "provider-team", "team", "membership", "team", "team", "alice", 1, "pending")
	for _, tc := range []struct {
		existing    bool
		preparation string
	}{{false, "prepare:team"}, {true, "group:team"}} {
		helper.calls = nil
		helper.existing = tc.existing
		if _, err := s.syncSourceToDSM(ctx, "sync", "a", "2000-01-01", sourceSyncPolicy{}); err != nil {
			t.Fatal(err)
		}
		if want := []string{"user:alice", tc.preparation, "members:team:1"}; !slices.Equal(helper.calls, want) {
			t.Fatalf("got %v want %v", helper.calls, want)
		}
		assertLocalMemberStatus(t, ctx, database, "membership", 1, "created")
	}
	if _, err := database.Exec("UPDATE group_members SET active=0"); err != nil {
		t.Fatal(err)
	}
	helper.existing = false
	helper.calls = nil
	if _, err := s.syncSourceToDSM(ctx, "empty", "a", "2000-01-01", sourceSyncPolicy{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(helper.calls, []string{"user:alice", "group:team"}) {
		t.Fatal(helper.calls)
	}
}
