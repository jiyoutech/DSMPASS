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
			for i := range 35 {
				group := "alpha"
				if i == 34 {
					group = "beta"
				}
				name := fmt.Sprintf("user%02d", i)
				seedSyncedAccount(t, ctx, database, "source", name, "external-"+name, "sub-"+name, name, "2026-10-01")
				if i == 0 || i == 34 {
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
				if err != nil || len(ops) != 35 || !slices.Equal(helper.batches, []string{"alpha:32", "alpha:2", "beta:1"}) || len(helper.singles) != 0 {
					t.Fatalf("success %v %v", helper, err)
				}
				assertLocalMemberStatus(t, ctx, database, "user34", 1, "created")
			case "fallback":
				if err != nil || len(ops) != 35 || len(helper.singles) != 34 || !slices.Equal(helper.batches, []string{"alpha:32", "beta:1"}) {
					t.Fatalf("fallback %v %v", helper, err)
				}
			case "partial":
				if err == nil || len(ops) != 1 || len(helper.singles) != 0 {
					t.Fatalf("unexpected partial result %v %v", ops, err)
				}
				assertLocalMemberStatus(t, ctx, database, "user00", 1, "failed")
				assertLocalMemberStatus(t, ctx, database, "user01", 1, "created")
				assertLocalMemberStatus(t, ctx, database, "user34", 1, "pending")
			case "rollback":
				if err == nil || len(ops) != 0 {
					t.Fatalf("save error %v %v", ops, err)
				}
				assertLocalMemberStatus(t, ctx, database, "user00", 1, "pending")
			}
		})
	}
}
