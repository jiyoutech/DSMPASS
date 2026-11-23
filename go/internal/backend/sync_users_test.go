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

type syncUserBatchFixture struct {
	testHelper
	mode    string
	sizes   []int
	singles int
}

func (h *syncUserBatchFixture) ProvisionUsers(_ context.Context, _ string, users []helperclient.UserProfile, _ string) ([]helperclient.UserProvisionOutcome, error) {
	h.sizes = append(h.sizes, len(users))
	switch h.mode {
	case "old":
		return nil, helperclient.ErrUserBatchUnsupported
	case "lost":
		return nil, errors.New("connection lost")
	case "short":
		return nil, nil
	}
	rows := make([]helperclient.UserProvisionOutcome, len(users))
	for i, u := range users {
		if u.Username == "test0001" {
			rows[i].Err = errors.New("account busy")
			continue
		}
		rows[i].Created = true
		rows[i].InitialPasswordApplied = true
	}
	return rows, nil
}

func (h *syncUserBatchFixture) ProvisionUser(context.Context, string, string, string, string, string) (bool, error) {
	h.singles++
	return true, nil
}

func TestSyncUserBatchesConfirmEachAccount(t *testing.T) {
	for _, mode := range []string{"partial", "old", "lost", "short"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			h := &syncUserBatchFixture{mode: mode}
			s := NewWithDB(config.BackendConfig{AdminJWTSecret: "test-key"}, h, database, q)
			if _, err := database.Exec("INSERT INTO identity_sources(slug,provider_type,display_name) VALUES('source','feishu','Directory')"); err != nil {
				t.Fatal(err)
			}
			n := 3
			if mode == "partial" {
				n = 700
			}
			for i := range n {
				name := fmt.Sprintf("test%04d", i)
				seedSyncedAccount(t, ctx, database, "source", name, "external-"+name, name, name, "2999-01-01")
			}
			if _, err := database.Exec("UPDATE dsm_accounts SET provision_status='pending'"); err != nil {
				t.Fatal(err)
			}
			ops, err := s.syncSourceToDSM(ctx, "run", "source", "2000-01-01", sourceSyncPolicy{})
			var created, failed, pending int
			if e := database.QueryRow("SELECT SUM(provision_status='created'),SUM(provision_status='failed'),SUM(provision_status='pending') FROM dsm_accounts").Scan(&created, &failed, &pending); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "partial":
				if !slices.Equal(h.sizes, []int{200, 200, 200, 100}) || h.singles != 0 || err == nil || created != 699 || failed != 1 || len(ops) != 699 {
					t.Fatalf("partial result: %v %v %d %d", h, err, created, failed)
				}
			case "old":
				if err != nil || h.singles != 3 || len(h.sizes) != 1 || created != 3 {
					t.Fatalf("unsupported fallback %v %v", h, err)
				}
			default:
				if err == nil || pending != n || len(ops) != 0 || h.singles != 0 || len(h.sizes) != 1 {
					t.Fatalf("uncertain batch retried or saved: %v %v", h, err)
				}
			}
		})
	}
}

func TestSaveUserBatchRollsBackOnMissingRow(t *testing.T) {
	ctx := context.Background()
	database, q, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	s := NewWithDB(config.BackendConfig{}, testHelper{}, database, q)
	seedSyncedAccount(t, ctx, database, "a", "alice", "external-alice", "alice", "alice", "2999-01-01")
	r := helperclient.UserProvisionOutcome{ProvisionUserResult: helperclient.ProvisionUserResult{Created: true}}
	err = s.saveSyncUserBatch(ctx, []pendingAccountProvision{{id: "account-alice", username: "alice"}, {id: "absent", username: "deleted"}}, []helperclient.UserProvisionOutcome{r, r})
	var status string
	if err == nil {
		t.Fatal("missing row accepted")
	}
	if err := database.QueryRow("SELECT provision_status FROM dsm_accounts WHERE id='account-alice'").Scan(&status); err != nil || status != "linked_existing" {
		t.Fatalf("partial commit: %s %v", status, err)
	}
}
