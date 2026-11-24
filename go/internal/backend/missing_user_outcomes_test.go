package backend

import (
	"context"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"testing"
)

type missingOutcomeHelper struct {
	recordingHelper
	calls   int
	outcome error
}

func (h *missingOutcomeHelper) DisableMissingUser(context.Context, string, string, string, string, string, string) error {
	h.calls++
	return h.outcome
}

func TestMissingUserOutcomesFinishLocalMappingOnly(t *testing.T) {
	for _, outcome := range []error{helperclient.ErrAccountAbsent, helperclient.ErrMembershipOnly} {
		ctx := context.Background()
		database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = database.Close() })
		h := &missingOutcomeHelper{outcome: outcome}
		s := NewWithDB(config.BackendConfig{}, h, database, queries)
		seedSyncedAccount(t, ctx, database, "source", "identity", "external", "subject", "alice", "2000-01-01")
		if _, err := database.Exec("UPDATE dsm_mapping_entries SET active=0"); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			ops, err := s.disableMissingAccounts(ctx, "run", "source", nil, nil)
			if err != nil || len(ops) != 0 {
				t.Fatal(ops, err)
			}
		}
		var login int
		var status string
		if err := database.QueryRow("SELECT allow_login,provision_status FROM dsm_accounts").Scan(&login, &status); err != nil || h.calls != 1 || login != 0 || status != "disabled" {
			t.Fatal(h.calls, login, status, err)
		}
	}
}
