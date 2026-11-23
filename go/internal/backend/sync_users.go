package backend

import (
	"context"
	"errors"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

type pendingAccountProvision struct {
	id          string
	username    string
	displayName string
	email       string
	status      string
}

func (s *Server) provisionUserBatch(ctx context.Context, client helperclient.UserBatchClient, batch []pendingAccountProvision, password string, full bool) ([]helperclient.UserProvisionOutcome, error) {
	if client != nil {
		users := make([]helperclient.UserProfile, len(batch))
		for i, item := range batch {
			users[i] = helperclient.UserProfile{Username: item.username, DisplayName: item.displayName, Email: item.email}
		}
		result, err := client.ProvisionUsers(ctx, "sync_users_"+randomHex(8), users, password)
		if err == nil && len(result) != len(users) {
			return nil, errors.New("incomplete DSM user batch confirmation")
		}
		return result, err
	}
	item := batch[0]
	id := "sync_user_" + randomHex(8)
	var result helperclient.UserProvisionOutcome
	if c, ok := s.helper.(helperclient.UserProvisionResultClient); ok && full {
		result.ProvisionUserResult, result.Err = c.ProvisionUserWithResult(ctx, id, item.username, item.displayName, item.email, password)
	} else {
		result.Created, result.Err = s.helper.ProvisionUser(ctx, id, item.username, item.displayName, item.email, password)
	}
	return []helperclient.UserProvisionOutcome{result}, nil
}

// Native work completes outside the SQLite write transaction. Only confirmed
// outcomes are reflected locally, together, before progress is published.
func (s *Server) saveSyncUserBatch(ctx context.Context, batch []pendingAccountProvision, results []helperclient.UserProvisionOutcome) error {
	return s.withSyncTransaction(ctx, func(tx db.DBTX) error {
		for i, item := range batch {
			result := results[i]
			if result.Err != nil {
				if err := saveObjectState(ctx, tx, item.username, `UPDATE dsm_accounts SET provision_status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=? AND dsm_username=?`, item.id, item.username); err != nil {
					return errors.Join(result.Err, err)
				}
				continue
			}
			status := "linked_existing"
			if result.Created {
				status = "created"
			}
			if err := saveObjectState(ctx, tx, item.username, `UPDATE dsm_accounts SET provision_status=?,conflict_reason=NULL,allow_login=(manual_login_blocked=0),updated_at=CURRENT_TIMESTAMP WHERE id=? AND dsm_username=?`, status, item.id, item.username); err != nil {
				return err
			}
		}
		return nil
	})
}
