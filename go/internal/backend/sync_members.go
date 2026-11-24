package backend

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"github.com/dsmpass/dsmpass/go/internal/syncsvc"
)

type syncMember struct {
	id        string
	groupname string
	username  string
	status    string
}

// members are ordered by group, then by creation time and ID.
func (s *Server) syncGroupMembers(ctx context.Context, runID, source string, members []syncMember, logs *syncLogBuffer, progress *operationProgress) ([]syncsvc.PlanItem, error) {
	batchClient, _ := s.helper.(helperclient.GroupMemberBatchClient)
	var operations []syncsvc.PlanItem
	var fallbackGroup string
	for len(members) > 0 {
		group := members[0].groupname
		useBatch := batchClient != nil && group != fallbackGroup
		n := 1
		for useBatch && n < len(members) && n < helperclient.GroupMemberBatchSize && members[n].groupname == group {
			n++
		}
		batch := members[:n]
		var confirmed []string
		var err error
		if useBatch {
			names := make([]string, n)
			for i, m := range batch {
				names[i] = m.username
			}
			confirmed, err = batchClient.AddGroupMembers(ctx, "sync_members_"+randomHex(8), group, names)
			if errors.Is(err, helperclient.ErrGroupBatchUnsupported) {
				fallbackGroup = group
				continue
			}
		} else {
			name := batch[0].username
			_, err = s.helper.AddGroupMember(ctx, "sync_member_"+randomHex(8), group, name)
			if err == nil {
				confirmed = []string{name}
			}
		}
		if err == nil && len(confirmed) != n {
			err = errors.New("incomplete DSM group confirmation")
		}
		if saveErr := s.saveSyncMemberBatch(ctx, batch, confirmed); saveErr != nil {
			return operations, errors.Join(err, saveErr)
		}
		for _, m := range batch {
			key := group + ":" + m.username
			if slices.Contains(confirmed, m.username) {
				s.writeSyncOperation(logs, runID, source, "member", m.id, key, "create_or_update", "success", m.status, "created", "")
				operations = append(operations, syncsvc.PlanItem{Action: "sync_dsm_group_member", ProviderSlug: source, Subject: m.id, DSMUsername: m.username, DSMGroupname: group, ProvisionStatus: "created"})
			} else {
				message := "DSM did not confirm group membership"
				if err != nil {
					message = err.Error()
				}
				s.writeSyncOperation(logs, runID, source, "member", m.id, key, "create_or_update", "failed", m.status, "failed", message)
			}
			if progress != nil {
				progress.step(ctx, "同步 DSM 成员", key)
			}
		}
		if err != nil {
			return operations, fmt.Errorf("同步 DSM 群组 %q 成员: %w", group, err)
		}
		members = members[n:]
	}
	return operations, nil
}

func (s *Server) saveSyncMemberBatch(ctx context.Context, members []syncMember, confirmed []string) error {
	return s.withSyncTransaction(ctx, func(tx db.DBTX) error {
		if len(confirmed) > 0 {
			if err := saveObjectState(ctx, tx, members[0].groupname, `UPDATE dsm_groups SET provision_status='created', updated_at=CURRENT_TIMESTAMP WHERE id=(SELECT dsm_group_id FROM group_members WHERE id=?)`, members[0].id); err != nil {
				return err
			}
		}
		for _, m := range members {
			status := "failed"
			if slices.Contains(confirmed, m.username) {
				status = "created"
			}
			if err := saveObjectState(ctx, tx, m.groupname+":"+m.username, `UPDATE group_members SET provision_status=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND active=1`, status, m.id); err != nil {
				return err
			}
		}
		return nil
	})
}
