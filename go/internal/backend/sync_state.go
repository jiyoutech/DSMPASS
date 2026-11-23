package backend

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func saveObjectState(ctx context.Context, exec db.DBTX, name, query string, args ...any) error {
	result, err := exec.ExecContext(ctx, query, args...)
	if err == nil {
		var count int64
		count, err = result.RowsAffected()
		if err == nil && count != 1 {
			err = sql.ErrNoRows
		}
	}
	if err != nil {
		return fmt.Errorf("%s 的本地状态未保存: %w", name, err)
	}
	return nil
}

func (s *Server) withSyncTransaction(ctx context.Context, write func(db.DBTX) error) error {
	switch conn := s.store.DBTX().(type) {
	case *sql.Tx:
		return write(conn)
	case *sql.DB:
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err = write(tx); err != nil {
			return err
		}
		return tx.Commit()
	default:
		return errors.New("sync state requires a database transaction")
	}
}

func (s *Server) saveGroupMembership(ctx context.Context, id, name string) error {
	err := s.withSyncTransaction(ctx, func(tx db.DBTX) error {
		if err := saveObjectState(ctx, tx, name, `UPDATE dsm_groups SET provision_status='created', updated_at=CURRENT_TIMESTAMP WHERE id=(SELECT dsm_group_id FROM group_members WHERE id=?)`, id); err != nil {
			return err
		}
		return saveObjectState(ctx, tx, name, `UPDATE group_members SET provision_status='created',updated_at=CURRENT_TIMESTAMP WHERE id=? AND active=1`, id)
	})
	if err != nil {
		return fmt.Errorf("DSM 成员 %s 已处理，本地状态未保存: %w", name, err)
	}
	return nil
}

func (s *Server) markMissingSourceData(ctx context.Context, source, start string, preserveGroups bool) error {
	return s.withSyncTransaction(ctx, func(tx db.DBTX) error {
		if _, err := tx.ExecContext(ctx, `UPDATE external_accounts SET active=0,updated_at=CURRENT_TIMESTAMP WHERE provider_slug=? AND active=1 AND updated_at<?`, source, start); err != nil {
			return err
		}
		if !preserveGroups {
			if _, err := tx.ExecContext(ctx, `UPDATE provider_groups SET active=0,updated_at=CURRENT_TIMESTAMP WHERE provider_slug=? AND active=1 AND updated_at<?`, source, start); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE dsm_mapping_entries SET active=0,updated_at=CURRENT_TIMESTAMP WHERE provider_slug=? AND active=1 AND updated_at<? AND (NOT ? OR mapping_type='user')`, source, start, preserveGroups)
		return err
	})
}
