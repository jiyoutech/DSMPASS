package helperclient

import (
	"context"
	"errors"
	"time"
)

// The Helper holds the project writer lock for one wave of native resets.
const PasswordResetBatchSize = 4

var ErrPasswordBatchUnsupported = errors.New("Helper does not support password reset batches")

type PasswordResetTarget struct {
	AccountID string
	Username  string
}

type PasswordBatchClient interface {
	ResetSyncedUserPasswords(context.Context, string, string, []PasswordResetTarget, string) ([]error, error)
}

func (c UnixSocketClient) ResetSyncedUserPasswords(ctx context.Context, requestID, source string, users []PasswordResetTarget, password string) ([]error, error) {
	if len(users) == 0 || len(users) > PasswordResetBatchSize {
		return nil, errors.New("invalid password batch size")
	}
	rows := make([]map[string]string, len(users))
	for i, user := range users {
		rows[i] = map[string]string{"account_id": user.AccountID, "dsm_username": user.Username}
	}
	if c.Timeout < 2*time.Minute {
		c.Timeout = 2 * time.Minute
	}
	reply, err := c.send(ctx, map[string]any{
		"action": "scoped_reset_synced_user_passwords", "request_id": requestID,
		"source_slug": source, "password": password, "dsm_users": rows,
	})
	if err != nil {
		return nil, err
	}
	return passwordResetResults(users, reply)
}

func passwordResetResults(users []PasswordResetTarget, reply map[string]any) ([]error, error) {
	items, ok := reply["user_results"].([]any)
	if !ok || len(items) != len(users) {
		return nil, errors.New("incomplete DSM password batch response")
	}
	results := make([]error, len(users))
	for i, item := range items {
		row, ok := item.(map[string]any)
		if !ok || row["account_id"] != users[i].AccountID || row["dsm_username"] != users[i].Username {
			return nil, errors.New("invalid DSM password batch identity")
		}
		success, ok := row["success"].(bool)
		if !ok {
			return nil, errors.New("invalid DSM password batch result")
		}
		if !success {
			if row["error_code"] == "DINGTALK_MEMBERSHIP_ONLY" {
				results[i] = ErrDingTalkMembershipOnly
			} else if message, ok := row["error"].(string); ok && message != "" {
				results[i] = errors.New(message)
			} else {
				results[i] = errors.New("DSM/SMB password reset was not confirmed")
			}
		}
	}
	return results, nil
}
