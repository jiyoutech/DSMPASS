package helperclient

import (
	"context"
	"errors"
	"fmt"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

const UserProvisionBatchSize = db.MaxProvisionUsers

var ErrUserBatchUnsupported = errors.New("Helper does not support user batches")

type UserProfile struct {
	Username, DisplayName, Email string
}

type UserProvisionOutcome struct {
	ProvisionUserResult
	Err error
}

type UserBatchClient interface {
	ProvisionUsers(context.Context, string, []UserProfile, string) ([]UserProvisionOutcome, error)
}

func (c UnixSocketClient) ProvisionUsers(ctx context.Context, requestID string, users []UserProfile, password string) ([]UserProvisionOutcome, error) {
	if len(users) == 0 || len(users) > UserProvisionBatchSize {
		return nil, errors.New("invalid user batch size")
	}
	// Maps preserve the same canonical JSON key order on both sides of the signature.
	rows := make([]map[string]string, len(users))
	for i, user := range users {
		rows[i] = map[string]string{"dsm_username": user.Username, "display_name": user.DisplayName, "email": user.Email}
	}
	response, err := c.send(ctx, map[string]any{"action": "scoped_provision_users", "request_id": requestID, "dsm_users": rows, "initial_password": password})
	if err != nil {
		return nil, err
	}
	items, ok := response["user_results"].([]any)
	if !ok || len(items) != len(users) {
		return nil, errors.New("incomplete DSM user batch response")
	}
	results := make([]UserProvisionOutcome, len(users))
	for i, item := range items {
		row, ok := item.(map[string]any)
		if !ok || row["dsm_username"] != users[i].Username {
			return nil, errors.New("invalid DSM user batch identity")
		}
		success, ok := row["success"].(bool)
		if !ok {
			return nil, errors.New("invalid DSM user batch result")
		}
		if !success {
			message, _ := row["error"].(string)
			if message == "" {
				message = "DSM user provisioning failed"
			}
			results[i].Err = fmt.Errorf("%s: %s", users[i].Username, message)
			continue
		}
		created, ok := row["created"].(bool)
		applied, explicit := row["initial_password_applied"].(bool)
		if !ok || !explicit || (applied && (!created || password == "")) {
			return nil, errors.New("invalid DSM user creation confirmation")
		}
		results[i].ProvisionUserResult = ProvisionUserResult{Created: created, InitialPasswordApplied: applied}
	}
	return results, nil
}
