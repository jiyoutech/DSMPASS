package helperclient

import (
	"context"
	"errors"
)

type DirectoryAccountState uint8

const (
	DirectoryReview DirectoryAccountState = iota
	DirectoryMissing
	DirectoryUnchanged
)

type DirectorySnapshotClient interface {
	CaptureDirectory(context.Context, string) error
	ReleaseDirectory(context.Context, string) error
	DirectorySnapshot(context.Context, string, []UserProfile) (map[string]DirectoryAccountState, error)
}

func (c UnixSocketClient) CaptureDirectory(ctx context.Context, runID string) error {
	_, err := c.send(ctx, map[string]any{"action": "capture_directory_snapshot", "request_id": runID})
	return err
}

func (c UnixSocketClient) ReleaseDirectory(ctx context.Context, runID string) error {
	_, err := c.send(ctx, map[string]any{"action": "release_directory_snapshot", "request_id": runID})
	return err
}

// The response is position-aligned with the request and exposes only scoped accounts.
func (c UnixSocketClient) DirectorySnapshot(ctx context.Context, requestID string, profiles []UserProfile) (map[string]DirectoryAccountState, error) {
	rows := make([]map[string]string, len(profiles))
	for i, p := range profiles {
		rows[i] = map[string]string{"dsm_username": p.Username, "display_name": p.DisplayName, "email": p.Email}
	}
	response, err := c.send(ctx, map[string]any{"action": "scoped_directory_snapshot", "request_id": requestID, "dsm_users": rows, "snapshot_id": requestID})
	if err != nil {
		return nil, err
	}
	states, ok := response["states"].(string)
	if !ok || len(states) != len(profiles) {
		return nil, errors.New("incomplete DSM directory plan")
	}
	result := make(map[string]DirectoryAccountState, len(profiles))
	for i, p := range profiles {
		switch states[i] {
		case 'r':
			result[p.Username] = DirectoryReview
		case 'm':
			result[p.Username] = DirectoryMissing
		case 'u':
			result[p.Username] = DirectoryUnchanged
		default:
			return nil, errors.New("invalid DSM directory plan")
		}
	}
	return result, nil
}
