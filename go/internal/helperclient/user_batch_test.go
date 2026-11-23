package helperclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/signing"
)

func TestUserBatchSignsProfilesAndRejectsUncertainResponses(t *testing.T) {
	good := map[string]any{"dsm_username": "alice", "success": true, "created": true, "initial_password_applied": true}
	invalid := []map[string]any{
		{"dsm_username": "wrong", "success": true, "created": true, "initial_password_applied": true},
		{"dsm_username": "alice", "success": true, "created": false, "initial_password_applied": true},
		{"dsm_username": "alice", "success": true},
	}
	responses := []map[string]any{{"success": true, "user_results": []any{good}}, {"success": true, "user_results": []any{}}, {"success": false, "error_code": "BAD_REQUEST", "error": "unsupported action"}, {"success": false, "error_code": "DSM_IMPORT_UNCONFIRMED", "error": "unknown"}}
	for _, row := range invalid {
		responses = append(responses, map[string]any{"success": true, "user_results": []any{row}})
	}
	for i, response := range responses {
		path := shortSocketPath(t)
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		signed := make(chan bool, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				signed <- false
				return
			}
			defer c.Close()
			var req map[string]any
			valid := json.NewDecoder(c).Decode(&req) == nil && signing.Verify(req, "fixture", 60) == nil && req["action"] == "scoped_provision_users"
			users, ok := req["dsm_users"].([]any)
			signed <- valid && ok && len(users) == 1
			_ = json.NewEncoder(c).Encode(response)
		}()
		c := UnixSocketClient{SocketPath: path, Secret: "fixture", Timeout: time.Second}
		got, err := c.ProvisionUsers(context.Background(), "batch", []UserProfile{{Username: "alice"}}, "fixture")
		l.Close()
		if !<-signed || (i == 0) != (err == nil) || errors.Is(err, ErrUserBatchUnsupported) != (i == 2) {
			t.Fatalf("case %d: %v %v", i, got, err)
		}
		if i == 0 && (len(got) != 1 || !got[0].InitialPasswordApplied || !got[0].Created) {
			t.Fatal(got)
		}
	}
}
