package helperclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/signing"
)

func TestSignedGroupBatchValidatesConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name              string
		result            map[string]any
		want              []string
		fail, unsupported bool
	}{
		{"complete", map[string]any{"success": true, "confirmed": []string{"bob", "alice"}}, []string{"bob", "alice"}, false, false},
		{"partial", map[string]any{"success": true, "confirmed": []string{"bob"}, "batch_error": "partial update"}, []string{"bob"}, true, false},
		{"missing", map[string]any{"success": true, "confirmed": []string{"alice"}}, []string{"alice"}, true, false},
		{"foreign", map[string]any{"success": true, "confirmed": []string{"root"}}, nil, true, false},
		{"duplicate", map[string]any{"success": true, "confirmed": []string{"alice", "alice"}}, nil, true, false},
		{"legacy", map[string]any{"success": false, "error_code": "BAD_REQUEST", "error": "unsupported action"}, nil, true, true},
		{"unsupported", map[string]any{"success": false, "error_code": "GROUP_BATCH_UNSUPPORTED"}, nil, true, true},
		{"forbidden", map[string]any{"success": false, "error_code": "ACCOUNT_FORBIDDEN"}, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := shortSocketPath(t)
			socket, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			done := make(chan bool, 1)
			go func() {
				conn, err := socket.Accept()
				if err != nil {
					done <- false
					return
				}
				defer conn.Close()
				var request map[string]any
				valid := json.NewDecoder(conn).Decode(&request) == nil && signing.Verify(request, "fixture", 60) == nil
				names, _ := request["dsm_usernames"].([]any)
				done <- valid && request["action"] == "scoped_add_group_members" && request["dsm_groupname"] == "engineering" && slices.Equal(names, []any{"alice", "bob"})
				_ = json.NewEncoder(conn).Encode(tc.result)
			}()
			client := UnixSocketClient{SocketPath: path, Secret: "fixture", Timeout: time.Second}
			got, err := client.AddGroupMembers(context.Background(), "batch", "engineering", []string{"alice", "bob"})
			if !<-done || (err != nil) != tc.fail || errors.Is(err, ErrGroupBatchUnsupported) != tc.unsupported || !slices.Equal(got, tc.want) {
				t.Fatalf("confirmation=%v err=%v", got, err)
			}
		})
	}
}
