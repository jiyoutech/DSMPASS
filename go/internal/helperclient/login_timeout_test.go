package helperclient

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestLoginTimeoutAllowsQueueingButHonorsCallerDeadline(t *testing.T) {
	for _, tc := range []struct {
		name, action    string
		cancel, allowed bool
	}{
		{"browser", "scoped_prepare_browser_login", false, true},
		{"relay", "scoped_relay_login", false, true},
		{"completion", "complete_browser_login", false, true},
		{"health_stays_short", "health_check", false, false},
		{"caller_deadline", "scoped_prepare_browser_login", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := shortSocketPath(t)
			listener, err := net.Listen("unix", p)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				var request map[string]any
				if json.NewDecoder(conn).Decode(&request) != nil {
					return
				}
				time.Sleep(150 * time.Millisecond)
				_ = json.NewEncoder(conn).Encode(map[string]any{"success": true})
			}()
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 40*time.Millisecond)
				defer cancel()
			}
			c := UnixSocketClient{SocketPath: p, Secret: "fixture-secret", Timeout: 30 * time.Millisecond}
			_, err = c.send(ctx, map[string]any{"action": tc.action})
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v err=%v", tc.allowed, err)
			}
			<-done
		})
	}
}
