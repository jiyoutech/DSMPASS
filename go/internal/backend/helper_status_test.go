package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/gin-gonic/gin"
)

type helperStatusFixture struct {
	testHelper
	health map[string]any
	err    error
}

func (h helperStatusFixture) HealthCheck(context.Context) (map[string]any, error) {
	return h.health, h.err
}

func TestHelperRestartNoticeOnlyForReachableStaleBuild(t *testing.T) {
	version, rev, epoch := buildinfo.Version, buildinfo.Revision, buildinfo.BuildEpoch
	buildinfo.Version, buildinfo.Revision, buildinfo.BuildEpoch = "0.8.51", "target", "200"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Revision, buildinfo.BuildEpoch = version, rev, epoch })
	for _, tc := range []struct {
		name, rev, epoch        string
		ready, offline, restart bool
	}{
		{"current", "target", "200", true, false, false}, {"initializing", "target", "200", false, false, false},
		{"old-revision", "previous", "", true, false, true}, {"rebuilt", "target", "199", true, false, true}, {"offline", "", "", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := helperStatusFixture{health: map[string]any{"version": "0.8.51", "revision": tc.rev, "build_epoch": tc.epoch, "startup_ready": tc.ready}}
			if tc.offline {
				h.err = errors.New("socket unavailable")
			}
			s := New(config.BackendConfig{}, h, nil)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/admin/helper/status", nil)
			s.helperStatus(c)
			var status struct {
				Restart   bool `json:"restart_required"`
				Reachable bool `json:"reachable"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Restart != tc.restart || status.Reachable == tc.offline {
				t.Fatalf("unexpected status: %s, %v", w.Body.String(), err)
			}
		})
	}
}
