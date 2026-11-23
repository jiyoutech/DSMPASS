package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Fixed synthetic API latency makes this benchmark comparable across revisions.
func BenchmarkDingTalkDirectory100Groups700Users(b *testing.B) {
	d := NewDingTalk(DingTalkConfig{AppTokenURL: "https://fixture.test/gettoken", ContactBaseURL: "https://fixture.test/topapi", CheckAccountStatus: true})
	var requests atomic.Int64
	d.client.Transport = fakeTransport(func(r *http.Request) (any, int) {
		requests.Add(1)
		time.Sleep(5 * time.Millisecond)
		var body struct {
			DeptID int    `json:"dept_id"`
			UserID string `json:"userid"`
		}
		if r.Body != nil {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return map[string]any{"errcode": 1}, 400
			}
		}
		switch r.URL.Path {
		case "/gettoken":
			return map[string]any{"access_token": "fixture"}, 200
		case "/topapi/v2/department/get":
			return map[string]any{"result": map[string]any{"name": "root"}}, 200
		case "/topapi/v2/department/listsub":
			groups := []map[string]any{}
			if body.DeptID == 1 {
				for i := 2; i <= 100; i++ {
					groups = append(groups, map[string]any{"dept_id": i, "name": strconv.Itoa(i), "parent_id": 1})
				}
			}
			return map[string]any{"result": groups}, 200
		case "/topapi/user/listsimple":
			var users []map[string]any
			for i := range 7 {
				users = append(users, map[string]any{"userid": fmt.Sprintf("user-%d-%d", body.DeptID, i)})
			}
			return map[string]any{"result": map[string]any{"list": users, "has_more": false}}, 200
		case "/topapi/v2/user/get":
			return map[string]any{"result": map[string]any{"userid": body.UserID, "unionid": "union-" + body.UserID, "name": body.UserID}}, 200
		}
		return map[string]any{"errcode": 404}, 404
	})
	for b.Loop() {
		users, groups, err := d.ListUsersAndGroups()
		if err != nil || len(users) != 700 || len(groups) != 100 {
			b.Fatalf("got %d users, %d groups, err=%v", len(users), len(groups), err)
		}
	}
	b.ReportMetric(float64(requests.Load())/float64(b.N), "requests/op")
}
