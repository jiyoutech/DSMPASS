package provider

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWeComBuildAuthorizeURLUsesCorpIDAgentIDAndRedirect(t *testing.T) {
	wecom := NewWeCom(WeComConfig{
		CorpID:       "wwcorp",
		AgentID:      "1000002",
		AuthorizeURL: "https://open.weixin.qq.com/connect/oauth2/authorize",
	})
	got := wecom.BuildAuthorizeURL("state-1", "https://idp.example.com/idp/source/callback")
	for _, want := range []string{
		"https://open.weixin.qq.com/connect/oauth2/authorize?",
		"appid=wwcorp",
		"agentid=1000002",
		"redirect_uri=https%3A%2F%2Fidp.example.com%2Fidp%2Fsource%2Fcallback",
		"response_type=code",
		"scope=snsapi_base",
		"state=state-1",
		"#wechat_redirect",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize url missing %q: %s", want, got)
		}
	}
}

func TestWeComExchangeCodeReturnsUserIDSubject(t *testing.T) {
	wecom := NewWeCom(WeComConfig{
		CorpID:      "wwcorp",
		CorpSecret:  "secret",
		TokenURL:    "https://wecom.test/cgi-bin/gettoken",
		UserInfoURL: "https://wecom.test/cgi-bin/auth/getuserinfo",
	})
	wecom.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			if r.URL.Query().Get("corpid") != "wwcorp" || r.URL.Query().Get("corpsecret") != "secret" {
				t.Fatalf("unexpected token query: %s", r.URL.RawQuery)
			}
			return map[string]any{"errcode": 0, "access_token": "access-token"}, http.StatusOK
		case "/cgi-bin/auth/getuserinfo":
			if r.URL.Query().Get("access_token") != "access-token" || r.URL.Query().Get("code") != "login-code" {
				t.Fatalf("unexpected userinfo query: %s", r.URL.RawQuery)
			}
			return map[string]any{"errcode": 0, "UserId": "zhangsan"}, http.StatusOK
		default:
			return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
		}
	})}

	token, err := wecom.ExchangeCode("login-code", "https://idp.example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := wecom.FetchProfile(token)
	if err != nil {
		t.Fatal(err)
	}
	subject, subjectType := wecom.ProfileSubject(profile)
	if subject != "zhangsan" || subjectType != "wecom_userid" {
		t.Fatalf("expected userid subject, got subject=%q type=%q", subject, subjectType)
	}
}

func TestWeComListGroupsBuildsDepartmentPaths(t *testing.T) {
	wecom := NewWeCom(WeComConfig{
		CorpID:         "wwcorp",
		CorpSecret:     "secret",
		TokenURL:       "https://wecom.test/cgi-bin/gettoken",
		ContactBaseURL: "https://wecom.test/cgi-bin",
	})
	wecom.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			return map[string]any{"errcode": 0, "access_token": "access-token"}, http.StatusOK
		case "/cgi-bin/department/list":
			return map[string]any{"errcode": 0, "department": []map[string]any{
				{"id": 1, "name": "公司", "parentid": 0},
				{"id": 2, "name": "研发", "parentid": 1},
				{"id": 3, "name": "平台", "parentid": 2},
			}}, http.StatusOK
		default:
			return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
		}
	})}

	groups, err := wecom.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	parents := map[string]string{}
	for _, group := range groups {
		paths[group.Subject] = group.Path
		parents[group.Subject] = group.ParentSubject
	}
	if paths["3"] != "公司/研发/平台" {
		t.Fatalf("department path got %q", paths["3"])
	}
	if parents["1"] != "" || parents["2"] != "1" || parents["3"] != "2" {
		t.Fatalf("unexpected parents: %#v", parents)
	}
}

func TestWeComListUsersMergesDepartmentIDs(t *testing.T) {
	wecom := NewWeCom(WeComConfig{
		CorpID:         "wwcorp",
		CorpSecret:     "secret",
		TokenURL:       "https://wecom.test/cgi-bin/gettoken",
		ContactBaseURL: "https://wecom.test/cgi-bin",
	})
	wecom.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			return map[string]any{"errcode": 0, "access_token": "access-token"}, http.StatusOK
		case "/cgi-bin/department/list":
			return map[string]any{"errcode": 0, "department": []map[string]any{
				{"id": 1, "name": "公司", "parentid": 0},
				{"id": 2, "name": "研发", "parentid": 1},
			}}, http.StatusOK
		case "/cgi-bin/user/list":
			if r.URL.Query().Get("department_id") == "1" {
				return map[string]any{"errcode": 0, "userlist": []map[string]any{
					{"userid": "zhangsan", "name": "张三", "department": []any{float64(1), float64(2)}, "email": "zhang@example.com", "status": float64(1)},
				}}, http.StatusOK
			}
			return map[string]any{"errcode": 0, "userlist": []map[string]any{
				{"userid": "zhangsan", "name": "张三", "department": []any{float64(1), float64(2)}, "biz_mail": "zhang@corp.example.com", "status": float64(1)},
			}}, http.StatusOK
		default:
			return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
		}
	})}

	users, err := wecom.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("users length got %d", len(users))
	}
	user := users[0]
	if user.Subject != "zhangsan" || user.SubjectType != "wecom_userid" || !user.Active {
		t.Fatalf("unexpected user identity: %#v", user)
	}
	if got := strings.Join(user.DepartmentSubjects, ","); got != "1,2" {
		t.Fatalf("DepartmentSubjects got %q", got)
	}
}

func TestWeComListUsersFallsBackToVisibleUserIDsWhenDepartmentsEmpty(t *testing.T) {
	wecom := NewWeCom(WeComConfig{
		CorpID:         "wwcorp",
		CorpSecret:     "secret",
		TokenURL:       "https://wecom.test/cgi-bin/gettoken",
		ContactBaseURL: "https://wecom.test/cgi-bin",
	})
	var listIDCalled bool
	getCalls := map[string]int{}
	wecom.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			return map[string]any{"errcode": 0, "access_token": "access-token"}, http.StatusOK
		case "/cgi-bin/department/list":
			return map[string]any{"errcode": 0, "department": []map[string]any{}}, http.StatusOK
		case "/cgi-bin/user/list_id":
			if r.Method != http.MethodPost {
				t.Fatalf("list_id method got %s", r.Method)
			}
			if r.URL.Query().Get("access_token") != "access-token" {
				t.Fatalf("unexpected list_id query: %s", r.URL.RawQuery)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["limit"] != float64(50) {
				t.Fatalf("list_id limit got %#v", body["limit"])
			}
			listIDCalled = true
			return map[string]any{"errcode": 0, "dept_user": []map[string]any{
				{"userid": "mas", "department": 1},
				{"userid": "meikle", "department": 2},
			}}, http.StatusOK
		case "/cgi-bin/user/get":
			userID := r.URL.Query().Get("userid")
			getCalls[userID]++
			switch userID {
			case "mas":
				return map[string]any{"errcode": 0, "userid": "mas", "name": "马少云", "email": "ma@example.com", "status": float64(1)}, http.StatusOK
			case "meikle":
				return map[string]any{"errcode": 0, "userid": "meikle", "name": "Meikle Hong", "mobile": "13800000000", "status": float64(1)}, http.StatusOK
			default:
				return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
			}
		case "/cgi-bin/user/list":
			t.Fatal("department user list should not be called when departments are empty")
		}
		return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
	})}

	users, err := wecom.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if !listIDCalled {
		t.Fatal("expected list_id fallback")
	}
	if len(users) != 2 {
		t.Fatalf("users length got %d", len(users))
	}
	bySubject := map[string]User{}
	for _, user := range users {
		bySubject[user.Subject] = user
	}
	if bySubject["mas"].DisplayName != "马少云" || strings.Join(bySubject["mas"].DepartmentSubjects, ",") != "1" {
		t.Fatalf("unexpected mas user: %#v", bySubject["mas"])
	}
	if bySubject["meikle"].DisplayName != "Meikle Hong" || strings.Join(bySubject["meikle"].DepartmentSubjects, ",") != "2" {
		t.Fatalf("unexpected meikle user: %#v", bySubject["meikle"])
	}
	if getCalls["mas"] != 1 || getCalls["meikle"] != 1 {
		t.Fatalf("unexpected get calls: %#v", getCalls)
	}
}

func TestWeComTrustedIPErrorIsActionable(t *testing.T) {
	err := formatWeComHTTPError(http.StatusOK, []byte(`{"errcode":60020,"errmsg":"not allow to access from your ip"}`))
	if err == nil {
		t.Fatal("expected error")
	}
	message := err.Error()
	for _, want := range []string{
		"企业微信接口请求失败",
		"60020",
		"可信 IP",
		"DSMPASS 后端公网出口 IP",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q: %s", want, message)
		}
	}
}
