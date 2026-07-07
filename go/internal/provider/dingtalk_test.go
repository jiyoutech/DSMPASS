package provider

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDingTalkBuildAuthorizeURLUsesQRLoginOAuth(t *testing.T) {
	dingtalk := NewDingTalk(DingTalkConfig{
		AppKey:       "ding-app-key",
		AuthorizeURL: "https://login.dingtalk.com/oauth2/auth",
	})
	got := dingtalk.BuildAuthorizeURL("state-1", "https://idp.example.com/idp/source/callback")
	for _, want := range []string{
		"https://login.dingtalk.com/oauth2/auth?",
		"client_id=ding-app-key",
		"redirect_uri=https%3A%2F%2Fidp.example.com%2Fidp%2Fsource%2Fcallback",
		"response_type=code",
		"scope=openid",
		"state=state-1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize url missing %q: %s", want, got)
		}
	}
	for _, forbidden := range []string{"corpId=", "agentid=", "suiteKey=", "loginTmpCode="} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("qr login url should not contain %q: %s", forbidden, got)
		}
	}
}

func TestDingTalkExchangeCodeFetchesProfileAndPrefersUnionID(t *testing.T) {
	dingtalk := NewDingTalk(DingTalkConfig{
		AppKey:       "ding-app-key",
		AppSecret:    "secret",
		UserTokenURL: "https://api.dingtalk.test/v1.0/oauth2/userAccessToken",
		UserInfoURL:  "https://api.dingtalk.test/v1.0/contact/users/me",
	})
	dingtalk.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/v1.0/oauth2/userAccessToken":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["clientId"] != "ding-app-key" || body["clientSecret"] != "secret" || body["code"] != "login-code" || body["grantType"] != "authorization_code" {
				t.Fatalf("unexpected token body: %#v", body)
			}
			return map[string]any{"accessToken": "user-token"}, http.StatusOK
		case "/v1.0/contact/users/me":
			if r.Header.Get("x-acs-dingtalk-access-token") != "user-token" {
				t.Fatalf("unexpected user token header: %s", r.Header.Get("x-acs-dingtalk-access-token"))
			}
			return map[string]any{"unionId": "union-1", "openId": "open-1", "nick": "张三"}, http.StatusOK
		default:
			return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
		}
	})}

	token, err := dingtalk.ExchangeCode("login-code", "https://idp.example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := dingtalk.FetchProfile(token)
	if err != nil {
		t.Fatal(err)
	}
	subject, subjectType := dingtalk.ProfileSubject(profile)
	if subject != "union-1" || subjectType != "dingtalk_unionid" {
		t.Fatalf("expected union id subject, got subject=%q type=%q", subject, subjectType)
	}
}

func TestDingTalkListGroupsBuildsDepartmentPaths(t *testing.T) {
	dingtalk := NewDingTalk(DingTalkConfig{
		AppKey:         "ding-app-key",
		AppSecret:      "secret",
		AppTokenURL:    "https://oapi.dingtalk.test/gettoken",
		ContactBaseURL: "https://oapi.dingtalk.test/topapi",
	})
	dingtalk.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/gettoken":
			return map[string]any{"errcode": 0, "access_token": "app-token"}, http.StatusOK
		case "/topapi/v2/department/get":
			return map[string]any{"errcode": 0, "result": map[string]any{"dept_id": 1, "name": "公司"}}, http.StatusOK
		case "/topapi/v2/department/listsub":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			switch body["dept_id"] {
			case float64(1):
				return map[string]any{"errcode": 0, "result": []map[string]any{{"dept_id": 2, "name": "研发", "parent_id": 1}}}, http.StatusOK
			case float64(2):
				return map[string]any{"errcode": 0, "result": []map[string]any{{"dept_id": 3, "name": "平台", "parent_id": 2}}}, http.StatusOK
			case float64(3):
				return map[string]any{"errcode": 0, "result": []map[string]any{}}, http.StatusOK
			default:
				t.Fatalf("unexpected dept_id: %#v", body["dept_id"])
			}
		}
		return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
	})}

	groups, err := dingtalk.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, group := range groups {
		paths[group.Subject] = group.Path
	}
	if paths["1"] != "公司" || paths["3"] != "公司/研发/平台" {
		t.Fatalf("unexpected paths: %#v", paths)
	}
}

func TestDingTalkListUsersMergesDepartmentIDs(t *testing.T) {
	dingtalk := NewDingTalk(DingTalkConfig{
		AppKey:            "ding-app-key",
		AppSecret:         "secret",
		AppTokenURL:       "https://oapi.dingtalk.test/gettoken",
		ContactBaseURL:    "https://oapi.dingtalk.test/topapi",
		DirectoryPageSize: 1,
	})
	dingtalk.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/gettoken":
			return map[string]any{"errcode": 0, "access_token": "app-token"}, http.StatusOK
		case "/topapi/v2/department/get":
			return map[string]any{"errcode": 0, "result": map[string]any{"dept_id": 1, "name": "公司"}}, http.StatusOK
		case "/topapi/v2/department/listsub":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["dept_id"] == float64(1) {
				return map[string]any{"errcode": 0, "result": []map[string]any{{"dept_id": 2, "name": "研发", "parent_id": 1}}}, http.StatusOK
			}
			return map[string]any{"errcode": 0, "result": []map[string]any{}}, http.StatusOK
		case "/topapi/user/listsimple":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["size"] != float64(1) {
				t.Fatalf("size got %#v", body["size"])
			}
			switch body["dept_id"] {
			case float64(1):
				return map[string]any{"errcode": 0, "result": map[string]any{"list": []map[string]any{{"userid": "u1", "name": "张三"}}}}, http.StatusOK
			case float64(2):
				return map[string]any{"errcode": 0, "result": map[string]any{"list": []map[string]any{{"userid": "u1", "name": "张三"}}}}, http.StatusOK
			default:
				t.Fatalf("unexpected dept_id: %#v", body["dept_id"])
			}
		case "/topapi/v2/user/get":
			return map[string]any{"errcode": 0, "result": map[string]any{
				"userid":       "u1",
				"unionid":      "union-1",
				"name":         "张三",
				"email":        "zhang@example.com",
				"mobile":       "13800000000",
				"dept_id_list": []any{float64(1), float64(2)},
				"active":       true,
			}}, http.StatusOK
		}
		return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
	})}

	users, err := dingtalk.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("users length got %d", len(users))
	}
	user := users[0]
	if user.Subject != "union-1" || user.SubjectType != "dingtalk_unionid" || user.DisplayName != "张三" || !user.Active {
		t.Fatalf("unexpected user: %#v", user)
	}
	if got := strings.Join(user.DepartmentSubjects, ","); got != "1,2" {
		t.Fatalf("DepartmentSubjects got %q", got)
	}
}

func TestDingTalkListUsersRequiresLoginCompatibleSubject(t *testing.T) {
	dingtalk := NewDingTalk(DingTalkConfig{
		AppKey:         "ding-app-key",
		AppSecret:      "secret",
		AppTokenURL:    "https://oapi.dingtalk.test/gettoken",
		ContactBaseURL: "https://oapi.dingtalk.test/topapi",
	})
	dingtalk.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/gettoken":
			return map[string]any{"errcode": 0, "access_token": "app-token"}, http.StatusOK
		case "/topapi/v2/department/get":
			return map[string]any{"errcode": 0, "result": map[string]any{"dept_id": 1, "name": "公司"}}, http.StatusOK
		case "/topapi/v2/department/listsub":
			return map[string]any{"errcode": 0, "result": []map[string]any{}}, http.StatusOK
		case "/topapi/user/listsimple":
			return map[string]any{"errcode": 0, "result": map[string]any{"list": []map[string]any{{"userid": "u1"}}}}, http.StatusOK
		case "/topapi/v2/user/get":
			return map[string]any{"errcode": 0, "result": map[string]any{"userid": "u1", "name": "张三", "active": true}}, http.StatusOK
		}
		return map[string]any{"errcode": 404, "errmsg": "not found"}, http.StatusNotFound
	})}

	_, err := dingtalk.ListUsers()
	if err == nil || !strings.Contains(err.Error(), "缺少 unionid/openid") {
		t.Fatalf("expected missing union/open subject error, got %v", err)
	}
}
