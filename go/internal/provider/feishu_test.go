package provider

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestFormatFeishuPermissionError(t *testing.T) {
	body := []byte(`{
		"code": 99991672,
		"msg": "Access denied.",
		"error": {
			"log_id": "202605151614305BA15FDC10F58567BF8D",
			"troubleshooter": "https://open.feishu.cn/search?code=99991672",
			"permission_violations": [
				{"type": "action_scope_required", "subject": "contact:contact.base:readonly"},
				{"type": "action_scope_required", "subject": "contact:department.organize:readonly"}
			]
		}
	}`)

	err := formatFeishuHTTPError(400, body)
	if err == nil {
		t.Fatal("expected error")
	}
	message := err.Error()
	for _, want := range []string{
		"飞书接口权限不足",
		"contact:contact.base:readonly",
		"contact:department.organize:readonly",
		"99991672",
		"202605151614305BA15FDC10F58567BF8D",
		"https://open.feishu.cn/search?code=99991672",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("formatted message missing %q: %s", want, message)
		}
	}
	if strings.Contains(message, `"permission_violations"`) {
		t.Fatalf("formatted message should not expose raw JSON: %s", message)
	}
}

func TestDecodeResponseRejectsFeishuErrorWithHTTP200(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(`{
			"code": 99991672,
			"msg": "Access denied.",
			"error": {
				"log_id": "log-1",
				"permission_violations": [
					{"type": "action_scope_required", "subject": "contact:department.organize:readonly"}
				]
			}
		}`)),
	}
	var out map[string]any
	err := decodeResponse(response, &out)
	if err == nil {
		t.Fatal("expected feishu api error")
	}
	message := err.Error()
	if !strings.Contains(message, "飞书接口权限不足") || !strings.Contains(message, "contact:department.organize:readonly") {
		t.Fatalf("unexpected error message: %s", message)
	}
}

func TestFetchProfileRejectsFeishuAPIError(t *testing.T) {
	feishu := Feishu{
		cfg: config.BackendConfig{FeishuUserInfoURL: "https://feishu.test/profile"},
		client: http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
			"code": 99991672,
			"msg": "Access denied.",
			"error": {
				"log_id": "log-profile",
				"permission_violations": [
					{"type": "action_scope_required", "subject": "contact:user.base:readonly"}
				]
			}
		}`)),
			}, nil
		})},
	}
	_, err := feishu.FetchProfile(map[string]any{"access_token": "token"})
	if err == nil {
		t.Fatal("expected profile api error")
	}
	message := err.Error()
	if !strings.Contains(message, "飞书接口权限不足") || !strings.Contains(message, "contact:user.base:readonly") || !strings.Contains(message, "log-profile") {
		t.Fatalf("unexpected error message: %s", message)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestBuildAuthorizeURLUsesAccountsEndpointAndClientID(t *testing.T) {
	feishu := NewFeishu(config.BackendConfig{
		FeishuAuthorizeURL: "https://accounts.feishu.cn/open-apis/authen/v1/authorize",
		FeishuClientID:     "cli_test",
	})
	got := feishu.BuildAuthorizeURL("state-1", "https://idp.example.com/idp/source/callback")
	for _, want := range []string{
		"https://accounts.feishu.cn/open-apis/authen/v1/authorize?",
		"client_id=cli_test",
		"redirect_uri=https%3A%2F%2Fidp.example.com%2Fidp%2Fsource%2Fcallback",
		"response_type=code",
		"state=state-1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize url missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "app_id=") {
		t.Fatalf("authorize url should not use app_id: %s", got)
	}
}

func TestMissingFeishuFieldErrorIsActionable(t *testing.T) {
	err := MissingFeishuFieldError{
		Resource:       "部门",
		ResourceID:     "od-123",
		Field:          "部门名称 name/i18n_name",
		RequiredScopes: []string{"contact:department.base:readonly"},
		Advice:         "同步部门树还需要 contact:department.organize:readonly。",
	}
	message := err.Error()
	for _, want := range []string{
		"飞书接口未返回部门名称 name/i18n_name字段",
		"部门=od-123",
		"contact:department.base:readonly",
		"contact:department.organize:readonly",
		"应用通讯录权限范围",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("missing field message missing %q: %s", want, message)
		}
	}
}

func TestDepartmentNameUsesI18NMap(t *testing.T) {
	raw := map[string]any{
		"open_department_id": "od-123",
		"i18n_name": map[string]any{
			"zh_cn": "研发部",
			"en_us": "Engineering",
		},
	}
	if got := departmentName(raw, "od-123"); got != "研发部" {
		t.Fatalf("departmentName got %q", got)
	}
}

func TestDepartmentNameFallbackIsUnique(t *testing.T) {
	raw := map[string]any{"open_department_id": "od-123"}
	if got := departmentName(raw, ""); got != "" {
		t.Fatalf("departmentName without fallback got %q", got)
	}
	if got := departmentName(raw, "od-123"); got != "dep_50271585c8" {
		t.Fatalf("departmentName fallback got %q", got)
	}
}

func TestListGroupsBuildsDepartmentPathFromTraversal(t *testing.T) {
	feishu := NewFeishu(config.BackendConfig{
		FeishuClientID:          "cli_test",
		FeishuClientSecret:      "secret",
		FeishuTenantTokenURL:    "https://feishu.test/tenant",
		FeishuContactBaseURL:    "https://feishu.test",
		FeishuDirectoryPageSize: 50,
	})
	feishu.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/tenant":
			return map[string]any{"tenant_access_token": "tenant-token"}, http.StatusOK
		case "/departments/0/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{{"open_department_id": "matrix", "name": "matrix"}}}}, http.StatusOK
		case "/departments/matrix/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{{"open_department_id": "sup1", "name": "sup1"}}}}, http.StatusOK
		case "/departments/sup1/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{{"open_department_id": "sup2", "name": "sup2"}}}}, http.StatusOK
		case "/departments/sup2/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{{"open_department_id": "sup5", "name": "sup5"}}}}, http.StatusOK
		case "/departments/sup5/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{}}}, http.StatusOK
		default:
			return map[string]any{"error": "not found"}, http.StatusNotFound
		}
	})}

	groups, err := feishu.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, group := range groups {
		paths[group.Subject] = group.Path
	}
	if got := paths["sup5"]; got != "matrix/sup1/sup2/sup5" {
		t.Fatalf("sup5 path got %q", got)
	}
}

func TestListGroupMembersReadsAllPages(t *testing.T) {
	feishu := NewFeishu(config.BackendConfig{
		FeishuClientID:          "cli_test",
		FeishuClientSecret:      "secret",
		FeishuTenantTokenURL:    "https://feishu.test/tenant",
		FeishuContactBaseURL:    "https://feishu.test",
		FeishuDirectoryPageSize: 1,
	})
	feishu.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/tenant":
			return map[string]any{"tenant_access_token": "tenant-token"}, http.StatusOK
		case "/users/find_by_department":
			if r.URL.Query().Get("page_token") == "" {
				return map[string]any{"data": map[string]any{
					"items":      []map[string]any{{"open_id": "ou_1"}},
					"has_more":   true,
					"page_token": "next",
				}}, http.StatusOK
			}
			return map[string]any{"data": map[string]any{
				"items": []map[string]any{{"open_id": "ou_2"}},
			}}, http.StatusOK
		default:
			return map[string]any{"error": "not found"}, http.StatusNotFound
		}
	})}

	members, err := feishu.ListGroupMembers("sup5")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(members, ","); got != "ou_1,ou_2" {
		t.Fatalf("members got %q", got)
	}
}

func TestListGroupsReadsAllChildDepartmentPages(t *testing.T) {
	feishu := NewFeishu(config.BackendConfig{
		FeishuClientID:          "cli_test",
		FeishuClientSecret:      "secret",
		FeishuTenantTokenURL:    "https://feishu.test/tenant",
		FeishuContactBaseURL:    "https://feishu.test",
		FeishuDirectoryPageSize: 1,
	})
	feishu.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/tenant":
			return map[string]any{"tenant_access_token": "tenant-token"}, http.StatusOK
		case "/departments/0/children":
			if r.URL.Query().Get("page_token") == "" {
				return map[string]any{"data": map[string]any{
					"items":      []map[string]any{{"open_department_id": "sup1", "name": "sup1"}},
					"has_more":   true,
					"page_token": "next",
				}}, http.StatusOK
			}
			return map[string]any{"data": map[string]any{
				"items": []map[string]any{{"open_department_id": "sup2", "name": "sup2"}},
			}}, http.StatusOK
		case "/departments/sup1/children", "/departments/sup2/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{}}}, http.StatusOK
		default:
			return map[string]any{"error": "not found"}, http.StatusNotFound
		}
	})}

	groups, err := feishu.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	subjects := make([]string, 0, len(groups))
	for _, group := range groups {
		subjects = append(subjects, group.Subject)
	}
	if got := strings.Join(subjects, ","); got != "sup1,sup2" {
		t.Fatalf("groups got %q", got)
	}
}

func TestListUsersMergesMultipleDepartmentIDs(t *testing.T) {
	feishu := NewFeishu(config.BackendConfig{
		FeishuClientID:          "cli_test",
		FeishuClientSecret:      "secret",
		FeishuTenantTokenURL:    "https://feishu.test/tenant",
		FeishuContactBaseURL:    "https://feishu.test",
		FeishuDirectoryPageSize: 50,
	})
	feishu.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/tenant":
			return map[string]any{"tenant_access_token": "tenant-token"}, http.StatusOK
		case "/departments/0/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{
				{"open_department_id": "sup2", "name": "sup2"},
				{"open_department_id": "sup3", "name": "sup3"},
			}}}, http.StatusOK
		case "/departments/sup2/children", "/departments/sup3/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{}}}, http.StatusOK
		case "/users/find_by_department":
			return map[string]any{"data": map[string]any{"items": []map[string]any{
				{"open_id": "ou_amk", "name": "amktest", "department_ids": []any{"marketing", "sup2", "sup3"}},
			}}}, http.StatusOK
		default:
			return map[string]any{"error": "not found"}, http.StatusNotFound
		}
	})}

	users, err := feishu.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("users length got %d", len(users))
	}
	got := strings.Join(users[0].DepartmentSubjects, ",")
	if got != "marketing,sup2,sup3" {
		t.Fatalf("DepartmentSubjects got %q", got)
	}
}

func TestListUsersPrefersOpenIDOverUserID(t *testing.T) {
	feishu := NewFeishu(config.BackendConfig{
		FeishuClientID:          "cli_test",
		FeishuClientSecret:      "secret",
		FeishuTenantTokenURL:    "https://feishu.test/tenant",
		FeishuContactBaseURL:    "https://feishu.test",
		FeishuDirectoryPageSize: 50,
	})
	feishu.client = http.Client{Transport: fakeTransport(func(r *http.Request) (any, int) {
		switch r.URL.Path {
		case "/tenant":
			return map[string]any{"tenant_access_token": "tenant-token"}, http.StatusOK
		case "/departments/0/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{
				{"open_department_id": "sup2", "name": "sup2"},
			}}}, http.StatusOK
		case "/departments/sup2/children":
			return map[string]any{"data": map[string]any{"items": []map[string]any{}}}, http.StatusOK
		case "/users/find_by_department":
			return map[string]any{"data": map[string]any{"items": []map[string]any{
				{"user_id": "ca32gc25", "open_id": "ou_ca32gc25", "name": "amktest"},
			}}}, http.StatusOK
		default:
			return map[string]any{"error": "not found"}, http.StatusNotFound
		}
	})}

	users, err := feishu.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("users length got %d", len(users))
	}
	if users[0].Subject != "ou_ca32gc25" || users[0].SubjectType != "feishu_open_id" {
		t.Fatalf("expected open_id subject, got subject=%q type=%q", users[0].Subject, users[0].SubjectType)
	}
	members, err := feishu.ListGroupMembers("sup2")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(members, ",") != "ou_ca32gc25" {
		t.Fatalf("members should use open_id, got %#v", members)
	}
}

func TestUserDisplayNameUsesI18NMap(t *testing.T) {
	raw := map[string]any{
		"open_id": "ou_123",
		"i18n_name": map[string]any{
			"zh_cn": "张三",
			"en_us": "Zhang San",
		},
	}
	if got := userDisplayName(raw); got != "张三" {
		t.Fatalf("userDisplayName got %q", got)
	}
}

type fakeTransport func(*http.Request) (any, int)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, status := f(r)
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(body); err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(&buffer),
		Header:     make(http.Header),
		Request:    r,
	}, nil
}
