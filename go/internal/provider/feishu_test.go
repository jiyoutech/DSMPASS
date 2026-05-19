package provider

import (
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
