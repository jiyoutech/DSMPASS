package diaglog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendRedactsOAuthSecretsAndProfilePII(t *testing.T) {
	dir := t.TempDir()

	Append(dir, "request-1", "stage", true, Event{
		"request_url":   "/idp/wecom/callback?code=login-code&state=oauth-state&next=/",
		"authorize_url": "https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=corp&state=launch-state",
		"code":          "login-code",
		"code_present":  true,
		"status_code":   200,
		"profile": Event{
			"userid": "zhangsan",
			"email":  "zhang@example.com",
		},
		"email":  "zhang@example.com",
		"mobile": "13800000000",
	})

	raw, err := os.ReadFile(filepath.Join(dir, "login-diagnostics.log"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(raw)
	for _, leaked := range []string{
		"login-code",
		"oauth-state",
		"launch-state",
		"zhang@example.com",
		"13800000000",
		"zhangsan",
	} {
		if strings.Contains(line, leaked) {
			t.Fatalf("diagnostic log leaked %q: %s", leaked, line)
		}
	}
	for _, want := range []string{
		"code_present=true",
		"status_code=200",
		`code="[REDACTED]"`,
		"code=%5BREDACTED%5D",
		"state=%5BREDACTED%5D",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("diagnostic log missing %q: %s", want, line)
		}
	}
}
