package helperserver

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestDSMLoginUsesChangedNativePortWithoutRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "DSM.json")
	cfg := config.HelperConfig{DSMLoginAPI: "http://127.0.0.1:1/webapi/entry.cgi", DSMNativeConfigPath: path, DSMTimeoutSeconds: 2, DSMSession: "webui"}
	for _, sid := range []string{"first-session", "after-port-change"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/webapi/entry.cgi" || r.URL.Query().Get("api") != "SYNO.API.Auth" || r.URL.Query().Get("account") != "alice" {
				t.Error("incorrect DSM request")
			}
			fmt.Fprintf(w, `{"success":true,"data":{"sid":%q}}`, sid)
		}))
		port := server.Listener.Addr().(*net.TCPAddr).Port
		if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"port":%d}`, port)), 0600); err != nil {
			t.Fatal(err)
		}
		result, err := dsmLogin(cfg, "native-port", "alice", "test-password")
		server.Close()
		if err != nil || result.SID != sid {
			t.Fatalf("native port not used: %+v %v", result, err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"port":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := dsmLogin(cfg, "bad-native-port", "alice", "test-password"); err == nil {
		t.Fatal("invalid native config accepted")
	}
}
