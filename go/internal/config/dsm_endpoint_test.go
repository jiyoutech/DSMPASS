package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDSMEndpointFollowsNativePortsWithoutBackendOverrides(t *testing.T) {
	p := filepath.Join(t.TempDir(), "DSM.json")
	cfg := HelperConfig{DSMNativeConfigPath: p, DSMLoginAPI: "https://127.0.0.1:5001/webapi/entry.cgi"}
	t.Setenv("DSMPASS_DSM_LOGIN_API", "https://untrusted.example/webapi/entry.cgi")
	for _, tc := range []struct{ data, want string }{
		{`{"port":5000,"ssl":{"port":5001},"fqdn":"ignored.example"}`, "https://127.0.0.1:5001/webapi/entry.cgi"},
		{`{"port":6500,"ssl":{"port":6501}}`, "https://127.0.0.1:6501/webapi/entry.cgi"},
		{`{"port":6500,"ssl":null}`, "http://127.0.0.1:6500/webapi/entry.cgi"},
		{`{"port":6500}`, "http://127.0.0.1:6500/webapi/entry.cgi"},
		{`{}`, ""}, {`{"port":0}`, ""}, {`{"port":65536}`, ""},
		{`{"port":5000,"ssl":{"port":0}}`, ""},
		{`{"ssl":{"port":"6501"}}`, ""}, {`not JSON`, ""},
	} {
		if err := os.WriteFile(p, []byte(tc.data), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveDSMLoginAPI(cfg)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Fatalf("data=%s got=%q err=%v", tc.data, got, err)
		}
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveDSMLoginAPI(cfg); err == nil {
		t.Fatal("missing native config silently fell back")
	}
	cfg.DSMNativeConfigPath = ""
	if got, err := ResolveDSMLoginAPI(cfg); err != nil || got != cfg.DSMLoginAPI {
		t.Fatal("explicit endpoint changed")
	}
}

func TestPrivilegedDSMPortDiscoveryAndExplicitRootOverride(t *testing.T) {
	for _, endpoint := range []string{"auto", "https://127.0.0.1:5001/webapi/entry.cgi", "https://127.0.0.1:6501/webapi/entry.cgi"} {
		settings := validRootSettings()
		settings.DSMLoginAPI = endpoint
		data, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := parsePrivilegedHelper(data)
		if err != nil {
			t.Fatal(err)
		}
		if (cfg.DSMNativeConfigPath != "") != (endpoint != "https://127.0.0.1:6501/webapi/entry.cgi") {
			t.Fatal("incorrect native discovery mode")
		}
	}
}

func TestDSMEndpointRejectsUntrustedNativeConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "DSM.json")
	if err := os.WriteFile(p, []byte(`{"port":6500}`), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveDSMLoginAPI(HelperConfig{Privileged: true, DSMNativeConfigPath: p}); err == nil {
		t.Fatal("writable DSM config accepted")
	}
	link := filepath.Join(dir, "redirect.json")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveDSMLoginAPI(HelperConfig{Privileged: true, DSMNativeConfigPath: link}); err == nil {
		t.Fatal("symlink DSM config accepted")
	}
}
