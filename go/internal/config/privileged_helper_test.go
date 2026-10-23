package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func validRootSettings() RootHelperSettings {
	return RootHelperSettings{PackageUID: 1234, PackageGID: 1234, DatabasePath: "/package/data/dsmpass.db", HMACSecret: strings.Repeat("a", 64), DSMLoginAPI: "https://127.0.0.1:5001/webapi/entry.cgi"}
}

func TestPrivilegedHelperIgnoresCallerEnvironment(t *testing.T) {
	for _, key := range []string{"DSMPASS_APP_DIR", "DSMPASS_DATA_DIR", "DSMPASS_HELPER_SOCKET", "DSMPASS_DATABASE_URL", "DSMPASS_HELPER_HMAC_SECRET", "DSMPASS_DSM_LOGIN_API", "DSMPASS_SYNOUSER_PATH", "DSMPASS_SYNOGROUP_PATH"} {
		t.Setenv(key, "/untrusted/caller/value")
	}
	settings := validRootSettings()
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parsePrivilegedHelper(data)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Privileged || cfg.HMACSecret != settings.HMACSecret || cfg.DSMLoginAPI != settings.DSMLoginAPI || cfg.DatabaseURL != "sqlite://"+settings.DatabasePath {
		t.Fatal("caller environment replaced root-approved settings")
	}
	if cfg.SynoUserPath != "/usr/syno/sbin/synouser" || cfg.SynoGroupPath != "/usr/syno/sbin/synogroup" || cfg.SocketPath != HelperSocketPath || cfg.DataDir != HelperDataDir {
		t.Fatal("caller environment redirected privileged paths")
	}
}

func TestPrivilegedHelperRejectsUnsafeConfiguration(t *testing.T) {
	for _, name := range []string{"root uid", "root gid", "relative database", "short secret", "remote endpoint", "DNS endpoint", "userinfo", "query", "wrong path", "unknown field", "trailing JSON"} {
		t.Run(name, func(t *testing.T) {
			settings := validRootSettings()
			switch name {
			case "root uid":
				settings.PackageUID = 0
			case "root gid":
				settings.PackageGID = 0
			case "relative database":
				settings.DatabasePath = "relative.db"
			case "short secret":
				settings.HMACSecret = "short"
			case "remote endpoint":
				settings.DSMLoginAPI = "https://192.0.2.1/webapi/entry.cgi"
			case "DNS endpoint":
				settings.DSMLoginAPI = "https://nas.example.com/webapi/entry.cgi"
			case "userinfo":
				settings.DSMLoginAPI = "https://user@127.0.0.1/webapi/entry.cgi"
			case "query":
				settings.DSMLoginAPI += "?redirect=external"
			case "wrong path":
				settings.DSMLoginAPI = "https://127.0.0.1/other"
			}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if name == "unknown field" {
				data = append(data[:len(data)-1], []byte(",\"synouser_path\":\"/untrusted/program\"}")...)
			}
			if name == "trailing JSON" {
				data = append(data, []byte(" {}")...)
			}
			if _, err := parsePrivilegedHelper(data); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestPrivilegedHelperAcceptsIPv6Loopback(t *testing.T) {
	settings := validRootSettings()
	settings.DSMLoginAPI = "https://[::1]:5001/webapi/entry.cgi"
	if err := ValidateRootHelperSettings(settings); err != nil {
		t.Fatal(err)
	}
}
