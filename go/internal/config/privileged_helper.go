package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

const HelperInstallDir = "/usr/local/libexec/dsmpass"
const HelperControlPath = HelperInstallDir + "/helper-control.sh"
const HelperBinaryPath = HelperInstallDir + "/dsmpass-helper"
const HelperConfigPath = "/etc/dsmpass/helper.json"
const HelperDataDir = "/var/lib/dsmpass"
const HelperRunDir = "/run/dsmpass"
const HelperSocketPath = HelperRunDir + "/helper.sock"

// RootHelperSettings is installed by a root administrator. Executable, state,
// socket and recovery paths are deliberately not configurable here.
type RootHelperSettings struct {
	PackageUID   int    `json:"package_uid"`
	PackageGID   int    `json:"package_gid"`
	DatabasePath string `json:"database_path"`
	HMACSecret   string `json:"hmac_secret"`
	DSMLoginAPI  string `json:"dsm_login_api"`
}

func LoadPrivilegedHelper() (HelperConfig, error) {
	if os.Geteuid() != 0 {
		return HelperConfig{}, errors.New("privileged Helper must run as root through the installed controller")
	}
	if err := securefs.CheckRootPath(HelperConfigPath); err != nil {
		return HelperConfig{}, fmt.Errorf("trusted Helper configuration: %w", err)
	}
	info, err := os.Stat(HelperConfigPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return HelperConfig{}, errors.New("trusted Helper configuration must be a private regular file")
	}
	data, err := os.ReadFile(HelperConfigPath)
	if err != nil {
		return HelperConfig{}, err
	}
	return parsePrivilegedHelper(data)
}

func parsePrivilegedHelper(data []byte) (HelperConfig, error) {
	var settings RootHelperSettings
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return HelperConfig{}, fmt.Errorf("trusted Helper configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return HelperConfig{}, errors.New("trusted Helper configuration contains trailing data")
	}
	if settings.PackageUID <= 0 || uint64(settings.PackageUID) >= 1<<32-1 || settings.PackageGID <= 0 || uint64(settings.PackageGID) >= 1<<32-1 || !filepath.IsAbs(settings.DatabasePath) || filepath.Clean(settings.DatabasePath) != settings.DatabasePath {
		return HelperConfig{}, errors.New("trusted Helper configuration requires a non-root package identity and absolute database path")
	}
	if len(settings.HMACSecret) < 32 || strings.ContainsAny(settings.HMACSecret, "\x00\r\n") {
		return HelperConfig{}, errors.New("trusted Helper configuration has an invalid signing secret")
	}
	endpoint, err := url.Parse(settings.DSMLoginAPI)
	if err != nil || (endpoint.Scheme != "https" && endpoint.Scheme != "http") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/webapi/entry.cgi" {
		return HelperConfig{}, errors.New("trusted Helper DSM endpoint must be a loopback DSM Auth API URL")
	}
	ip := net.ParseIP(endpoint.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return HelperConfig{}, errors.New("trusted Helper DSM endpoint must use a loopback IP address")
	}
	return HelperConfig{
		Privileged: true, PackageUID: settings.PackageUID, PackageGID: settings.PackageGID,
		AccountPolicyPath: HelperDataDir + "/account-policy.json", PasswdPath: "/etc/passwd", GroupPath: "/etc/group",
		DatabaseURL: "sqlite://" + settings.DatabasePath, DataDir: HelperDataDir,
		SocketPath: HelperSocketPath, HMACSecret: settings.HMACSecret, TimestampSkewSeconds: 60,
		DSMLoginAPI: settings.DSMLoginAPI, DSMSession: "webui", DSMTLSSkipVerify: true,
		DSMTimeoutSeconds: 10, DSMBrowserLoginTTLSeconds: 30,
		ShadowPath: "/etc/shadow", ShadowLockPath: HelperRunDir + "/locks/shadow.lock",
		OpenSSLPath: "/usr/bin/openssl", LockDir: HelperRunDir + "/locks",
		JournalDir: HelperDataDir + "/journal", TempPasswordLength: 64, InitialPasswordLength: 32,
		SynoUserPath: "/usr/syno/sbin/synouser", SynoGroupPath: "/usr/syno/sbin/synogroup",
		SynoWebAPIPath: "/usr/syno/bin/synowebapi",
	}, nil
}

func ValidateRootHelperSettings(settings RootHelperSettings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = parsePrivilegedHelper(data)
	return err
}
