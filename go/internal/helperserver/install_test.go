package helperserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestBootstrapSecretTreatsEnvAsData(t *testing.T) {
	secret := strings.Repeat("a", 64)
	got, err := bootstrapHelperSecret("UNRELATED=$(untrusted-command)\nDSMPASS_HELPER_HMAC_SECRET=" + secret + "\n")
	if err != nil || got != secret {
		t.Fatal("valid literal secret was not read")
	}
	for _, data := range []string{"", "DSMPASS_HELPER_HMAC_SECRET=$(untrusted-command)", "DSMPASS_HELPER_HMAC_SECRET='" + secret + "'", "DSMPASS_HELPER_HMAC_SECRET=" + secret + "\nDSMPASS_HELPER_HMAC_SECRET=" + secret, "DSMPASS_HELPER_HMAC_SECRET=short"} {
		if _, err := bootstrapHelperSecret(data); err == nil {
			t.Fatal("invalid or ambiguous secret accepted")
		}
	}
}

func TestHelperSudoRuleRestrictsCommandsAndEnvironment(t *testing.T) {
	rule := helperSudoersRule()
	if strings.Contains(rule, "NOPASSWD:SETENV:") || strings.Contains(rule, config.HelperBinaryPath) || strings.Contains(rule, "/var/packages/") || strings.Contains(rule, "*") {
		t.Fatal("sudo rule permits untrusted executable, arguments or environment")
	}
	if !strings.Contains(rule, "NOSETENV:") || !strings.Contains(rule, "!setenv") {
		t.Fatal("sudo environment restrictions missing")
	}
	for _, action := range []string{"start", "stop", "restart", "status", "upgrade", "uninstall-preserve", "uninstall-purge"} {
		if !strings.Contains(rule, config.HelperControlPath+" "+action) {
			t.Fatal("required control action missing")
		}
	}
	if visudo, err := exec.LookPath("visudo"); err == nil {
		path := filepath.Join(t.TempDir(), "sudoers")
		if err := os.WriteFile(path, []byte(rule), 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(visudo, "-cf", path).CombinedOutput(); err != nil {
			t.Fatalf("invalid sudo rule: %v: %s", err, output)
		}
	}
}

func TestParseHelperProcessStartTime(t *testing.T) {
	fields := []string{"S", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "12345"}
	got, err := parseProcessStartTime("123 (helper with ) spaces) " + strings.Join(fields, " "))
	if err != nil || got != "12345" {
		t.Fatalf("unexpected start time: %s, %v", got, err)
	}
	for _, invalid := range []string{"", "123 helper", "123 (helper) S 1", "123 (helper) " + strings.Repeat("bad ", 20)} {
		if _, err := parseProcessStartTime(invalid); err == nil {
			t.Fatal("invalid process identity accepted")
		}
	}
}

func TestHelperInstallationWaitsForRecovery(t *testing.T) {
	for _, status := range []string{"restored", "superseded", "pending", "active_browser_login", "restoring_browser_login", "unknown", ""} {
		t.Run(status, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte(`{"status":"`+status+`"}`), 0600); err != nil {
				t.Fatal(err)
			}
			err := assertNoPendingJournals(dir)
			if (err == nil) != (status == "restored" || status == "superseded") {
				t.Fatalf("incorrect recovery gate: %v", err)
			}
		})
	}
}
