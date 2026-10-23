package helperserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

// Unit tests isolate the hash command from the host's crypt implementation.
// The DSM integration test authenticates the real OpenSSL output with DSM.
func testShadowHashCommand(t *testing.T) string {
	t.Helper()
	hash := "$6$testsalt$" + strings.Repeat("A", 86)
	return testShadowHashScript(t, "cat >/dev/null\nprintf '%s\\n' '"+hash+"'\n")
}

func testShadowHashScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openssl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTemporaryShadowLinePreservesAccountFieldsAndUsesStdin(t *testing.T) {
	hash := "$6$testsalt$" + strings.Repeat("A", 86)
	command := testShadowHashScript(t, `
[ "$#" -eq 3 ] && [ "$1" = passwd ] && [ "$2" = -6 ] && [ "$3" = -stdin ] || exit 1
IFS= read -r password
[ "$password" = 'test-password' ] || exit 2
printf '%s\n' '`+hash+`'
`)
	line, err := temporaryShadowLine(command, "alice", "alice:$old:19000:2:90:7:14:20000:reserved", "test-password")
	if err != nil {
		t.Fatal(err)
	}
	if line != "alice:"+hash+":19000:2:90:7:14:20000:reserved" {
		t.Fatal("temporary password installation changed non-password fields")
	}
}

func TestTemporaryShadowLineRejectsInvalidInputsBeforeRunningCommand(t *testing.T) {
	cases := []struct{ name, username, record, password string }{
		{"empty user", "", "alice:$old:19000:0:99999:7:::", "password"},
		{"wrong user", "bob", "alice:$old:19000:0:99999:7:::", "password"},
		{"bad fields", "alice", "alice:$old", "password"},
		{"extra record", "alice", "alice:$old:19000:0:99999:7:::\nbob:$old:19000:0:99999:7:::", "password"},
		{"locked", "alice", "alice:!$old:19000:0:99999:7:::", "password"},
		{"disabled", "alice", "alice:*:19000:0:99999:7:::", "password"},
		{"passwordless", "alice", "alice::19000:0:99999:7:::", "password"},
		{"empty password", "alice", "alice:$old:19000:0:99999:7:::", ""},
		{"multiline password", "alice", "alice:$old:19000:0:99999:7:::", "password\nother"},
		{"nul password", "alice", "alice:$old:19000:0:99999:7:::", "password\x00other"},
		{"long password", "alice", "alice:$old:19000:0:99999:7:::", strings.Repeat("a", 128)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := temporaryShadowLine("/nonexistent/hash-command", tc.username, tc.record, tc.password)
			if err == nil || strings.Contains(err.Error(), "generate temporary") {
				t.Fatalf("expected input validation before command invocation, got %v", err)
			}
		})
	}
}

func TestTemporaryShadowLineRejectsHashFailuresWithoutLeakingOutput(t *testing.T) {
	for _, body := range []string{
		"echo private-password >&2; exit 1\n",
		"echo private-password\n",
		"echo '$1$salt$invalid'\n",
		"echo '$6$salt$short'\n",
		"printf '%s\\n' '$6$salt$" + strings.Repeat("?", 86) + "'\n",
	} {
		_, err := temporaryShadowLine(testShadowHashScript(t, body), "alice", "alice:$old:19000:0:99999:7:::", "private-password")
		if err == nil || strings.Contains(err.Error(), "private-password") {
			t.Fatalf("expected a non-sensitive hash error, got %v", err)
		}
	}
}

func shadowOnlyTestConfig(t *testing.T) (config.HelperConfig, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	original := "alice:$original:19000:2:90:7:14:20000:reserved"
	if err := os.WriteFile(path, []byte(original+"\nbob:$untouched:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := browserLoginTestConfig(t, path, filepath.Join(dir, "journal"), filepath.Join(dir, "locks"), "/must-not-invoke-synouser")
	return cfg, original
}

func TestShadowOnlyBrowserLoginRestoresWithoutDSMVerification(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	before, err := os.ReadFile(cfg.ShadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "shadow-only-browser", "alice"); err != nil {
		t.Fatal(err)
	}
	current, err := shadowLine(cfg.ShadowPath, "alice")
	if err != nil || current == original {
		t.Fatalf("temporary password was not installed: %v", err)
	}
	j, err := loadJournal(cfg, "shadow-only-browser")
	if err != nil || j.TempLineHash != lineHash(current) {
		t.Fatalf("journal cannot identify the temporary record: %v", err)
	}
	// Simulate a crash after replacing shadow but before persisting active status.
	j.Status = journalStatusPendingBrowser
	if err := saveJournal(cfg, j); err != nil {
		t.Fatal(err)
	}
	if err := recoverPending(cfg); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cfg.ShadowPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("startup recovery did not preserve every original shadow record: %v", err)
	}
}

func TestShadowOnlyPreparationFailurePreservesShadow(t *testing.T) {
	for _, failure := range []string{"hash", "journal", "duplicate", "external change"} {
		t.Run(failure, func(t *testing.T) {
			cfg, original := shadowOnlyTestConfig(t)
			want, err := os.ReadFile(cfg.ShadowPath)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "hash":
				cfg.OpenSSLPath = "/nonexistent/hash-command"
			case "journal":
				if err := os.WriteFile(cfg.JournalDir, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				want = append(want, []byte(original+"\n")...)
				if err := os.WriteFile(cfg.ShadowPath, want, 0o600); err != nil {
					t.Fatal(err)
				}
			case "external change":
				want = []byte(strings.Replace(string(want), "$original", "$external-change", 1))
				cfg.OpenSSLPath = testShadowHashScript(t, fmt.Sprintf("cat >/dev/null\nprintf '%%s' '%s' > '%s'\nprintf '%%s\\n' '$6$salt$%s'\n", want, cfg.ShadowPath, strings.Repeat("A", 86)))
			}
			if _, err := prepareBrowserLogin(cfg, "failed-prepare", "alice"); err == nil {
				t.Fatal("expected preparation to fail")
			}
			got, err := os.ReadFile(cfg.ShadowPath)
			if err != nil || string(got) != string(want) {
				t.Fatalf("failed preparation overwrote shadow: %v", err)
			}
		})
	}
}

func TestShadowOnlyRelayRestoresAfterDSMFailure(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":400}}`))
	}))
	defer auth.Close()
	cfg.DSMLoginAPI = auth.URL
	cfg.DSMTimeoutSeconds = 2
	if _, err := relayLoginReal(cfg, "failed-auth", "alice"); err == nil {
		t.Fatal("expected DSM login failure")
	}
	line, err := shadowLine(cfg.ShadowPath, "alice")
	if err != nil || line != original {
		t.Fatalf("failed DSM authentication left a temporary shadow password: %v", err)
	}
}

func TestShadowOnlyBrowserTTLRestoresPassword(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	cfg.DSMBrowserLoginTTLSeconds = 1
	if _, err := prepareBrowserLogin(cfg, "ttl-restore", "alice"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := loadJournal(cfg, "ttl-restore")
		if err == nil && j.Status == "restored" {
			line, err := shadowLine(cfg.ShadowPath, "alice")
			if err != nil || line != original {
				t.Fatalf("TTL recovery did not restore the original password: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("browser password was not restored after TTL")
}
