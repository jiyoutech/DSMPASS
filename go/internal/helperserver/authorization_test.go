package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func policyTestConfig(t *testing.T) config.HelperConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := config.HelperConfig{AccountPolicyPath: filepath.Join(dir, "policy.json"), PasswdPath: filepath.Join(dir, "passwd"), GroupPath: filepath.Join(dir, "group"), JournalDir: filepath.Join(dir, "journal"), LockDir: filepath.Join(dir, "locks"), ShadowLockPath: filepath.Join(dir, "shadow.lock")}
	writeFile(t, cfg.PasswdPath, "root:x:0:0:root:/root:/bin/sh\nalice:x:1026:100:Alice:/home/alice:/bin/sh\nbob:x:1027:100:Bob:/home/bob:/bin/sh\noperator:x:1028:100:Operator:/home/operator:/bin/sh\nservice:x:500:100:Service:/:/bin/false\n")
	writeFile(t, cfg.GroupPath, "root:x:0:root\nusers:x:100:alice,bob\nadministrators:x:101:operator\nengineering:x:65536:alice\nfinance:x:65537:bob\n")
	return cfg
}

func TestAccountPolicyRequiresIndependentEnrollment(t *testing.T) {
	cfg := policyTestConfig(t)
	if err := requireManagedUser(cfg, "alice"); err == nil {
		t.Fatal("missing policy allowed account")
	}
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedUser(cfg, "alice"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bob", "operator", "root", "service", "missing", "-option", "alice\n"} {
		if err := requireManagedUser(cfg, name); err == nil {
			t.Fatalf("allowed %q", name)
		}
	}
	for _, name := range []string{"operator", "root", "service"} {
		if err := updateAccountPolicy(cfg, name, false, false); err == nil {
			t.Fatalf("enrolled privileged account %s", name)
		}
	}
	data, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, strings.Replace(string(data), "alice:x:1026:", "alice:x:1030:", 1))
	if err := requireManagedUser(cfg, "alice"); err == nil {
		t.Fatal("UID reuse accepted")
	}
	writeFile(t, cfg.PasswdPath, string(data))
	writeFile(t, cfg.GroupPath, "root:x:0:root\nusers:x:100:alice\nadministrators:x:101:operator,alice\n")
	if err := requireManagedUser(cfg, "alice"); err == nil {
		t.Fatal("administrator promotion ignored")
	}
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	policy, err := readAccountPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := policy.Users["alice"]; ok {
		t.Fatal("revocation failed")
	}
}

func TestPolicyRejectsUntrustedFileAndAmbiguousSystemIdentity(t *testing.T) {
	for _, test := range []string{"writable", "symlink", "malformed", "duplicate_uid", "missing_admin_group"} {
		t.Run(test, func(t *testing.T) {
			cfg := policyTestConfig(t)
			if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
				t.Fatal(err)
			}
			switch test {
			case "writable":
				if err := os.Chmod(cfg.AccountPolicyPath, 0666); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				original := cfg.AccountPolicyPath
				cfg.AccountPolicyPath += ".link"
				if err := os.Symlink(original, cfg.AccountPolicyPath); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				writeFile(t, cfg.AccountPolicyPath, `{"users":{"alice":1026},"groups":{}} {}`)
			case "duplicate_uid":
				writeFile(t, cfg.PasswdPath, "alice:x:1026:100::/:/bin/sh\nbob:x:1026:100::/:/bin/sh\n")
			case "missing_admin_group":
				writeFile(t, cfg.GroupPath, "users:x:100:alice\n")
			}
			if err := requireManagedUser(cfg, "alice"); err == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}

func TestLoginRequiresIdentitySourceAndActiveMapping(t *testing.T) {
	for _, tc := range []struct {
		name, sql, field, value string
		allowed                 bool
	}{
		{name: "normal", allowed: true},
		{name: "manually_named", sql: "UPDATE dsm_accounts SET managed=0", allowed: true},
		{name: "wrong_identity", field: "identity_id", value: "other"},
		{name: "missing_identity", field: "identity_id"},
		{name: "wrong_source", field: "login_source", value: "other"},
		{name: "missing_source", field: "login_source"},
		{name: "wrong_username", field: "dsm_username", value: "bob"},
		{name: "unmapped", sql: "DELETE FROM dsm_mapping_entries"},
		{name: "mapping_inactive", sql: "UPDATE dsm_mapping_entries SET active=0"},
		{name: "source_disabled", sql: "UPDATE identity_sources SET enabled=0"},
		{name: "login_disabled", sql: "UPDATE identity_sources SET login_enabled=0"},
		{name: "external_inactive", sql: "UPDATE external_accounts SET active=0"},
		{name: "identity_disabled", sql: "UPDATE app_identities SET status='disabled'"},
		{name: "account_disabled", sql: "UPDATE dsm_accounts SET allow_login=0"},
		{name: "unprovisioned", sql: "UPDATE dsm_accounts SET provision_status='pending'"},
		{name: "external_mismatch", sql: "UPDATE external_accounts SET app_identity_id='other'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policyTestConfig(t)
			if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			if tc.sql != "" {
				if _, err := q.DBTX().ExecContext(context.Background(), tc.sql); err != nil {
					t.Fatal(err)
				}
			}
			payload := map[string]any{"dsm_username": "alice", "identity_id": "identity", "login_source": "source"}
			if tc.field != "" {
				payload[tc.field] = tc.value
			}
			err := NewWithStore(cfg, q).authorizeLogin(cfg, payload)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
		})
	}
}

func TestSignedRequestsCannotGrantOrBypassAccountScope(t *testing.T) {
	cfg := policyTestConfig(t)
	cfg.HMACSecret, cfg.TimestampSkewSeconds = "test-secret", 60
	cfg.SynoUserPath, cfg.SynoGroupPath = "/must-not-run", "/must-not-run"
	server := NewWithStore(cfg, syncedPasswordTestStore(t, "alice"))
	for _, action := range []string{"relay_login", "prepare_browser_login", "provision_user", "reset_synced_user_password", "disable_user", "add_group_member", "remove_group_member", "provision_group", "authorize-user", "scoped_relay_login", "scoped_prepare_browser_login", "scoped_disable_user", "scoped_reset_synced_user_password", "scoped_remove_group_member"} {
		p := signedPayload(t, cfg.HMACSecret, map[string]any{"action": action, "request_id": "test", "dsm_username": "alice", "identity_id": "identity", "login_source": "source", "source_slug": "source", "account_id": "account", "password": "test-password", "dsm_groupname": "engineering"})
		if response := server.handlePayload(p); response["success"] == true {
			t.Fatalf("action %s bypassed authorization: %v", action, response)
		}
	}
	if _, err := os.Stat(cfg.AccountPolicyPath); !os.IsNotExist(err) {
		t.Fatal("RPC changed enrollment policy")
	}
}

func TestGroupScopeRequiresEnrollmentAndRechecksGID(t *testing.T) {
	cfg := policyTestConfig(t)
	if err := requireManagedGroup(cfg, "engineering"); err == nil {
		t.Fatal("unmanaged group accepted")
	}
	if err := updateAccountPolicy(cfg, "engineering", true, false); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedGroup(cfg, "engineering"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"users", "administrators", "root", "finance", "-group", "bad\ngroup"} {
		if err := requireManagedGroup(cfg, name); err == nil {
			t.Fatalf("allowed group %q", name)
		}
	}
	writeFile(t, cfg.GroupPath, "administrators:x:101:\nengineering:x:65538:\n")
	if err := requireManagedGroup(cfg, "engineering"); err == nil {
		t.Fatal("recreated group accepted")
	}
}

func TestRevocationBlocksLoginButAllowsPasswordRecovery(t *testing.T) {
	cfg, original := shadowOnlyTestConfig(t)
	policy := policyTestConfig(t)
	cfg.AccountPolicyPath, cfg.PasswdPath, cfg.GroupPath = policy.AccountPolicyPath, policy.PasswdPath, policy.GroupPath
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "revoked-login", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "alice", false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareBrowserLogin(cfg, "revoked-login", "alice"); err == nil {
		t.Fatal("idempotent login bypassed revocation")
	}
	if err := restorePendingJournal(cfg, "revoked-login", "revoked"); err != nil {
		t.Fatal(err)
	}
	line, err := shadowLine(cfg.ShadowPath, "alice")
	if err != nil || line != original {
		t.Fatalf("recovery failed: %q %v", line, err)
	}
}

func TestAuthorizationOutputIsBounded(t *testing.T) {
	var output limitedAuthorizationOutput
	if _, err := output.Write(make([]byte, 8192)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestProvisionOnlyEnrollsSuccessfullyCreatedAccounts(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{true: "existing", false: "new"}[existing], func(t *testing.T) {
			cfg := policyTestConfig(t)
			username := "new-user"
			if existing {
				username = "alice"
			}
			cfg.SynoUserPath = filepath.Join(t.TempDir(), "synouser")
			marker := cfg.SynoUserPath + ".mutation"
			body := "#!/bin/sh\ncase \"$1\" in\n--get) /usr/bin/grep -q \"^$2:\" '" + cfg.PasswdPath + "';;\n--add) printf 'new-user:x:1030:100:New:/:/bin/sh\\n' >> '" + cfg.PasswdPath + "'; printf called > '" + marker + "';;\n--modify) printf called > '" + marker + "';;\nesac\n"
			if err := os.WriteFile(cfg.SynoUserPath, []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
			s := NewWithStore(cfg, syncedPasswordTestStore(t, username))
			response := s.provisionAccount(cfg, map[string]any{"dsm_username": username, "display_name": "New", "initial_password": "private-test"})
			if (response["success"] == true) == existing {
				t.Fatalf("existing=%v response=%v", existing, response)
			}
			_, err := os.Stat(marker)
			if existing && !os.IsNotExist(err) {
				t.Fatal("existing unapproved account was modified")
			}
			if !existing {
				if err := requireManagedUser(cfg, username); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGroupMutationsRefuseExistingUnapprovedGroups(t *testing.T) {
	cfg := policyTestConfig(t)
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(t.TempDir(), "native-command")
	marker := command + ".mutation"
	if err := os.WriteFile(command, []byte("#!/bin/sh\n[ \"$1\" = --get ] && exit 0\nprintf called > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.SynoGroupPath, cfg.SynoUserPath = command, command
	s := New(cfg)
	for _, action := range []string{"scoped_provision_group", "scoped_add_group_member", "scoped_remove_group_member"} {
		r := s.mutateGroup(cfg, action, map[string]any{"dsm_username": "alice", "dsm_groupname": "engineering"})
		if r["success"] == true {
			t.Fatalf("unapproved mutation: %v", r)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("native mutation ran")
	}
	if err := updateAccountPolicy(cfg, "engineering", true, false); err != nil {
		t.Fatal(err)
	}
	r := s.mutateGroup(cfg, "scoped_add_group_member", map[string]any{"dsm_username": "alice", "dsm_groupname": "engineering"})
	if r["success"] != true {
		t.Fatalf("authorized mutation failed: %v", r)
	}
}

func TestSystemAliasesAndCommentsDoNotBlockUnrelatedManagedAccounts(t *testing.T) {
	cfg := policyTestConfig(t)
	passwd, err := os.ReadFile(cfg.PasswdPath)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := os.ReadFile(cfg.GroupPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.PasswdPath, string(passwd)+"service_a:x:21:21::/:/bin/false\nservice_b:x:21:21::/:/bin/false\n")
	writeFile(t, cfg.GroupPath, "# DSM system groups\n   \n"+string(groups)+"root_alias:x:0:\n")
	if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedUser(cfg, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := updateAccountPolicy(cfg, "engineering", true, false); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedGroup(cfg, "engineering"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.GroupPath, string(groups)+"administrator_alias:x:101:alice\n")
	if err := requireManagedUser(cfg, "alice"); err == nil {
		t.Fatal("administrator group alias bypassed protection")
	}
	writeFile(t, cfg.GroupPath, string(groups)+"engineering_alias:x:65536:\n")
	if err := requireManagedGroup(cfg, "engineering"); err == nil {
		t.Fatal("ambiguous target GID accepted")
	}
}
