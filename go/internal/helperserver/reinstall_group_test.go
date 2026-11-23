package helperserver

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func emptyDirectorySnapshot() (*db.HelperEnrollmentSnapshot, error) {
	return &db.HelperEnrollmentSnapshot{Users: []string{}, Groups: []string{}}, nil
}

func TestDirectoryGroupReuseAfterCleanReinstall(t *testing.T) {
	for _, tc := range []struct {
		name, change string
		allowed      bool
	}{
		{"pending", "UPDATE dsm_groups SET provision_status='pending'", true},
		{"previously_failed", "UPDATE dsm_groups SET provision_status='failed'", true},
		{"already_linked", "UPDATE dsm_groups SET provision_status='linked_existing'", true},
		{"missing_mapping", "DELETE FROM dsm_mapping_entries WHERE mapping_type='group'", false},
		{"inactive_mapping", "UPDATE dsm_mapping_entries SET active=0", false},
		{"inactive_department", "UPDATE provider_groups SET active=0", false},
		{"different_source", "UPDATE provider_groups SET provider_slug='other'", false},
		{"conflict", "UPDATE dsm_groups SET provision_status='conflict'", false},
		{"disabled_sync", "UPDATE identity_sources SET directory_sync_enabled=0", false},
		{"disabled_source", "UPDATE identity_sources SET enabled=0", false},
		{"wrong_name", "UPDATE dsm_groups SET dsm_groupname='other'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := policyTestConfig(t)
			if _, err := migrateAccountPolicy(cfg, false, emptyDirectorySnapshot); err != nil {
				t.Fatal(err)
			}
			q := syncedPasswordTestStore(t, "alice")
			addEngineeringMapping(t, q)
			if _, err := q.DBTX().ExecContext(context.Background(), tc.change); err != nil {
				t.Fatal(err)
			}
			cfg.SynoUserPath = "/usr/bin/true"
			cfg.SynoGroupPath = filepath.Join(t.TempDir(), "synogroup")
			marker := cfg.SynoGroupPath + ".member"
			// The native stub accepts only a single member addition. Recreating
			// the group or replacing its list would fail this test.
			if err := os.WriteFile(cfg.SynoGroupPath, []byte("#!/bin/sh\n[ \"$#\" = 3 ] && [ \"$1\" = --memberadd ] && [ \"$2\" = engineering ] && [ \"$3\" = alice ] && touch '"+marker+"'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := updateAccountPolicy(cfg, "alice", false, false); err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{"dsm_groupname": "engineering", "dsm_username": "alice"}
			server := NewWithStore(cfg, q)
			if r := server.mutateGroup(cfg, "scoped_add_group_member", payload); r["success"] == true {
				t.Fatal("member operation claimed group before provisioning")
			}
			for range 2 {
				r := server.mutateGroup(cfg, "scoped_provision_group", payload)
				if (r["success"] == true) != tc.allowed {
					t.Fatalf("provision: %v", r)
				}
			}
			if r := server.mutateGroup(cfg, "scoped_add_group_member", payload); (r["success"] == true) != tc.allowed {
				t.Fatalf("add: %v", r)
			}
			_, err := os.Stat(marker)
			if tc.allowed && err != nil || !tc.allowed && !os.IsNotExist(err) {
				t.Fatalf("unexpected native membership operation, stat: %v", err)
			}
			p, err := readAccountPolicy(cfg)
			if err != nil || (p.Groups["engineering"] == 65536) != tc.allowed || p.ReusableGroups["finance"] != 65537 {
				t.Fatalf("unexpected group policy: %+v %v", p, err)
			}
		})
	}
}

func TestDirectoryReuseBoundToInstalledGroupsAndRevocation(t *testing.T) {
	cfg := policyTestConfig(t)
	writeFile(t, cfg.GroupPath, "administrators:x:101:\nusers:x:100:\n财务部:x:65536:\nlast:x:95536:\nsystem:x:65535:\nafter:x:95537:\npackage:x:200000:\nldap:x:1000000:\ndocker:x:65540:\nalias1:x:65542:\nalias2:x:65542:\n")
	if _, err := migrateAccountPolicy(cfg, false, emptyDirectorySnapshot); err != nil {
		t.Fatal(err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil || !reflect.DeepEqual(p.ReusableGroups, map[string]int{"财务部": 65536, "last": 95536}) {
		t.Fatalf("captured groups: %v %v", p.ReusableGroups, err)
	}
	if err := updateAccountPolicy(cfg, "财务部", true, true); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfg.GroupPath, "administrators:x:101:\n财务部:x:65536:\nlast:x:65539:\nnew:x:65540:\n")
	for _, name := range []string{"财务部", "last", "new", "administrators", ""} {
		err := checkGroupEnrollment(cfg, name, func() (bool, error) { t.Fatal("queried a mapping outside the pinned scope"); return true, nil })
		if err == nil {
			t.Fatalf("unexpected reuse of %q", name)
		}
	}
	if err := updateAccountPolicy(cfg, "last", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateAccountPolicy(cfg, true, emptyDirectorySnapshot); err != nil {
		t.Fatal(err)
	}
	p, err = readAccountPolicy(cfg)
	if err != nil || p.ReusableGroups == nil || len(p.ReusableGroups) != 0 {
		t.Fatalf("reset an empty snapshot: %+v %v", p, err)
	}
}

func TestLegacyGroupPolicyRequiresExplicitInstallerOptIn(t *testing.T) {
	cfg := policyTestConfig(t)
	writeFile(t, cfg.AccountPolicyPath, `{"users":{},"groups":{"engineering":65538},"legacy_migration_complete":true}`)
	if err := os.Chmod(cfg.AccountPolicyPath, 0600); err != nil {
		t.Fatal(err)
	}
	for _, optIn := range []bool{false, true} {
		if _, err := migrateAccountPolicy(cfg, optIn, func() (*db.HelperEnrollmentSnapshot, error) { t.Fatal("re-ran legacy migration"); return nil, nil }); err != nil {
			t.Fatal(err)
		}
		p, err := readAccountPolicy(cfg)
		if err != nil || (p.ReusableGroups["finance"] == 65537) != optIn || p.Groups["engineering"] != 65538 {
			t.Fatalf("legacy migration: %+v %v", p, err)
		}
		err = checkGroupEnrollment(cfg, "engineering", func() (bool, error) { return true, nil })
		if err == nil || !strings.Contains(err.Error(), "65538") {
			t.Fatalf("existing binding replaced: %v", err)
		}
	}
}

func TestDirectoryReuseRechecksGIDAfterMappingLookup(t *testing.T) {
	cfg := policyTestConfig(t)
	if _, err := migrateAccountPolicy(cfg, false, emptyDirectorySnapshot); err != nil {
		t.Fatal(err)
	}
	groupFile, err := os.ReadFile(cfg.GroupPath)
	if err != nil {
		t.Fatal(err)
	}
	err = checkGroupEnrollment(cfg, "engineering", func() (bool, error) {
		writeFile(t, cfg.GroupPath, strings.Replace(string(groupFile), "engineering:x:65536:", "engineering:x:65539:", 1))
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "65539") {
		t.Fatalf("group changed during lookup: %v", err)
	}
	p, err := readAccountPolicy(cfg)
	if err != nil || p.ReusableGroups["engineering"] != 65536 || len(p.Groups) != 0 {
		t.Fatalf("unexpected enrollment: %+v %v", p, err)
	}
}
