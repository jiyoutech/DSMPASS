package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Execute the real packaging entrypoint. A sentinel npm stops ordinary builds
// before they compile anything, and proves unsigned releases stop even earlier.
func TestPackageRequiresSigningForReleases(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\necho frontend-build-reached >&2\nexit 42\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DSMPASS_HELPER_SIGNING_KEY", "")
	t.Setenv("DSMPASS_HELPER_SIGNING_KEY_FILE", "")
	t.Setenv("DSMPASS_ALLOW_MULTIPLE_IDENTITY_SOURCES", "0")
	t.Setenv("DSMPASS_BUILD_EPOCH", "1")
	for _, tc := range []struct {
		name, actions, refType, required string
		blocked                          bool
	}{
		{"local source", "", "", "0", false},
		{"branch CI", "true", "branch", "0", false},
		{"tag CI", "true", "tag", "0", true},
		{"explicit signed release", "", "", "1", true},
		{"invalid requirement", "", "", "false", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_ACTIONS", tc.actions)
			t.Setenv("GITHUB_REF_TYPE", tc.refType)
			t.Setenv("DSMPASS_REQUIRE_SIGNED_RELEASE", tc.required)
			output, err := exec.Command("sh", "./package-dsm.sh").CombinedOutput()
			if err == nil {
				t.Fatal("packaging unexpectedly completed")
			}
			reachedBuild := strings.Contains(string(output), "frontend-build-reached")
			if reachedBuild == tc.blocked {
				t.Fatalf("unexpected signing gate result: %s", output)
			}
			if tc.blocked && !strings.Contains(string(output), "Signed release required") && !strings.Contains(string(output), "DSMPASS_REQUIRE_SIGNED_RELEASE must") {
				t.Fatalf("packaging failed for another reason: %s", output)
			}
		})
	}
}
