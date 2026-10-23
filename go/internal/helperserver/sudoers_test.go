package helperserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSudoersFallbackRollbackAndConcurrency(t *testing.T) {
	for _, scenario := range []string{"success", "restore_existing", "remove_new", "concurrent_edit", "write_failure", "rollback_failure"} {
		t.Run(scenario, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sudoers")
			old, rule := []byte("old rule\n"), []byte(helperSudoersRule())
			if scenario != "remove_new" {
				if err := os.WriteFile(path, old, 0600); err != nil {
					t.Fatal(err)
				}
			}
			writes := 0
			write := func(data []byte) error {
				writes++
				if scenario == "write_failure" || (scenario == "rollback_failure" && writes == 2) {
					return errors.New("write failed")
				}
				return os.WriteFile(path, data, 0600)
			}
			validate := func() error {
				current, err := os.ReadFile(path)
				if err != nil || string(current) != string(rule) {
					t.Fatal("candidate was not installed for parser validation")
				}
				if scenario == "success" {
					return nil
				}
				if scenario == "concurrent_edit" {
					if err := os.WriteFile(path, []byte("another root edit\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return errors.New("parser rejected candidate")
			}
			err := replaceVerifiedSudoers(path, rule, write, validate)
			if (err == nil) != (scenario == "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			current, readErr := os.ReadFile(path)
			switch scenario {
			case "success":
				if string(current) != string(rule) {
					t.Fatal("valid rule not retained")
				}
			case "restore_existing", "write_failure":
				if string(current) != string(old) {
					t.Fatal("old rule lost")
				}
			case "remove_new":
				if !os.IsNotExist(readErr) {
					t.Fatal("rejected rule retained")
				}
			case "concurrent_edit":
				if string(current) != "another root edit\n" {
					t.Fatal("concurrent edit overwritten")
				}
			case "rollback_failure":
				if !strings.Contains(err.Error(), "write failed") {
					t.Fatal("rollback failure hidden")
				}
			}
		})
	}
}

func TestSudoValidatorRejectsErrorsEvenWithSuccessfulExit(t *testing.T) {
	for _, body := range []string{"exit 1", "echo 'syntax error' >&2; exit 0", "exit 0"} {
		path := filepath.Join(t.TempDir(), "validator")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		err := runSudoRuleValidator(path)
		if (err == nil) != (body == "exit 0") {
			t.Fatalf("validator %q: %v", body, err)
		}
	}
}
