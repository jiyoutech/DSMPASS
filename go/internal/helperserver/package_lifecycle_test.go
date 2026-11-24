package helperserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the generated shell hooks with a fake controller. DSM calls both
// uninstall hooks during upgrades, including when deletion flags are inherited.
func TestUpgradeCannotRunUninstallCleanup(t *testing.T) {
	data, err := os.ReadFile("../../scripts/dsm/package-spk.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"preuninst", "postuninst"} {
		start := strings.Index(string(data), `cat > "$work_dir/scripts/`+hook+`" <<`)
		if start < 0 {
			t.Fatal("missing lifecycle hook")
		}
		body := string(data)[start:]
		body = body[strings.Index(body, "\n")+1:]
		body = body[:strings.Index(body, "\nEOF")]
		if hook == "postuninst" {
			body = strings.ReplaceAll(body, `\$`, `$`)
		}
		for _, status := range []string{"UPGRADE", "INSTALL", "", "UNINSTALL"} {
			t.Run(hook+"/"+status, func(t *testing.T) {
				dir := t.TempDir()
				marker := filepath.Join(dir, "called")
				controller := filepath.Join(dir, "controller")
				if err := os.WriteFile(controller, []byte("#!/bin/sh\nprintf '%s' \"$1\" > \"$TEST_MARKER\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
				pkgvar := filepath.Join(dir, "data")
				if err := os.Mkdir(pkgvar, 0700); err != nil {
					t.Fatal(err)
				}
				script := strings.ReplaceAll(body, "/usr/local/libexec/dsmpass/helper-control.sh", controller)
				script = strings.ReplaceAll(script, `/volume1/@appdata/$PACKAGE_NAME`, filepath.Join(dir, "appdata"))
				cmd := exec.Command("/bin/sh", "-c", script)
				cmd.Env = append(os.Environ(), "SYNOPKG_PKG_STATUS="+status, "SYNOPKG_PKGVAR="+pkgvar, "DSMPASS_DELETE_DATA=1", "TEST_MARKER="+marker)
				output, err := cmd.CombinedOutput()
				if hook == "preuninst" && status == "UNINSTALL" {
					if err == nil || !strings.Contains(string(output), "uninstall-purge") {
						t.Fatalf("missing administrator instruction: %v %s", err, output)
					}
					if err := os.Remove(controller); err != nil {
						t.Fatal(err)
					}
					retry := exec.Command("/bin/sh", "-c", script)
					retry.Env = cmd.Env
					if out, e := retry.CombinedOutput(); e != nil {
						t.Fatalf("uninstall after cleanup: %v %s", e, out)
					}
				} else if err != nil {
					t.Fatalf("hook: %v %s", err, output)
				}
				_, markerErr := os.Stat(marker)
				_, dataErr := os.Stat(pkgvar)
				if status != "UNINSTALL" || hook == "preuninst" {
					if !os.IsNotExist(markerErr) || dataErr != nil {
						t.Fatal("lifecycle hook unexpectedly ran cleanup")
					}
				} else if !os.IsNotExist(dataErr) {
					t.Fatal("requested uninstall did not remove package data")
				}
			})
		}
	}
}

func TestRetainedReinstallHooks(t *testing.T) {
	generator, err := os.ReadFile("../../scripts/dsm/package-spk.sh")
	if err != nil {
		t.Fatal(err)
	}
	hook := func(name string) string {
		t.Helper()
		tag := "cat > "
		if name == "postinst" {
			tag = "cat >> "
		}
		_, body, ok := strings.Cut(string(generator), tag+`"$work_dir/scripts/`+name+`" <<`)
		if !ok {
			t.Fatal("missing hook", name)
		}
		_, body, _ = strings.Cut(body, "\n")
		body, _, _ = strings.Cut(body, "\nEOF\n")
		return strings.ReplaceAll(body, `\$`, `$`)
	}
	for _, tc := range []struct {
		name, status                                            string
		retained, data, env, failUpgrade, wantManual, wantError bool
	}{
		{"preserved", "INSTALL", true, true, true, false, true, false},
		{"legacy-preserved", "INSTALL", false, true, true, false, true, false},
		{"ordinary-upgrade", "UPGRADE", false, true, true, false, false, false},
		{"clean-install", "INSTALL", false, false, false, false, false, false},
		{"missing-database", "INSTALL", true, false, true, false, false, true},
		{"missing-settings", "INSTALL", true, true, false, false, false, true},
		{"restore-refused", "INSTALL", true, true, true, true, true, true},
		{"changed-uid", "INSTALL", true, true, true, true, true, false},
		{"unsigned", "INSTALL", true, true, true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dataDir := filepath.Join(dir, "data")
			if err := os.Mkdir(dataDir, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.env {
				writeFile(t, filepath.Join(dir, "dsmpass.env"), "DSMPASS_GO_LISTEN=0.0.0.0:25000\n")
			}
			path := filepath.Join(dataDir, "dsmpass.db")
			if tc.data {
				writeFile(t, path, "saved database")
			}
			if tc.retained {
				writeFile(t, filepath.Join(dir, "retained"), "retained\n")
			}
			writeFile(t, filepath.Join(dir, "controller"), "#!/bin/sh\necho \"$1\" >> \"$SYNOPKG_PKGVAR/calls\"\nif [ \"$1\" = upgrade ] && [ -n \"$UPGRADE_ERROR\" ]; then echo \"$UPGRADE_ERROR\" >&2; exit 1; fi\n")
			// The real hook schedules an INFO refresh after installation. Keep that
			// separate package-manager operation outside this test.
			writeFile(t, filepath.Join(dir, "nohup"), "#!/bin/sh\nexit 0\n")
			for _, f := range []string{"nohup", "controller"} {
				if err := os.Chmod(filepath.Join(dir, f), 0700); err != nil {
					t.Fatal(err)
				}
			}
			run := func(name string, extra ...string) error {
				t.Helper()
				body := strings.NewReplacer("/usr/local/libexec/dsmpass/helper-control.sh", filepath.Join(dir, "controller"), "/usr/local/libexec/dsmpass/retained", filepath.Join(dir, "retained"), "/var/packages/", dir+"/packages/", "/volume1/@appdata/", dir+"/@appdata/").Replace(hook(name))
				cmd := exec.Command("/bin/sh", "-ec", body)
				cmd.Env = []string{"PATH=" + dir + ":" + os.Getenv("PATH"), "SYNOPKG_PKGVAR=" + dir, "SYNOPKG_PKGDEST=" + dir, "DEFAULT_MANAGEMENT_PORT=25000", "DEFAULT_IDP_PORT=24000", "PACKAGE_NAME=DSMPASS", "SYNOPKG_PKG_STATUS=" + tc.status}
				if tc.failUpgrade {
					detail := "Helper release signature is invalid"
					switch tc.name {
					case "changed-uid":
						detail = "reinstalled package UID/GID changed; run setup-helper-sudo.sh as root"
					case "unsigned":
						detail = "signed Helper manifest unavailable: no such file or directory"
					}
					cmd.Env = append(cmd.Env, "UPGRADE_ERROR="+detail)
				}
				cmd.Env = append(cmd.Env, extra...)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Logf("%s: %s", name, out)
				}
				return err
			}
			if tc.retained {
				if err := os.Remove(filepath.Join(dir, "retained")); err != nil {
					t.Fatal(err)
				}
				if err := run("preuninst", "SYNOPKG_PKG_STATUS=UNINSTALL", "keep_data=true"); err != nil {
					t.Fatal(err)
				}
				calls, err := os.ReadFile(filepath.Join(dir, "calls"))
				if err != nil || string(calls) != "retain\n" {
					t.Fatal("preserve action", string(calls), err)
				}
				if err := os.Remove(filepath.Join(dir, "calls")); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(dir, "retained"), "retained\n")
				if err := run("preuninst", "SYNOPKG_PKG_STATUS=UNINSTALL", "keep_data=true"); err != nil {
					t.Fatal(err)
				}
				if err := run("preuninst", "SYNOPKG_PKG_STATUS=UNINSTALL", "delete_data=true"); err == nil {
					t.Fatal("purge accepted before root cleanup")
				}
				if err := run("postuninst", "SYNOPKG_PKG_STATUS=UNINSTALL", "keep_data=true"); err != nil {
					t.Fatal(err)
				}
				if err := run("preinst"); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(dir, "calls")); !os.IsNotExist(err) {
					t.Fatal("dormant controller called before reinstall", err)
				}
			}
			err := run("postinst")
			if (err != nil) != tc.wantError {
				t.Fatalf("postinst returned %v", err)
			}
			if tc.data {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != "saved database" {
					t.Fatal("package data changed", err)
				}
			}
			_, err = os.Stat(filepath.Join(dataDir, "restore-manual-sync"))
			if (err == nil) != tc.wantManual {
				t.Fatal("wrong manual sync marker", err)
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
			if tc.retained && tc.data && tc.env && string(calls) != "upgrade\n" {
				t.Fatalf("reinstall actions %q", calls)
			}
		})
	}
}
