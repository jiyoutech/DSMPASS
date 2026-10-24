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
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("hook: %v %s", err, output)
				}
				_, markerErr := os.Stat(marker)
				_, dataErr := os.Stat(pkgvar)
				if status != "UNINSTALL" {
					if !os.IsNotExist(markerErr) || dataErr != nil {
						t.Fatal("non-uninstall lifecycle removed helper or data")
					}
				} else if hook == "preuninst" {
					called, err := os.ReadFile(marker)
					if err != nil || string(called) != "uninstall-purge" {
						t.Fatal("uninstall did not select fixed purge action", err)
					}
				} else if !os.IsNotExist(dataErr) {
					t.Fatal("requested uninstall did not remove package data")
				}
			})
		}
	}
}
