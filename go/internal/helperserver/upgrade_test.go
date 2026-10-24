package helperserver

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestUpgradeRollbackRestoresAllFilesAndReportsFailures(t *testing.T) {
	files := []protectedHelperFile{{"binary", []byte("old-binary"), 0755}, {"controller", []byte("old-controller"), 0755}, {"settings", []byte("root-settings"), 0600}}
	failure := errors.New("disk full")
	for _, fail := range []bool{false, true} {
		var restored []protectedHelperFile
		err := restoreProtectedHelperFiles(files, func(path string, data []byte, mode os.FileMode) error {
			restored = append(restored, protectedHelperFile{path, data, mode})
			if fail && path == "controller" {
				return failure
			}
			return nil
		})
		if !reflect.DeepEqual(restored, files) {
			t.Fatalf("rollback stopped before all files: %v", restored)
		}
		if (err != nil) != fail || fail && !errors.Is(err, failure) {
			t.Fatalf("lost rollback error: %v", err)
		}
	}
}
