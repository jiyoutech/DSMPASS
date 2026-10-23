package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedPathRejectsReplacementByOtherUsers(t *testing.T) {
	for _, kind := range []string{"safe", "writable file", "writable parent", "symlink file", "symlink parent", "wrong owner", "missing"} {
		t.Run(kind, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "protected")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "program")
			if err := os.WriteFile(path, []byte("trusted"), 0600); err != nil {
				t.Fatal(err)
			}
			owner := os.Geteuid()
			switch kind {
			case "writable file":
				err = os.Chmod(path, 0660)
			case "writable parent":
				err = os.Chmod(parent, 0770)
			case "symlink file":
				link := filepath.Join(parent, "link")
				err = os.Symlink(path, link)
				path = link
			case "symlink parent":
				link := filepath.Join(root, "link")
				err = os.Symlink(parent, link)
				path = filepath.Join(link, "program")
			case "wrong owner":
				owner++
			case "missing":
				path = filepath.Join(parent, "missing")
			}
			if err != nil {
				t.Fatal(err)
			}
			err = checkPath(path, root, owner)
			if (err == nil) != (kind == "safe") {
				t.Fatalf("unexpected trust decision for %s: %v", kind, err)
			}
		})
	}
}
