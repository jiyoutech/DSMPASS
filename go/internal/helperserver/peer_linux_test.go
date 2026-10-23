//go:build linux

package helperserver

import (
	"encoding/json"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestHelperUsesKernelPeerCredentials(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]net.Conn, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "peer-test")
		connections[i], err = net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		defer connections[i].Close()
		if err := connections[i].SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	uid, err := helperPeerUID(connections[0])
	if err != nil || uid != os.Geteuid() {
		t.Fatalf("unexpected peer identity: %d, %v", uid, err)
	}
	if os.Geteuid() != 0 {
		s := New(config.HelperConfig{Privileged: true, PackageUID: os.Geteuid() + 1})
		go s.handle(connections[0])
		var payload map[string]any
		if err := json.NewDecoder(connections[1]).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		// Rejection happens before any signing secret or request is read.
		if payload["success"] != false {
			t.Fatalf("unrelated local peer accepted: %v", payload)
		}
	}
}
