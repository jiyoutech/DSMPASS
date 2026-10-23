//go:build linux

package helperserver

import (
	"errors"
	"net"
	"syscall"
)

func helperPeerUID(conn net.Conn) (int, error) {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("Helper requires a Unix socket peer")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credentials, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		uid = int(credentials.Uid)
	})
	return uid, errors.Join(err, credentialErr)
}
