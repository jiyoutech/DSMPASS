//go:build !linux

package helperserver

import (
	"errors"
	"net"
)

func helperPeerUID(conn net.Conn) (int, error) {
	return 0, errors.New("privileged Helper peer verification requires Linux")
}
