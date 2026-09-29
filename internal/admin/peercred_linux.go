//go:build linux

package admin

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("peerUID: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var innerErr error
	err = raw.Control(func(fd uintptr) {
		ucred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			innerErr = e
			return
		}
		uid = ucred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, innerErr
}
