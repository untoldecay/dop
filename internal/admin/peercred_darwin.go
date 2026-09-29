//go:build darwin

package admin

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective uid of the process on the other end of
// a unix socket connection. macOS uses LOCAL_PEERCRED (xucred).
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
		xu, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			innerErr = e
			return
		}
		uid = xu.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, innerErr
}
