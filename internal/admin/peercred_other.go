//go:build !darwin && !linux

package admin

import (
	"errors"
	"net"
)

// peerUID is not implemented on this OS — treated as an error so the
// session refuses the connection rather than silently accepting it.
func peerUID(_ net.Conn) (uint32, error) {
	return 0, errors.New("peerUID: unsupported OS")
}
