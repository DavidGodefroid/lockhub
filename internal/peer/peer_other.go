//go:build !linux

package peer

import (
	"errors"
	"net"
)

func cred(*net.UnixConn) (Cred, error) { return Cred{}, errors.New("peer credentials: Linux only") }
