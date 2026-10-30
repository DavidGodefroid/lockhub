//go:build !linux && !darwin

package peer

import (
	"errors"
	"net"
)

func cred(*net.UnixConn) (Cred, error) { return Cred{}, errors.New("peer credentials: Linux only") }
