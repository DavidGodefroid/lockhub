package peer

import (
	"net"
	"syscall"
)

func cred(c *net.UnixConn) (Cred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Cred{}, err
	}
	var uc *syscall.Ucred
	var serr error
	err = raw.Control(func(fd uintptr) {
		uc, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return Cred{}, err
	}
	if serr != nil {
		return Cred{}, serr
	}
	return Cred{UID: int(uc.Uid), PID: int(uc.Pid), Known: true}, nil
}
