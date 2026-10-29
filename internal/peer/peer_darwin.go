package peer

import (
	"net"

	"golang.org/x/sys/unix"
)

func cred(c *net.UnixConn) (Cred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Cred{}, err
	}
	var x *unix.Xucred
	var pid int
	var serr error
	err = raw.Control(func(fd uintptr) {
		x, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if serr == nil {
			pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	})
	if err != nil {
		return Cred{}, err
	}
	if serr != nil {
		return Cred{}, serr
	}
	return Cred{UID: int(x.Uid), PID: pid, Known: true}, nil
}
