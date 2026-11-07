package lockconsoles

import (
	"bytes"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a new pseudo-terminal pair: lox run holds the master, the
// docker attach runs on the slave (posix_openpt, grantpt, unlockpt,
// ptsname).
func openPTY() (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")
	fail := func(err error) (*os.File, *os.File, error) {
		master.Close()
		return nil, nil, err
	}
	if err := ioctl(fd, unix.TIOCPTYGRANT, 0); err != nil {
		return fail(err)
	}
	if err := ioctl(fd, unix.TIOCPTYUNLK, 0); err != nil {
		return fail(err)
	}
	buf := make([]byte, 128)
	if err := ioctl(fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&buf[0]))); err != nil {
		return fail(err)
	}
	name := string(buf[:max(bytes.IndexByte(buf, 0), 0)])
	sfd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	return master, os.NewFile(uintptr(sfd), name), nil
}

func ioctl(fd int, req uint, arg uintptr) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), arg); e != 0 {
		return e
	}
	return nil
}
