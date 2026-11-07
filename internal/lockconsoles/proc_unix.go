//go:build linux || darwin

package lockconsoles

import (
	"os"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// Size of the console's terminal as lox run's pty gives it.
const (
	ptyRows = 40
	ptyCols = 120
)

// prepare puts the slave in raw mode (no echo: what lox run writes, a
// secret, never comes back on the master) at the pty's size.
func prepare(slave *os.File) error {
	if _, err := term.MakeRaw(int(slave.Fd())); err != nil {
		return err
	}
	return pty.Setsize(slave, &pty.Winsize{Rows: ptyRows, Cols: ptyCols})
}

// ownTerminal runs the attach in a session of its own with the slave as
// its controlling terminal: never lox run's.
func ownTerminal() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}
