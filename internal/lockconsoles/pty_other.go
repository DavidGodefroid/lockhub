//go:build !linux && !darwin

package lockconsoles

import "os"

// openPTY: no pseudo-terminal here; the consoles' questions are answered
// with lox attach.
func openPTY() (master, slave *os.File, err error) {
	return nil, nil, ErrUnsupported
}
