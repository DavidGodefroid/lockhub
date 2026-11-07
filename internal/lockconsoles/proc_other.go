//go:build !linux && !darwin

package lockconsoles

import (
	"os"
	"syscall"
)

func prepare(*os.File) error { return ErrUnsupported }

func ownTerminal() *syscall.SysProcAttr { return nil }
