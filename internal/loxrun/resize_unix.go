//go:build !windows

package loxrun

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyResize(c chan os.Signal) { signal.Notify(c, syscall.SIGWINCH) }
