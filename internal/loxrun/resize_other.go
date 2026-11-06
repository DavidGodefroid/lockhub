//go:build windows

package loxrun

import "os"

// notifyResize: no SIGWINCH; the frame follows the size at each redraw
// (every second).
func notifyResize(chan os.Signal) {}
