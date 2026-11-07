package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

// detachLine says how to leave a console, the last line lox prints before
// the console's screen (#144).
const detachLine = "Ctrl-P Ctrl-Q detaches (the console keeps running) · Ctrl-C stops it · closing this terminal only detaches"

// detachKeys are the keys lox attach detaches with (docker's default,
// named explicitly on the attach): Ctrl-P Ctrl-Q.
const detachKeys = "\x10\x11"

// serveStep is how often lox checks, while attached, whether the console
// serves.
var serveStep = 500 * time.Millisecond

// readyGrace is how long lox stays attached once the console serves, so
// that its Ready box reaches the screen before lox detaches.
var readyGrace = time.Second

// drainWait is how long lox waits for the console's last output once the
// attach has ended.
const drainWait = time.Second

// errNoPty: lox cannot put the attach on a pseudo-terminal of its own;
// nothing ran.
var errNoPty = errors.New("no pseudo-terminal")

// attachUntilServes runs c (docker compose attach) on a pseudo-terminal
// lox owns, relayed to the user's terminal (in, out, in raw mode meanwhile,
// as docker attach puts it): what the user types goes to the console, what
// the console writes comes back through shown. Once serves says the console
// serves, lox types the detach keys for the user: the attach ends as on
// Ctrl-P Ctrl-Q and the console keeps running (killing the attach client
// instead could reach the console). served says lox detached; errNoPty says
// nothing ran.
func attachUntilServes(c *exec.Cmd, in, out *os.File, shown io.Writer, serves func() bool) (served bool, err error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return false, errNoPty
	}
	defer ptmx.Close()
	defer tty.Close()
	keys, err := cancelreader.NewReader(in)
	if err != nil {
		return false, errNoPty
	}
	defer keys.Close()
	raw, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return false, errNoPty
	}
	defer func() { _ = term.Restore(int(in.Fd()), raw) }()
	_ = pty.InheritSize(out, ptmx)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)

	c.Stdin, c.Stdout, c.Stderr = tty, tty, tty
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(shown, ptmx)
		close(copied)
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ptmx, keys)
	}()
	done := make(chan struct{})
	var detached atomic.Bool
	go func() {
		defer wg.Done()
		t := time.NewTicker(serveStep)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-winch:
				_ = pty.InheritSize(out, ptmx)
			case <-t.C:
				if serves() {
					select {
					case <-done:
						return
					case <-time.After(readyGrace):
					}
					detached.Store(true)
					_, _ = io.WriteString(ptmx, detachKeys)
					return
				}
			}
		}
	}()
	err = c.Run()
	close(done)
	keys.Cancel()
	wg.Wait()
	// The console's last words are still in the pseudo-terminal: lox
	// shows them before it closes it. Closing its end ends the copy.
	_ = tty.Close()
	select {
	case <-copied:
	case <-time.After(drainWait):
	}
	return detached.Load(), err
}

// consoleListens is whether the console of lock name (compose, the compose
// command lox up applied) listens on a unix socket of tool, from the
// kernel's table of its network namespace: a socket file in the volume may
// be a dead console's.
func consoleListens(compose []string, name, tool string) bool {
	out, err := exec.Command("docker", slices.Concat(compose, []string{"exec", "-T", "lock-" + name, "cat", "/proc/net/unix"})...).Output()
	return err == nil && unixListening(string(out), tool)
}

// unixListening is whether /proc/net/unix (table) holds a listening socket
// in /run/<tool>/: the flag __SO_ACCEPTCON (00010000), state 01.
func unixListening(table, tool string) bool {
	if tool == "" {
		return false
	}
	for _, ln := range strings.Split(table, "\n") {
		f := strings.Fields(ln)
		if len(f) == 8 && f[3] == "00010000" && f[5] == "01" && strings.HasPrefix(f[7], "/run/"+tool+"/") {
			return true
		}
	}
	return false
}

// isTerminal is whether f is a terminal.
func isTerminal(f *os.File) bool { return f != nil && term.IsTerminal(int(f.Fd())) }
