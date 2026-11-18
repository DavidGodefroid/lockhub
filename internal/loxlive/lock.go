// Package loxlive is what lox live adds around lox run's engine: the lock
// that keeps lox run and lox live from serving one workspace together,
// its health, and the read-only status socket another Unix user (a
// daemon that raises tickets and waits for them) reads it on.
package loxlive

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Who serves a workspace's decisions.
const (
	// Run is lox run: a human at a terminal. Several may serve together
	// (lox run --no-start next to a lox run), as before.
	Run = "lox run"
	// Live is lox live: alone.
	Live = "lox live"
)

// lockFile is the serve lock, in the workspace's state directory.
const lockFile = "serve.lock"

// HeldError is a workspace the other command already serves.
type HeldError struct{ Msg string }

func (e *HeldError) Error() string { return e.Msg }

// Acquire takes the workspace's serve lock for who (Run: shared; Live:
// exclusive) in its state directory, made 0700 when missing. lox run and
// lox live decide with different rules about who is asked: both at once
// would race for every ticket, so the second to start is refused with a
// *HeldError naming the first. The kernel drops the lock with its
// holder (flock): a lox that died never keeps a workspace. release gives
// it back.
func Acquire(state, who string) (release func(), err error) {
	if err := os.MkdirAll(state, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(state, lockFile)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if who == Live {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		defer f.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		b := make([]byte, 64)
		n, _ := f.ReadAt(b, 0)
		holder := strings.TrimSpace(string(b[:n]))
		if strings.HasPrefix(holder, Live) {
			msg := fmt.Sprintf("%s serves this workspace's decisions (%s): ", Live, holder)
			if who == Run {
				msg += "answer the tickets it leaves to a human with lox approve (or the phone), or stop it first (systemctl stop lox-live) to run lox run"
			} else {
				msg += "one per workspace"
			}
			return nil, &HeldError{Msg: msg}
		}
		return nil, &HeldError{Msg: Run + " serves this workspace's decisions in a terminal: quit it (q q) before lox live starts"}
	}
	if who == Live {
		// Who holds it, for the other's message. A shared holder writes
		// nothing: it is never alone.
		_ = f.Truncate(0)
		_, _ = f.WriteAt([]byte(fmt.Sprintf("%s pid %d\n", Live, os.Getpid())), 0)
	}
	return func() {
		if who == Live {
			_ = f.Truncate(0)
		}
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
