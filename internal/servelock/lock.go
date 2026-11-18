// Package servelock keeps lox live and everything that applies or serves
// a workspace at a terminal (lox run, and lox add, remove, up and init,
// which apply as lox run does) from working on one workspace together.
package servelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Who holds a workspace.
const (
	// Run is a human's lox at a terminal: lox run serving decisions, or
	// any command applying the workspace. Several may hold it together
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

// Acquire takes the workspace's lock for who (Run: shared; Live:
// exclusive) in its state directory, made 0700 when missing. lox run and
// lox live decide with different rules about who is asked, and lox live
// serves exactly what was enrolled: a second one racing for every ticket,
// or a command applying something else under a serving lox live, is
// refused with a *HeldError. The kernel drops the lock with its holder
// (flock): a lox that died never keeps a workspace. release gives it back.
//
// Who holds it is read from the lock itself, never from the file's text:
// a shared request is only ever refused by the exclusive holder (lox
// live), and an exclusive one that a shared probe would pass is refused
// by shared holders (a lox at a terminal). The pid lox live writes there
// is a hint for the message, nothing more.
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
		live := who == Run // only lox live refuses a shared request
		if who == Live {
			// Exclusive refused: by shared holders if a shared lock passes.
			if perr := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); perr == nil {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			} else {
				live = true
			}
		}
		if !live {
			return nil, &HeldError{Msg: "a lox at a terminal holds this workspace (lox run serving its decisions, or a command applying it): quit it (q q in lox run) before lox live starts"}
		}
		hint := ""
		b := make([]byte, 64)
		if n, _ := f.ReadAt(b, 0); n > 0 {
			if pid, ok := strings.CutPrefix(strings.TrimSpace(string(b[:n])), "pid "); ok && pid != "" && strings.Trim(pid, "0123456789") == "" {
				hint = " (pid " + pid + ")"
			}
		}
		msg := Live + " serves this workspace's decisions" + hint + ": "
		if who == Run {
			msg += "answer the tickets it leaves to a human with lox approve (or the phone); to run or apply anything here, stop it first (systemctl stop lox-live), then lox live enrol what you applied"
		} else {
			msg += "one per workspace"
		}
		return nil, &HeldError{Msg: msg}
	}
	if who == Live {
		_ = f.Truncate(0)
		_, _ = f.WriteAt([]byte(fmt.Sprintf("pid %d\n", os.Getpid())), 0)
	}
	return func() {
		if who == Live {
			_ = f.Truncate(0)
		}
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
