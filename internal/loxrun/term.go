package loxrun

import (
	"io"
	"os"
	"os/signal"

	"golang.org/x/term"
)

// Terminal is lox run's terminal: stdin in raw mode (keys arrive one by
// one, Ctrl-C as a key: quitting is lox run's own), stdout drawn as a
// full screen on the alternate buffer when it is a terminal, or written
// as plain lines when it is not (a pipe, a log).
type Terminal struct {
	in, out *os.File
	restore *term.State
	// Keys are the key presses; Resize ticks on SIGWINCH.
	Keys   chan Key
	Resize chan struct{}
	// Full: stdout is a terminal (frames); otherwise plain lines.
	Full bool
	stop func()
}

// OpenTerminal puts in (a terminal) in raw mode and starts reading keys.
func OpenTerminal(in, out *os.File) (*Terminal, error) {
	st, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return nil, err
	}
	t := &Terminal{in: in, out: out, restore: st, Keys: make(chan Key, 64), Resize: make(chan struct{}, 1),
		Full: term.IsTerminal(int(out.Fd()))}
	go t.read()
	sig := make(chan os.Signal, 1)
	t.stop = func() { signal.Stop(sig) }
	notifyResize(sig)
	go func() {
		for range sig {
			select {
			case t.Resize <- struct{}{}:
			default:
			}
		}
	}()
	if t.Full {
		// The alternate screen, without the cursor: the frame is redrawn
		// whole, so a resize never leaves half a line.
		io.WriteString(out, "\x1b[?1049h\x1b[?25l")
	}
	return t, nil
}

func (t *Terminal) read() {
	buf := make([]byte, 256)
	for {
		n, err := t.in.Read(buf)
		if n > 0 {
			for _, k := range ParseKeys(buf[:n]) {
				t.Keys <- k
			}
		}
		if err != nil {
			close(t.Keys)
			return
		}
	}
}

// Size is the terminal's size (80x24 when it cannot tell).
func (t *Terminal) Size() (int, int) {
	w, h, err := term.GetSize(int(t.out.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// Close leaves the alternate screen and restores the terminal.
func (t *Terminal) Close() {
	t.stop()
	if t.Full {
		io.WriteString(t.out, "\x1b[?25h\x1b[?1049l")
	}
	term.Restore(int(t.in.Fd()), t.restore)
}
