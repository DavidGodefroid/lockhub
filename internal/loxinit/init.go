// Package loxinit is `lox init`: the hub of the Lock Family started in a
// project, alone, without a question. It checks the prerequisites, shows
// the data sources the project's files name as hints (read only, never a
// secret; each lock is added with lox add), writes a lockfamily.yaml with
// the hub alone when there is none, and runs lox up.
package loxinit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// EndLine is lox init's last line.
const EndLine = "Ready. Run `lea` (or `claude` + `lox approve`). Add a source: `lox add locksql|lockmq|lockfile|lockhttp`."

// Declared is a lock lockfamily.yaml declares already.
type Declared struct {
	Instance, Lock, Profile string
}

// Init is one `lox init`.
type Init struct {
	// Root is the project (the workspace whose .lockfamily/ holds
	// lockfamily.yaml).
	Root string
	Env  Env
	Out  io.Writer
	// Terminal: stdin is a terminal (lox up's review of declared locks
	// needs one).
	Terminal bool
	// Review is lox init --review: lox up shows everything and asks, so
	// a re-run never skips it.
	Review bool
	// HubImageGiven: --hub-image was passed.
	HubImageGiven bool

	// Declared reads the locks lockfamily.yaml declares (none when it
	// does not exist).
	Declared func() ([]Declared, error)
	// Hub writes lockfamily.yaml with the hub alone when it does not
	// exist; created says it did.
	Hub func(ctx context.Context) (created bool, err error)
	// Up is lox up (whose first run with no lock asks nothing).
	Up func(ctx context.Context) error
	// Running reports the workspace's hub running.
	Running func(ctx context.Context) bool
	// Unchanged reports the configuration's fingerprint equal to the
	// last applied one.
	Unchanged func(ctx context.Context) bool
	// Applied is the number of locks the last lox up applied.
	Applied func() (int, error)
}

func (in *Init) say(format string, a ...any) { fmt.Fprintf(in.Out, format+"\n", a...) }

// Do runs lox init. It asks nothing.
func (in *Init) Do(ctx context.Context) error {
	pre := CheckPrereqs(ctx, in.Env)
	in.say("lox init: %s", in.Root)
	in.say("")
	RenderPrereqs(in.Out, pre, in.Env.GOOS)
	if !pre.Ready() {
		return errors.New("prerequisites missing (above): nothing done")
	}
	sources, warnings := Detect(in.Root)
	RenderHints(in.Out, sources)
	for _, w := range warnings {
		in.say("  warning: %s", w)
	}
	created, err := in.Hub(ctx)
	if err != nil {
		return err
	}
	if created {
		in.say("")
		in.say("lockfamily.yaml written: the hub alone")
	}
	if !created && in.HubImageGiven {
		in.say("--hub-image: lockfamily.yaml exists, its hub image is kept (lox up --pin to change it)")
	}
	// Only a hub that already runs, from a file that was already there,
	// can be left alone; --review always runs lox up.
	maybeNoop := !created && !in.Review && in.Running(ctx)
	decl, err := in.Declared()
	if err != nil {
		return err
	}
	if len(decl) > 0 {
		names := make([]string, len(decl))
		for i, d := range decl {
			names[i] = d.Instance + " (" + d.Lock + ")"
		}
		in.say("")
		in.say("lockfamily.yaml declares locks, kept as they are: %s", strings.Join(names, ", "))
		if !in.Terminal {
			in.say("lockfamily.yaml declares locks: run lox up at a terminal to review and start them")
			in.end()
			return nil
		}
	} else if !in.Terminal {
		n, err := in.Applied()
		if err != nil {
			return err
		}
		if n > 0 {
			in.say("")
			in.say("lox up removes the locks applied before: run it at a terminal to review")
			in.end()
			return nil
		}
	}
	// The terminal guards come first: the check is lox up's own and may
	// start docker and cosign.
	if maybeNoop && in.Unchanged(ctx) {
		in.end()
		return nil
	}
	in.say("")
	if err := in.Up(ctx); err != nil {
		return err
	}
	in.end()
	return nil
}

func (in *Init) end() {
	in.say("")
	in.say("%s", EndLine)
}
