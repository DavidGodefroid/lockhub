package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxadd"
)

const removeUsage = "usage: lox remove NAME [--purge]"

// removeCmd is lox remove: the lock taken out of lockfamily.yaml, then lox
// up with the short review of that lock (its console stops). A decline,
// a failure or a Ctrl-C puts lockfamily.yaml back.
func removeCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	purge := fs.Bool("purge", false, "also take the lock's profile out of its config.toml, once the lock is removed")
	verbose := fs.Bool("v", false, "show cosign's and docker's own output (default: only when a step fails)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, removeUsage)
		return 2
	}
	if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stderr, "lox remove: the change is confirmed at a terminal; stdin is not one")
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox remove:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	in := bufio.NewReader(stdin)
	r := &removal{File: abs, Name: pos[0], Purge: *purge, Out: stdout, Err: stderr,
		Up: func(ctx context.Context, focus string) error {
			u := &family.Up{File: abs, State: stateDir(family.Project(family.Workspace(abs))), Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
				User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: family.QuietExec{Verbose: *verbose, Stderr: stderr},
				In: in, Out: stdout, Focus: focus}
			return u.Do(ctx)
		}}
	return r.run(ctx)
}

// removal is one lox remove: File is the lockfamily.yaml, Up lox up with
// the short review of the focus lock.
type removal struct {
	File, Name string
	Purge      bool
	Out, Err   io.Writer
	Up         func(ctx context.Context, focus string) error
}

func (r *removal) run(ctx context.Context) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(r.Err, "lox remove: "+format+"\n", a...)
		return 1
	}
	c, err := family.Load(r.File)
	if err != nil {
		return fail("%v", err)
	}
	l, ok := c.Locks[r.Name]
	if !ok {
		return fail("no lock %q in %s", r.Name, r.File)
	}
	dir := filepath.Join(family.Workspace(r.File), "."+l.Type)
	cfg := "." + l.Type + "/config.toml"
	effective := func(x family.Lock) string {
		if x.Profile == "" && x.Type == "lockfile" {
			return "default"
		}
		return x.Profile
	}
	profile := effective(l)
	if r.Purge {
		// Refused before anything is changed.
		if profile == "" {
			return fail("--purge: %s names no profile in %s: its profile is the only one of %s, remove it by hand", r.Name, filepath.Base(r.File), cfg)
		}
		for _, n := range c.Instances() {
			if o := c.Locks[n]; n != r.Name && o.Type == l.Type && effective(o) == profile {
				return fail("--purge: lock %s serves profile %s of %s too", n, profile, cfg)
			}
		}
	}
	snap, err := loxadd.TakeSnapshot(r.File)
	if err != nil {
		return fail("%v", err)
	}
	if err := family.RemoveLock(r.File, r.Name); err != nil {
		return fail("%v", err)
	}
	if r.Purge {
		fmt.Fprintf(r.Out, "remove lock %s (%s): its console stops; its profile %s is removed from %s after\n", r.Name, l.Type, profile, cfg)
	} else {
		fmt.Fprintf(r.Out, "remove lock %s (%s): its console stops; its profile stays in %s unless --purge\n", r.Name, l.Type, cfg)
	}
	if err := r.Up(ctx, r.Name); err != nil {
		// The interrupted or declined change is undone; plain file work,
		// which an interrupt cannot cut short.
		if rerr := snap.Restore(); rerr != nil {
			return fail("lox up did not apply it (%v), and %s could not be restored (%v): declare lock %s again by hand", err, filepath.Base(r.File), rerr, r.Name)
		}
		switch {
		case ctx.Err() != nil || errors.Is(err, context.Canceled):
			fmt.Fprintf(r.Err, "lox remove: interrupted: lock %s stays, %s is as before\n", r.Name, filepath.Base(r.File))
			return exitInterrupted
		case errors.Is(err, family.ErrNotConfirmed):
			return fail("not confirmed: lock %s stays, %s is as before", r.Name, filepath.Base(r.File))
		}
		return fail("lox up failed: %v: lock %s stays, %s is as before", err, r.Name, filepath.Base(r.File))
	}
	fmt.Fprintf(r.Out, "lock %s removed\n", r.Name)
	if !r.Purge {
		return 0
	}
	if err := family.RemoveProfile(dir, profile); err != nil {
		return fail("lock %s is removed, but its profile was not: %v", r.Name, err)
	}
	fmt.Fprintf(r.Out, "profile %s removed from %s\n", profile, cfg)
	return 0
}
