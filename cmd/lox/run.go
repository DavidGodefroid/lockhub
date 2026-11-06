package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// runCmd is lox run: in its own terminal, outside any agent harness, it
// starts (or reuses) the hub and the workspace's locks as lox up did,
// then serves the hub's decisions in the foreground: every ticket and
// decision shown live, masked; the auto mode's rules decide what they
// allow; the human answers the rest. Quitting stops serving decisions:
// tickets wait for the next lox run (fail closed).
func runCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	manual := fs.Bool("manual", false, "start in manual mode: every ticket is asked (Shift+Tab switches)")
	theme := fs.String("theme", "", "the terminal's background: light or dark (default: COLORFGBG, else dark)")
	noStart := fs.Bool("no-start", false, "serve decisions only: the hub and the locks already run (started by another lox run)")
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	keysDir := fs.String("facade-keys", family.FacadeKeysDir(stateHome()), "the pinned lock keys, as lox run wrote them")
	verbose := fs.Bool("v", false, "show cosign's and docker's own output while starting (default: only when a step fails)")
	review := fs.Bool("review", false, "show everything, the profiles line by line, and ask before starting")
	pin := fs.String("pin", "", "the hub image by digest (sha256:…, or the whole ghcr.io/davidgodefroid/lockhub@sha256:… reference)")
	noUpgrade := fs.Bool("no-upgrade", false, "keep the pinned images: do not upgrade those older than this lox's releases")
	var rotate stringsFlag
	fs.Var(&rotate, "rotate", "replace a key before starting: hub, a lock instance, or all (repeatable, or comma-separated)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox run: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 2
	}
	if *theme != "" && *theme != "light" && *theme != "dark" {
		fmt.Fprintln(stderr, "lox run: --theme is light or dark")
		return 2
	}
	// Decisions are taken by a human at a terminal, never piped.
	if !term.IsTerminal(int(stdin.Fd())) {
		fmt.Fprintln(stderr, "lox run: answers are typed at a terminal; stdin is not one (run it in a terminal of its own, outside the agent)")
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox run:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !*noStart {
		r := family.QuietExec{Verbose: *verbose, Stderr: stderr}
		u := &family.Up{File: abs, State: stateDir(family.Project(family.Workspace(abs))), Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
			User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: r, In: bufio.NewReader(stdin), Out: stdout,
			Pin: *pin, Rotate: rotate, Review: *review}
		if !*noUpgrade {
			u.Upgrade = upgrader(r)
		}
		if err := u.Do(ctx); err != nil {
			return failed(ctx, stderr, "run", err)
		}
	}
	locks := 0
	if c, err := family.Load(abs); err == nil {
		locks = len(c.Locks)
	}
	lockKeys, err := keys.LoadLocks(filepath.Join(*keysDir, family.LockKeysFile))
	if err != nil {
		lockKeys = map[string]ed25519.PublicKey{}
		fmt.Fprintln(stderr, "lox run: no pinned lock keys in", *keysDir, "(", err, "): no ticket can be checked, so every ticket is asked")
	}
	out, _ := stdout.(*os.File)
	if out == nil {
		out = os.Stdout
	}
	tm, err := loxrun.OpenTerminal(stdin, out)
	if err != nil {
		fmt.Fprintln(stderr, "lox run:", err)
		return 1
	}
	st := loxrun.DetectStyle(os.LookupEnv, *theme)
	mode := loxrun.Auto
	if *manual {
		mode = loxrun.Manual
	}
	s := &loxrun.Session{Hub: approve.Dial(*sock), Keys: tm.Keys, Resize: tm.Resize, Out: out, Style: st,
		Workspace: tildeHome(family.Workspace(abs)), Locks: locks, LockKeys: lockKeys, Display: os.Getenv("USER"), Mode: mode}
	// The a key: the hub's audit, as lox audit lists it. The session
	// journal places this session (who, when, its mode switches) in it.
	state := stateDir(family.Project(family.Workspace(abs)))
	src := auditSource(auditDirs{data: filepath.Join(state, "hub"), state: state}, "", *keysDir)
	src.Limit = 500
	s.Audit = func() ([]loxrun.Exchange, []loxrun.RunEvent, error) { return loxaudit.Load(ctx, src) }
	journal := func(e loxrun.RunEvent) {
		e.User, e.Workspace = s.Display, s.Workspace
		_ = loxaudit.AppendRun(src.Runs, e) // a place in the listing only: never in the way
	}
	journal(loxrun.RunEvent{Event: loxrun.RunStart, Mode: mode.String()})
	s.Observe = func(e loxrun.Event) {
		if e.Kind == loxrun.EvMode {
			journal(loxrun.RunEvent{Event: loxrun.RunMode, Mode: e.Mode.String()})
		}
	}
	if tm.Full {
		s.Size = tm.Size
	} else {
		s.Style.Color = false // a pipe or a log: no escapes
	}
	err = s.Run(ctx)
	journal(loxrun.RunEvent{Event: loxrun.RunStop})
	tm.Close()
	if err != nil {
		fmt.Fprintln(stderr, "lox run:", err)
		return 1
	}
	fmt.Fprintln(stdout, "lox run stopped: no decision is served any more; tickets wait at the hub for the next lox run (fail closed), and the locks close their connections once idle")
	return 0
}

// upgrader is lox run's automatic upgrade: to the releases this lox
// ships with (the hub at lox's own version), each image resolved by
// digest in ghcr.io and verified with cosign as lox add does.
func upgrader(r family.Runner) *family.Upgrade {
	rel := family.DefaultReleases(r)
	return &family.Upgrade{Pins: family.ShippedPins(version), Image: rel.ImageVariant}
}

// tildeHome shows a path under the home directory as ~/….
func tildeHome(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if rel, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
		return "~/" + rel
	}
	return p
}
