package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/lockconsoles"
	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/vaulttoken"
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
	// --no-start too: the rules it serves come from the workspace.
	if err := family.CheckWorkspace(family.Workspace(abs)); err != nil {
		fmt.Fprintln(stderr, "lox run:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ownState := stateDir(family.Project(family.Workspace(abs)))
	hubc := approve.Dial(*sock)
	if !*noStart {
		// Another workspace's hub on the facade socket: refused before this
		// workspace's hub starts and fails to serve it (#172). A hub too
		// old to say whose it is may be this workspace's, which starting
		// upgrades: the session checks it again.
		if foreignHub(ctx, hubc, *sock, ownState, stderr, "run") {
			return 1
		}
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
	// Without the lock file, no lock's rules are known: the engine's
	// defaults, and a locklog ticket's reads and every lockssh ticket are
	// asked (fail closed).
	var rules func(lock, instance, profile string) loxrun.ProfileRules
	var consoleLocks []lockconsoles.Lock
	var notStarted []loxrun.LockConsole
	var vault *loxrun.VaultCLI
	if c, err := family.Load(abs); err == nil {
		st := stateDir(family.Project(family.Workspace(abs)))
		if v, err := family.AppliedVaultCLI(st); err != nil {
			fmt.Fprintln(stderr, "lox run: vault_token: cli is not served (Vault tokens are asked):", err)
		} else if v != nil {
			vault = vaultCLI(v, c)
		}
		rules = profileRules(family.AppliedLogRules(st, c), family.AppliedSSHRules(st, c))
		// The locks the last lox run did not start: in the header, with
		// their reason; the others are served.
		ns, err := family.ReadNotStarted(st)
		if err != nil {
			fmt.Fprintln(stderr, "lox run:", err)
		}
		for _, name := range c.Instances() {
			if why, skip := ns[name]; skip {
				notStarted = append(notStarted, loxrun.LockConsole{Instance: name, Lock: c.Locks[name].Type, Err: why})
				continue
			}
			locks++
			consoleLocks = append(consoleLocks, lockconsoles.Lock{Instance: name, Type: c.Locks[name].Type})
		}
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
	s := &loxrun.Session{Hub: hubc, Keys: tm.Keys, Resize: tm.Resize, Out: out, Style: st,
		Workspace: tildeHome(family.Workspace(abs)), Locks: locks, LockKeys: lockKeys, Display: os.Getenv("USER"), Mode: mode, Rules: rules, NotStarted: notStarted, Vault: vault}
	// Only this workspace's hub's tickets are shown (#172).
	s.CheckHub = func(ctx context.Context) error { return checkHub(ctx, hubc, *sock, ownState) }
	// A question plays a sound of its own (not lea's), again while it waits.
	snd, warns := loxrun.SoundFromEnv(os.LookupEnv, loxrun.SystemHost(runtime.GOOS))
	for _, w := range warns {
		fmt.Fprintln(stderr, "lox run:", w)
	}
	s.Sound = snd
	// The a key: the hub's audit, as lox audit lists it. The session
	// journal places this session (who, when, its mode switches) in it.
	project := family.Project(family.Workspace(abs))
	state := stateDir(project)
	// The consoles' own questions (policy review, production name,
	// passwords) are asked here and typed at their terminals: lox attach
	// is a fallback only.
	if len(consoleLocks) > 0 {
		b := lockconsoles.Start(ctx, lockconsoles.Exec{Compose: composeArgs(project, state)}, consoleLocks)
		defer b.Close()
		s.Consoles = b
	}
	src := auditSource(auditDirs{data: filepath.Join(state, "hub"), state: state}, "", *keysDir)
	src.Limit = 500
	s.Audit = func() ([]loxrun.Exchange, []loxrun.RunEvent, error) { return loxaudit.Load(ctx, src) }
	journal := func(e loxrun.RunEvent) {
		e.User, e.Workspace = s.Display, s.Workspace
		_ = loxaudit.AppendRun(src.Runs, e) // a place in the listing only: never in the way
	}
	journal(loxrun.RunEvent{Event: loxrun.RunStart, Mode: mode.String()})
	s.Observe = func(e loxrun.Event) {
		switch e.Kind {
		case loxrun.EvMode:
			journal(loxrun.RunEvent{Event: loxrun.RunMode, Mode: e.Mode.String()})
		case loxrun.EvVaultToken:
			journal(loxrun.RunEvent{Event: loxrun.RunVaultToken, Instance: e.Instance, Vault: e.VaultToken})
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

// foreignHub says (on stderr, as lox cmd) when another workspace's hub
// serves the facade socket, before this workspace's hub is started: it
// could not serve the socket (#172).
func foreignHub(ctx context.Context, c family.HubKeyAsker, sock, state string, stderr io.Writer, cmd string) bool {
	var fe *family.ForeignFacadeError
	if err := family.CheckFacadeHub(ctx, c, sock, state); errors.As(err, &fe) {
		fmt.Fprintf(stderr, "lox %s: %v\n", cmd, err)
		return true
	}
	return false
}

// checkHub is lox run's Session.CheckHub: another workspace's hub stops
// the session; no hub answering is the hub unreachable. A hub that
// predates GET /v1/hub (every lockhub release before it) cannot say whose
// it is: it is served, as before #172, since refusing it would stop every
// lox run kept on such a hub (an upgrade refused, --no-upgrade, --pin);
// lox doctor warns about it.
func checkHub(ctx context.Context, c family.HubKeyAsker, sock, state string) error {
	err := family.CheckFacadeHub(ctx, c, sock, state)
	var fe *family.ForeignFacadeError
	switch {
	case errors.As(err, &fe):
		return &loxrun.ForeignHub{Msg: err.Error()}
	case errors.Is(err, family.ErrFacadeOldHub):
		return nil
	}
	return err
}

// profileRules are the engine's per-profile rules from the locks' own
// auto rules as lox run applied them: a locklog ticket's lock's (by
// instance), for the profile its console serves; a lockssh ticket's
// lock's, for its profile. A ticket on another profile, or on an
// instance whose rules lox run could not read (the lock file no longer
// loads, the instance left it), gets no rules here, and the engine asks
// it (fail closed: a locklog lock's reads, every lockssh action). The
// other locks keep the defaults (nil).
func profileRules(logs map[string]*family.LogRules, ssh map[string]map[string]*family.LogRules) func(lock, instance, profile string) loxrun.ProfileRules {
	return func(lock, instance, profile string) loxrun.ProfileRules {
		switch lock {
		case loxrun.LockLocklog:
			r, ok := logs[instance]
			if !ok || r.Profile != profile {
				return nil
			}
			return loxrun.LocklogRules(r.Get)
		case loxrun.LockLockssh:
			r, ok := ssh[instance][profile]
			if !ok || profile == "" || r.Unknown != "" {
				return nil
			}
			return loxrun.SSHRules(r.Get)
		}
		return nil
	}
}

// vaultCLI serves vault_token: cli (lockhub#124) to the locks the last
// confirmed lox run reviewed with it (v) that lockfamily.yaml (c) still
// sets it on: dropping it from the file takes effect without a review.
// The host's token is checked at the reviewed Vault, on the lock's
// reviewed vault_path, with the reviewed CA, before each use.
func vaultCLI(v *family.VaultCLI, c *family.Config) *loxrun.VaultCLI {
	locks := map[string]bool{}
	for n := range v.Locks {
		if l, ok := c.Locks[n]; ok && l.Vault && l.VaultToken == family.VaultTokenCLI {
			locks[n] = true
		}
	}
	if len(locks) == 0 {
		return nil
	}
	return &loxrun.VaultCLI{Address: v.Address, Locks: locks, Token: func(ctx context.Context, instance string) ([]byte, error) {
		path := v.Locks[instance]
		if path == "" {
			return nil, errors.New("the lock's reviewed profile names no vault_path")
		}
		ca, err := v.CA()
		if err != nil {
			return nil, err
		}
		src := &vaulttoken.Source{Address: v.Address, Namespace: v.Namespace, CA: ca}
		return src.Token(ctx, []string{path})
	}}
}

// upgrader is lox run's automatic upgrade: to the releases this lox
// ships with (the hub at lox's own version), each image resolved by
// digest in ghcr.io and verified with cosign as lox add does.
func upgrader(r family.Runner) *family.Upgrade {
	rel := family.DefaultReleases(r)
	return &family.Upgrade{Pins: family.ShippedPins(version), Image: rel.ImageVariant, Tags: rel.Tags, Digest: rel.Digest}
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
