package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/lockconsoles"
	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxlive"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// lox live is lox run's headless twin, for a host nobody sits at (a
// systemd service, no terminal, back by itself after a reboot): it
// brings up the stack a human applied and enrolled (lox live enrol),
// then serves the decisions the written rules take, under facade live.
// It answers no review and no question but a console's Vault token
// question (vault_token: cli), approves nothing a rule does not name,
// and leaves every other ticket pending for a human's facade. When it
// stops, nothing is decided (fail closed). docs/lox-live.md.

// defaultStatusSocket is lox live's status socket.
func defaultStatusSocket() string { return filepath.Join(runtimeDir(), "lockhub", "live-status.sock") }

// Timings of lox live's loop.
var (
	// liveEnrolPoll is how often the enrolment file is looked at for a
	// change (lox live enrol was run), liveRecheck how often a workspace
	// that needs an enrolment is checked again anyway.
	liveEnrolPoll = 15 * time.Second
	liveRecheck   = 10 * time.Minute
	// A start that failed (the engine is not up yet after a boot) is
	// tried again after liveRetry, doubled up to liveRetryMax.
	liveRetry    = 15 * time.Second
	liveRetryMax = 2 * time.Minute
)

func liveCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "enrol", "enroll":
			return liveEnrolCmd(args[1:], stdin, stdout, stderr)
		case "status":
			return liveStatusCmd(args[1:], stdout, stderr)
		}
	}
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml)")
	statusSock := fs.String("status-socket", defaultStatusSocket(), "the read-only status socket (health, ticket states) for another Unix user")
	statusGroup := fs.String("status-group", "", "the group that may open the status socket (0660; default: your own group)")
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	keysDir := fs.String("facade-keys", family.FacadeKeysDir(stateHome()), "the pinned lock keys, as lox run wrote them")
	verbose := fs.Bool("v", false, "show docker's own output while starting (default: only when a step fails)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox live: unexpected arguments:", strings.Join(fs.Args(), " "), "(lox live, lox live enrol, lox live status)")
		return 2
	}
	mf, err := family.LoadManaged(context.Background())
	if err != nil {
		return failed(context.Background(), stderr, "live", err)
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox live:", err)
		return 1
	}
	if err := family.CheckWorkspace(family.Workspace(abs)); err != nil {
		fmt.Fprintln(stderr, "lox live:", err)
		return 1
	}
	project := family.Project(family.Workspace(abs))
	state := stateDir(project)
	// lox run and lox live never serve one workspace together.
	release, err := loxlive.Acquire(state, loxlive.Live)
	if err != nil {
		fmt.Fprintln(stderr, "lox live:", err)
		return 1
	}
	defer release()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	out := &lineWriter{w: stdout}
	l := &live{abs: abs, state: state, project: project, sock: *sock, keysDir: *keysDir, out: out, stderr: stderr,
		tracker: loxlive.NewTracker(), hub: approve.Dial(*sock), managed: mf, reload: hup}
	l.start = func(ctx context.Context, e *family.Enrolment) error {
		u := &family.Up{File: abs, State: state, Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
			User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: family.QuietExec{Verbose: *verbose, Stderr: stderr},
			Out: prefixWriter{out, "lox live: start: "}, Enrolled: e}
		return u.Do(ctx)
	}
	l.consoles = func(ctx context.Context, locks []lockconsoles.Lock) (loxrun.Consoles, func()) {
		b := lockconsoles.Start(ctx, lockconsoles.Exec{Compose: composeArgs(project, state)}, locks)
		return b, b.Close
	}
	if mf != nil {
		l.logf("%s", mf.File.Describe())
	}

	// The status socket answers from now on, whatever state lox live is in.
	st := &loxlive.Status{Tracker: l.tracker, Hub: l.hub, Log: l.logf, LockKeys: func() map[string]ed25519.PublicKey {
		lk, _ := keys.LoadLocks(filepath.Join(*keysDir, family.LockKeysFile))
		return lk
	}}
	ln, err := loxlive.Listen(*statusSock, *statusGroup)
	if err != nil {
		fmt.Fprintln(stderr, "lox live: status socket:", err)
		return 1
	}
	if fi, err := os.Stat(filepath.Dir(*statusSock)); err == nil && fi.Mode().Perm()&0o070 == 0 && *statusGroup != "" {
		l.logf("note: the directory of the status socket (%s) is closed to group %s: give --status-socket a directory that group can enter (docs/lox-live.md)", filepath.Dir(*statusSock), *statusGroup)
	}
	srv := st.Server()
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		_ = srv.Close()
		_ = os.Remove(*statusSock)
	}()
	l.logf("status socket %s (read-only: health, ticket states, withdrawal of %s tickets)", *statusSock, loxlive.AgentPrefix)

	l.loop(ctx)
	l.tracker.Stopped("lox live stopped")
	l.logf("stopped: no decision is served any more; tickets wait at the hub (fail closed)")
	return 0
}

// lineWriter serializes whole writes to w (the session, the start and
// the status socket log lines to one stdout).
type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lineWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// prefixWriter writes each line given to it with a prefix, and nothing
// for an empty one (the start's output, as journal lines).
type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p prefixWriter) Write(b []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		// The start never asks here; a prompt it printed has no newline.
		if s := strings.TrimSpace(line); s != "" {
			fmt.Fprintf(p.w, "%s%s\n", p.prefix, s)
		}
	}
	return len(b), nil
}

// live is one lox live.
type live struct {
	abs, state, project string
	sock, keysDir       string
	out                 io.Writer
	stderr              io.Writer
	tracker             *loxlive.Tracker
	hub                 *approve.Client
	managed             *family.Managed
	// reload ticks on SIGHUP: check and start again.
	reload <-chan os.Signal
	// start brings the enrolled stack up (family.Up with Enrolled);
	// consoles follows the locks' consoles until its stop is called.
	start    func(ctx context.Context, e *family.Enrolment) error
	consoles func(ctx context.Context, locks []lockconsoles.Lock) (loxrun.Consoles, func())
	// lastWhy is the last state logged: said once, not at every check.
	lastWhy string
}

func (l *live) logf(format string, args ...any) {
	fmt.Fprintf(l.out, "lox live: "+format+"\n", args...)
}

// say logs why once per change.
func (l *live) say(why string) {
	if why != l.lastWhy {
		l.lastWhy = why
		l.logf("%s", why)
	}
}

// enrolStamp tells one enrolment file from the next.
func enrolStamp(state string) string {
	fi, err := os.Stat(filepath.Join(state, family.EnrolmentFile))
	if err != nil {
		return "none"
	}
	return fmt.Sprintf("%d/%d", fi.ModTime().UnixNano(), fi.Size())
}

// loop checks, starts and serves until ctx ends: a workspace that needs
// an enrolment keeps lox live running (the status socket answers) and
// is checked again when the enrolment changes, on SIGHUP, and now and
// then; a start that failed is tried again; a session that ended (the
// enrolment changed, SIGHUP) starts over from the check.
func (l *live) loop(ctx context.Context) {
	retry := liveRetry
	for ctx.Err() == nil {
		stamp := enrolStamp(l.state)
		wait, err := l.cycle(ctx, stamp)
		if ctx.Err() != nil {
			return
		}
		var ne *family.NeedsEnrolmentError
		switch {
		case err == nil:
			retry = liveRetry
			continue // the session ended to start over
		case errors.As(err, &ne):
			retry = liveRetry
			wait = liveRecheck
		default:
			wait = retry
			retry = min(2*retry, liveRetryMax)
		}
		l.waitChange(ctx, stamp, wait)
	}
}

// waitChange waits for the enrolment to change, a SIGHUP, max or ctx.
func (l *live) waitChange(ctx context.Context, stamp string, max time.Duration) {
	deadline := time.NewTimer(max)
	defer deadline.Stop()
	poll := time.NewTicker(liveEnrolPoll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-l.reload:
			l.logf("SIGHUP: checking again")
			return
		case <-poll.C:
			if enrolStamp(l.state) != stamp {
				l.logf("the enrolment changed: checking again")
				return
			}
		}
	}
}

// instances are the workspace's lock instances, for the health (nil
// when lockfamily.yaml does not load).
func (l *live) instances() []string {
	c, err := family.Load(l.abs)
	if err != nil {
		return nil
	}
	return c.Instances()
}

// cycle is one check, start and service. It returns nil when the
// session ended to start over, a *family.NeedsEnrolmentError when
// nothing was started for want of an enrolment, any other error when
// the start or the service failed.
func (l *live) cycle(ctx context.Context, stamp string) (time.Duration, error) {
	insts := l.instances()
	fail := func(err error) (time.Duration, error) {
		var ne *family.NeedsEnrolmentError
		if errors.As(err, &ne) {
			l.tracker.NeedsEnrolment(insts, ne.Why)
			l.say("needs enrolment, nothing started: " + ne.Why + " (lox run at a terminal, then lox live enrol)")
		} else {
			l.tracker.Failed(insts, err.Error())
			l.say("not started: " + err.Error())
		}
		return 0, err
	}
	enrol, err := family.ReadEnrolment(l.state)
	if err != nil {
		return fail(err)
	}
	if enrol == nil {
		return fail(&family.NeedsEnrolmentError{Why: "this workspace is not enrolled for lox live"})
	}
	var fe *family.ForeignFacadeError
	if err := family.CheckFacadeHub(ctx, l.hub, l.sock, l.state); errors.As(err, &fe) {
		return fail(err)
	}
	if err := l.start(ctx, enrol); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return fail(err)
	}
	l.lastWhy = ""
	err = l.serve(ctx, stamp)
	if ctx.Err() != nil {
		return 0, nil
	}
	if err != nil {
		return fail(err)
	}
	return 0, nil
}

// serve runs the unattended session on the stack just started, until
// ctx ends, the enrolment changes or a SIGHUP comes (nil: start over).
func (l *live) serve(ctx context.Context, stamp string) error {
	c, err := family.Load(l.abs)
	if err != nil {
		return err
	}
	l.tracker.Started(c.Instances())
	var vault *loxrun.VaultCLI
	if v, err := family.AppliedVaultCLI(l.state); err != nil {
		l.logf("vault_token: cli is not served: %v", err)
	} else if v != nil {
		vault = vaultCLI(v, c)
	}
	rules := profileRules(family.AppliedLogRules(l.state, c), family.AppliedProfileRules(l.state, c))
	ns, err := family.ReadNotStarted(l.state)
	if err != nil {
		l.logf("%v", err)
	}
	facts, err := family.AppliedFacts(l.state)
	if err != nil {
		l.logf("%v", err)
	}
	var consoleLocks []lockconsoles.Lock
	var notStarted []loxrun.LockConsole
	for _, name := range c.Instances() {
		if why, skip := ns[name]; skip {
			notStarted = append(notStarted, loxrun.LockConsole{Instance: name, Lock: c.Locks[name].Type, Err: why})
			l.tracker.Fixed(name, loxlive.Down, "not started: "+why)
			continue
		}
		consoleLocks = append(consoleLocks, lockconsoles.Lock{Instance: name, Type: c.Locks[name].Type})
		// All of lox live's secrets come from Vault: a profile whose
		// credentials a human types is not served, and says so, rather
		// than serve until its first connection asks for a password.
		if f := facts[name]; f.Credentials == "ask" || f.Odd["credentials"] != "" {
			l.tracker.Fixed(name, loxlive.MissingSecret, "its profile's credentials are typed by a human (credentials = \"ask\"): lox live takes them from Vault only")
			l.logf("lock %s: missing_secret: its profile's credentials are typed by a human; lox live takes them from Vault only", name)
		}
	}
	lockKeys, err := keys.LoadLocks(filepath.Join(l.keysDir, family.LockKeysFile))
	if err != nil {
		lockKeys = map[string]ed25519.PublicKey{}
		l.logf("no pinned lock keys in %s (%v): no ticket can be checked, so none is decided", l.keysDir, err)
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &loxrun.Session{Hub: l.hub, Out: l.out, Style: loxrun.Style{}, Workspace: tildeHome(family.Workspace(l.abs)), Locks: len(consoleLocks),
		LockKeys: lockKeys, Display: "lox live", Mode: loxrun.Auto, Rules: rules, NotStarted: notStarted, Vault: vault,
		Caps: managedCaps(l.managed), Unattended: true, Facade: route.Live}
	// Only this workspace's hub, and only one that takes facade live.
	s.CheckHub = func(ctx context.Context) error {
		if err := checkHub(ctx, l.hub, l.sock, l.state); err != nil {
			return err
		}
		info, err := l.hub.HubInfo(ctx)
		if err != nil || !info.Live {
			return errors.New("the hub's image predates lox live (it takes no decision of facade live): upgrade it with lox run, then lox live enrol")
		}
		return nil
	}
	if len(consoleLocks) > 0 {
		b, stop := l.consoles(sctx, consoleLocks)
		defer stop()
		s.Consoles = b
	}
	src := auditSource(auditDirs{data: filepath.Join(l.state, "hub"), state: l.state}, "", l.keysDir)
	journal := func(e loxrun.RunEvent) {
		e.User, e.Workspace = "lox live", s.Workspace
		_ = loxaudit.AppendRun(src.Runs, e) // a place in the listing only
	}
	journal(loxrun.RunEvent{Event: loxrun.RunStart, Mode: "LIVE"})
	defer journal(loxrun.RunEvent{Event: loxrun.RunStop})
	s.Observe = func(e loxrun.Event) {
		switch e.Kind {
		case loxrun.EvHub:
			l.tracker.Hub(e.Err)
		case loxrun.EvConsole:
			if e.Console != nil {
				l.tracker.Console(e.Instance, *e.Console)
				if e.Console.Blocked != "" {
					l.logf("lock %s: %s: %s", e.Instance, e.Console.Blocked, e.Console.Detail)
				}
			}
		case loxrun.EvVaultToken:
			journal(loxrun.RunEvent{Event: loxrun.RunVaultToken, Instance: e.Instance, Vault: e.VaultToken})
		}
	}
	// Start over when the enrolment changes or on SIGHUP.
	watched := make(chan struct{})
	defer func() { cancel(); <-watched }()
	go func() {
		defer close(watched)
		poll := time.NewTicker(liveEnrolPoll)
		defer poll.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-l.reload:
				l.logf("SIGHUP: starting over from the enrolment check")
				cancel()
				return
			case <-poll.C:
				if enrolStamp(l.state) != stamp {
					l.logf("the enrolment changed: starting over from the enrolment check")
					cancel()
					return
				}
			}
		}
	}()
	return s.Run(sctx)
}

// liveStatusCmd is lox live status: the health lox live serves on its
// status socket. Exit 0 when it serves, 1 otherwise.
func liveStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("live status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("status-socket", defaultStatusSocket(), "lox live's status socket")
	asJSON := fs.Bool("json", false, "the health as JSON, as GET /v1/health answers it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox live status: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 2
	}
	h := liveHealth(*sock)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(h)
	} else {
		word := "not serving"
		if h.Serving {
			word = "serving"
		}
		fmt.Fprintf(stdout, "lox live: %s: %s\n", word, h.Detail)
		names := make([]string, 0, len(h.Locks))
		for n := range h.Locks {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			fmt.Fprintf(stdout, "  lock %-20s %s\n", n, h.Locks[n])
		}
		fmt.Fprintf(stdout, "  %d ticket(s) pending at the hub\n", h.Pending)
	}
	if h.Serving {
		return 0
	}
	return 1
}

// liveHealth asks the lox live on sock for its health; one that does not
// answer is not serving.
func liveHealth(sock string) loxlive.Health {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	down := func(why string) loxlive.Health {
		return loxlive.Health{Locks: map[string]string{}, Detail: "lox live does not answer on " + sock + ": " + why}
	}
	resp, err := c.Get("http://lox-live/v1/health")
	if err != nil {
		return down(approve.Explain(err))
	}
	defer resp.Body.Close()
	var h loxlive.Health
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&h) != nil {
		return down("not a health answer (" + resp.Status + ")")
	}
	if h.Locks == nil {
		h.Locks = map[string]string{}
	}
	return h
}

// liveEnrolCmd is lox live enrol: at a terminal, after a lox run that
// reviewed and applied everything, a human enrols what is applied for
// unattended service.
func liveEnrolCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("live enrol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml)")
	verbose := fs.Bool("v", false, "show cosign's and docker's own output (default: only when a step fails)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox live enrol: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 2
	}
	// An enrolment is a human's, typed at a terminal, never piped.
	if !term.IsTerminal(int(stdin.Fd())) {
		fmt.Fprintln(stderr, "lox live enrol: an enrolment is confirmed at a terminal; stdin is not one")
		return 1
	}
	if _, err := family.LoadManaged(context.Background()); err != nil {
		return failed(context.Background(), stderr, "live enrol", err)
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox live enrol:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state := stateDir(family.Project(family.Workspace(abs)))
	probe := func(ctx context.Context) (*family.Reviewed, error) {
		fmt.Fprintln(stdout, "checking what is applied, and every pinned image's signature (cosign)…")
		u := &family.Up{File: abs, State: state, Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
			User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: family.QuietExec{Verbose: *verbose, Stderr: stderr},
			In: bufio.NewReader(strings.NewReader("")), Out: io.Discard, Probe: true}
		if err := u.Do(ctx); err != nil {
			return nil, err
		}
		if !u.Same {
			return nil, nil
		}
		return u.Reviewed, nil
	}
	facts, _ := family.AppliedFacts(state)
	code, err := liveEnrol(ctx, bufio.NewReader(stdin), stdout, probe, state, tildeHome(family.Workspace(abs)), os.Getenv("USER"), facts, time.Now())
	if err != nil {
		return failed(ctx, stderr, "live enrol", err)
	}
	return code
}

// liveEnrol enrols what probe finds applied and unchanged, once the
// human typed each production profile's name and said yes. Anything
// else enrols nothing.
func liveEnrol(ctx context.Context, in *bufio.Reader, out io.Writer, probe func(context.Context) (*family.Reviewed, error),
	state, workspace, by string, facts map[string]family.Facts, now time.Time) (int, error) {
	r, err := probe(ctx)
	if err != nil {
		return 1, err
	}
	if r == nil {
		return 1, errors.New("the configuration is not the one applied (or nothing is applied yet): review and apply it with lox run first, then enrol")
	}
	ask := func(prompt string) (string, error) {
		fmt.Fprint(out, prompt)
		type res struct {
			s   string
			err error
		}
		ch := make(chan res, 1)
		go func() {
			s, err := in.ReadString('\n')
			ch <- res{s, err}
		}()
		select {
		case a := <-ch:
			if a.err != nil && a.s == "" {
				return "", errors.New("no answer: nothing enrolled")
			}
			return strings.TrimSpace(a.s), nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	fmt.Fprintf(out, "Workspace %s, as the last lox run applied it:\n  configuration %s\n  %d pinned image(s), each verified with cosign now\n", workspace, r.Fingerprint, len(r.Images))
	names := make([]string, 0, len(facts))
	for n := range facts {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if f := facts[n]; f.Credentials == "ask" {
			fmt.Fprintf(out, "  warning: lock %s takes credentials a human types (credentials = \"ask\"): lox live will not serve it (missing_secret); use Vault\n", n)
		}
	}
	fmt.Fprintln(out, "Enrolled, lox live starts exactly this with no question after a reboot, serves what the profiles' auto rules decide,\nand leaves every other ticket to you (the phone, lox approve). Any change needs lox run, then a new enrolment.")
	prod := make([]string, 0, len(r.Production))
	for n := range r.Production {
		prod = append(prod, n)
	}
	slices.Sort(prod)
	for _, n := range prod {
		name := r.Production[n]
		if name == "" {
			return 1, fmt.Errorf("lock %s serves a production profile whose name the review cannot read: name it (locks.%s.profile), lox run, then enrol", n, n)
		}
		a, err := ask(fmt.Sprintf("Lock %s serves the PRODUCTION profile %s. Type the profile name %q to enrol it for unattended service: ", n, name, name))
		if err != nil {
			return 1, err
		}
		if a != name {
			fmt.Fprintln(out, "not the profile's name: nothing enrolled")
			return 1, nil
		}
	}
	a, err := ask("Enrol this workspace for lox live? [y/N] ")
	if err != nil {
		return 1, err
	}
	if strings.ToLower(a) != "y" {
		fmt.Fprintln(out, "nothing enrolled")
		return 1, nil
	}
	if err := family.WriteEnrolment(state, family.NewEnrolment(r, by, now)); err != nil {
		return 1, err
	}
	fmt.Fprintf(out, "enrolled (%s): lox live serves this workspace; a running lox live picks it up within %s\n", filepath.Join(state, family.EnrolmentFile), liveEnrolPoll)
	return 0, nil
}

// serveLock takes the workspace's serve lock for lox run, saying on
// stderr when lox live holds it.
func serveLock(abs string, stderr io.Writer) (func(), bool) {
	release, err := loxlive.Acquire(stateDir(family.Project(family.Workspace(abs))), loxlive.Run)
	if err != nil {
		fmt.Fprintln(stderr, "lox run:", err)
		return nil, false
	}
	return release, true
}
