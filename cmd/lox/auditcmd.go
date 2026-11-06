package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// auditDirs are where lox audit reads: the hub's data directory and the
// workspace's state directory (pinned hub keys, lox run's journal).
type auditDirs struct{ data, state string }

// auditSource is the audit of a workspace's hub: its data under the
// state directory, checked under the keys lox run pinned.
func auditSource(d auditDirs, hubKeyFile, facadeKeys string) loxaudit.Source {
	src := loxaudit.Source{Data: d.data, Runs: filepath.Join(d.state, loxaudit.RunsFile), LockKeys: map[string]ed25519.PublicKey{}}
	if hubKeyFile == "" {
		hubKeyFile = filepath.Join(d.state, family.HubKeysFile)
	}
	if b, err := os.ReadFile(hubKeyFile); err == nil {
		if pubs, err := keys.ParsePublics(b); err == nil {
			src.HubKeys = pubs
		}
	}
	if lk, err := keys.LoadLocks(filepath.Join(facadeKeys, family.LockKeysFile)); err == nil {
		src.LockKeys = lk
	}
	return src
}

// auditCmd is lox audit: the hub's exchanges (each ticket and its
// answer, masked by its lock) listed in lox run's colours, filtered;
// lox audit show one in detail; lox audit verify the chain.
func auditCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "verify" {
		return auditVerify(args[1:], stdout, stderr)
	}
	show := len(args) > 0 && args[0] == "show"
	name := "audit"
	if show {
		args, name = args[1:], "audit show"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	data := fs.String("data", "", "the hub's data directory (default: the workspace's, as lox run made it)")
	hubKeyFile := fs.String("hub-key-file", "", "the hub's pinned public keys (default: hub-keys.pub next to the data directory)")
	facadeKeys := fs.String("facade-keys", family.FacadeKeysDir(stateHome()), "the pinned lock keys, as lox run wrote them")
	theme := fs.String("theme", "", "the terminal's background: light or dark (default: COLORFGBG, else dark)")
	asJSON := fs.Bool("json", false, "one JSON object per exchange and per line, for scripts")
	noPager := fs.Bool("no-pager", false, "never page the listing")
	var f loxaudit.Filter
	var since, decision string
	var follow bool
	limit := 0
	if !show {
		fs.StringVar(&f.Agent, "agent", "", "only this agent's exchanges")
		fs.StringVar(&f.Lock, "lock", "", "only this lock's exchanges: an instance (crm) or a lock (locksql)")
		fs.StringVar(&f.Profile, "profile", "", "only this profile's exchanges")
		fs.StringVar(&since, "since", "", "only exchanges since: a duration (30m, 2h, 7d), a date (2006-01-02) or a time (RFC 3339)")
		fs.StringVar(&decision, "decision", "", "only exchanges decided so: denied, human, auto or pending")
		fs.BoolVar(&f.Writes, "writes", false, "only writes and DDL")
		fs.BoolVar(&follow, "follow", false, "keep listing new exchanges and decisions as they come (Ctrl-C stops)")
		fs.IntVar(&limit, "limit", 2000, "read the newest N exchanges at most (0: all)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if show != (fs.NArg() == 1) || (!show && fs.NArg() != 0) {
		if show {
			fmt.Fprintln(stderr, "usage: lox audit show [flags] INSTANCE/ID (or an id, or the start of one)")
		} else {
			fmt.Fprintln(stderr, "lox audit: unexpected arguments:", strings.Join(fs.Args(), " "))
		}
		return 2
	}
	if *theme != "" && *theme != "light" && *theme != "dark" {
		fmt.Fprintf(stderr, "lox %s: --theme is light or dark\n", name)
		return 2
	}
	if decision != "" && !slices.Contains(loxaudit.Decisions, decision) {
		fmt.Fprintf(stderr, "lox %s: --decision is one of %s\n", name, strings.Join(loxaudit.Decisions, ", "))
		return 2
	}
	f.Decision = decision
	var err error
	if f.Since, err = loxaudit.ParseSince(since, time.Now(), time.Local); err != nil {
		fmt.Fprintf(stderr, "lox %s: %v\n", name, err)
		return 2
	}
	dirs := auditDirs{data: *data}
	if dirs.data == "" {
		abs, err := lockFile(*file, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "lox %s: %v\n", name, err)
			return 1
		}
		dirs.state = stateDir(family.Project(family.Workspace(abs)))
		dirs.data = filepath.Join(dirs.state, "hub")
	} else {
		dirs.state = filepath.Dir(filepath.Clean(dirs.data))
	}
	src := auditSource(dirs, *hubKeyFile, *facadeKeys)
	src.Since, src.Limit = f.Since, limit

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	xs, runs, err := loxaudit.Load(ctx, src)
	if err != nil {
		fmt.Fprintf(stderr, "lox %s: %v (is this the workspace lox run started? --data names another hub)\n", name, err)
		return 1
	}
	o := newAuditOut(stdout, *theme)
	if show {
		x, err := loxaudit.Find(xs, fs.Arg(0))
		if err != nil {
			fmt.Fprintf(stderr, "lox %s: %v\n", name, err)
			return 1
		}
		if *asJSON {
			return o.json(loxaudit.RecordOf(x, true), stderr)
		}
		o.page(loxrun.AuditDetail(x, time.Local, o.width, o.style), *noPager)
		return 0
	}
	xs = f.Apply(xs)
	if *asJSON {
		for _, x := range xs {
			if c := o.json(loxaudit.RecordOf(x, false), stderr); c != 0 {
				return c
			}
		}
	} else {
		o.page(loxrun.AuditListing(xs, runs, time.Local, o.width, o.style), *noPager || follow)
	}
	if !follow {
		return 0
	}
	seen := map[string]string{}
	loxaudit.Changes(seen, xs)
	return followAudit(ctx, src, f, o, *asJSON, seen, len(runs), time.Second, stderr)
}

// followAudit is lox audit --follow: every tick, the exchanges new or
// changed since seen (and lox run sessions after the first nruns), until
// ctx ends.
func followAudit(ctx context.Context, src loxaudit.Source, f loxaudit.Filter, o auditOut, asJSON bool, seen map[string]string, nruns int, every time.Duration, stderr io.Writer) int {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-tick.C:
		}
		all, runs, err := loxaudit.Load(ctx, src)
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			fmt.Fprintln(stderr, "lox audit:", err)
			continue
		}
		if !asJSON && len(runs) > nruns {
			for _, r := range runs[nruns:] {
				fmt.Fprintln(o.w, loxrun.AuditRunLine(r, time.Local, o.width, o.style))
			}
		}
		nruns = max(nruns, len(runs))
		for _, x := range loxaudit.Changes(seen, f.Apply(all)) {
			if asJSON {
				if c := o.json(loxaudit.RecordOf(x, false), stderr); c != 0 {
					return c
				}
				continue
			}
			fmt.Fprintln(o.w, loxrun.AuditLine(x, time.Local, o.width, o.style))
		}
	}
}

// auditOut is where lox audit writes: a terminal (colours, its width, a
// pager), or a pipe (plain aligned text).
type auditOut struct {
	w             io.Writer
	tty           bool
	width, height int
	style         loxrun.Style
}

func newAuditOut(w io.Writer, theme string) auditOut {
	o := auditOut{w: w, width: 120, height: 0, style: loxrun.DetectStyle(os.LookupEnv, theme)}
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		o.tty = true
		o.width, o.height = 80, 24
		if cw, ch, err := term.GetSize(int(f.Fd())); err == nil && cw > 0 {
			o.width, o.height = cw, ch
		}
	} else {
		o.style.Color = false // a pipe or a file: no escapes
		if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c >= 40 {
			o.width = c
		}
	}
	return o
}

func (o auditOut) json(r loxaudit.Record, stderr io.Writer) int {
	b, err := json.Marshal(r)
	if err == nil {
		_, err = fmt.Fprintf(o.w, "%s\n", b)
	}
	if err != nil {
		fmt.Fprintln(stderr, "lox audit:", err)
		return 1
	}
	return 0
}

// page writes lines, through a pager with search ($PAGER, else less)
// when they do not fit the terminal.
func (o auditOut) page(lines []string, noPager bool) {
	text := strings.Join(lines, "\n") + "\n"
	if noPager || !o.tty || len(lines) < o.height {
		io.WriteString(o.w, text)
		return
	}
	if err := runPager(text, o.w); err != nil {
		io.WriteString(o.w, text)
	}
}

// runPager pipes text through $PAGER (else less -R: colours kept, / to
// search, q to quit).
func runPager(text string, out io.Writer) error {
	pager := strings.TrimSpace(os.Getenv("PAGER"))
	var cmd *exec.Cmd
	if pager == "" {
		path, err := exec.LookPath("less")
		if err != nil {
			return err
		}
		cmd = exec.Command(path)
		cmd.Env = os.Environ()
		if _, ok := os.LookupEnv("LESS"); !ok {
			cmd.Env = append(cmd.Env, "LESS=FRX")
		}
	} else {
		cmd = exec.Command("/bin/sh", "-c", pager)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(text), out, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil // the pager ran (and quit its way)
		}
		return err
	}
	return nil
}
