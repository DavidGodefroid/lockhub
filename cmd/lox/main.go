// Command lox is the Lock Family CLI on the host: lox run, in a terminal
// of its own outside any agent, starts the hub and the locks of a
// workspace and serves the hub's decisions (auto mode by default); lox
// add, import, doctor and the rest set the workspace up.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	lkaudit "github.com/DavidGodefroid/lockkit/audit"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/mobilecli"
	"github.com/DavidGodefroid/lockhub/internal/verify"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lox: the Lock Family CLI

Usage:
  lox init [--review] [-v] [--hub-image REF] [--file lockfamily.yaml]
                                          start the project's hub alone, without a question: prerequisites, the
                                          data sources its files name as hints (read only, no secret; lox add
                                          sets a lock up), lockfamily.yaml with the hub, then lox run
  lox run [--manual] [--theme light|dark] [--no-start] [--file lockfamily.yaml] [-v] [--review] [--pin sha256:DIGEST] [--no-upgrade] [--rotate hub|INSTANCE|all]
                                          in a terminal of its own, outside the agent: start (or reuse) the hub
                                          and the workspace's locks, then show every ticket and decision live
                                          (masked) and serve decisions: auto mode by default (reads auto, writes
                                          and DDL asked, a connection asked once per profile per session), the
                                          rest asked in a question card; Shift+Tab switches auto/manual; quitting
                                          stops decisions (tickets wait: fail closed). --no-start only serves
                                          decisions; --pin, --rotate, --review, -v as they were on lox up;
                                          an image older than this lox's release is upgraded first, verified
                                          with cosign (--no-upgrade keeps the pins)
  lox up                                  deprecated: use lox run (it still starts the hub and the locks)
  lox add TYPE [--non-interactive --host H …] [--review] [-v] [--version vX.Y.Z] [--file lockfamily.yaml]
                                          one source (TYPE: locksql, lockmq, lockfile, lockhttp), guided (or
                                          from flags alone with --non-interactive) and applied at once: profile
                                          add, init claude, doctor, lockfamily.yaml, the start with this lock's
                                          review, lox attach; a failure, a "n" or Ctrl-C keeps nothing; without
                                          a terminal it stops once the lock is declared
  lox add TYPE INSTANCE [--version vX.Y.Z | --image REF] [--profile P] [--hub-image REF] [--file lockfamily.yaml]
                                          only declare a lock, pinned by digest to its latest (or the given)
                                          release, cosign-verified
  lox add slack --team T… --channel C… --user U… [--user U…] [--file lockfamily.yaml]
                                          enable the Slack facade; asks for its tokens at the terminal
  lox add telegram --chat ID --from ID [--chat ID --from ID …] [--file lockfamily.yaml]
                                          enable the Telegram facade; asks for the bot token at the terminal
  lox remove NAME [--purge] [-v] [--file lockfamily.yaml]
                                          take a lock out of lockfamily.yaml and stop its console after one
                                          review; its profile stays in the lock's config.toml unless --purge;
                                          a "n", a failure or Ctrl-C keeps the lock
  lox vault set --address URL [--namespace NS] [--ca-file PATH] [--file lockfamily.yaml]
                                          write the shared vault: block; lox run reviews and applies it;
                                          an omitted --namespace / --ca-file keeps the current value, "" clears it
  lox import [--file lockfamily.yaml] [SUB...]
                                          merge sub-projects' lockfamily.yaml (default: every */lockfamily.yaml),
                                          keeping the strictest routing
  lox attach INSTANCE [--file lockfamily.yaml]
                                          answer a lock console's start-up questions (policy, credentials);
                                          detach with Ctrl-P Ctrl-Q
  lox doctor [--file lockfamily.yaml]    check the hub, the locks, keys, socket and network; changes nothing
  lox refresh INSTANCE [--file lockfamily.yaml]
                                          rewrite a locklog lock's containers map once (its docker source's
                                          containers, from the globs lox run applied)
  lox approve [--socket PATH] [--once] [--facade-keys DIR]
                                          answer approval tickets in this terminal (o: clear values, also Ctrl-O
                                          where the terminal passes it; r on an expired ticket: approve again)
  lox mobile pair --name NAME [--file FILE] [--socket PATH]
                                          pair a phone with the mobile facade (confirmed at this terminal)
  lox mobile list|revoke NAME|ID [--file FILE] [--socket PATH]
                                          list or revoke paired phones; lox run then (un)pins them at the locks
  lox audit [--agent A] [--lock L] [--profile P] [--since 2h] [--writes]
            [--decision denied|human|auto|pending] [--follow] [--json]
                                          the hub's exchanges: each ticket and its answer, masked
  lox audit show INSTANCE/ID [--json]     one exchange: masked plan, deciding rule or human, timings, signatures
  lox audit verify --data DIR --hub-key-file FILE
                                          check the hub's audit chain and decision signatures
  lox version                            print the version
  lox help                               show this help

lockfamily.yaml lives in the workspace's .lockfamily/ (lea's agents only read it there); a legacy
./lockfamily.yaml is still read, with a warning. lox add TYPE INSTANCE, lox vault set and lox import
only edit it: the next lox run reviews the change with you.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "lox", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "approve":
		return approveCmd(args[1:], stdin, stdout, stderr)
	case "mobile":
		return mobileCmd(args[1:], stdin, stdout, stderr)
	case "run":
		return runCmd(args[1:], stdin, stdout, stderr)
	case "up":
		fmt.Fprintln(stderr, "lox up is deprecated: use lox run (it starts the hub and the locks, then serves the decisions in its terminal)")
		return upCmd(args[1:], stdin, stdout, stderr)
	case "init":
		return initCmd(args[1:], stdin, stdout, stderr)
	case "add":
		if len(args) > 1 && args[1] == "slack" {
			return addSlackCmd(args[2:], stdin, stdout, stderr)
		}
		if len(args) > 1 && args[1] == "telegram" {
			return addTelegramCmd(args[2:], stdin, stdout, stderr)
		}
		return addCmd(args[1:], stdin, stdout, stderr)
	case "remove":
		return removeCmd(args[1:], stdin, stdout, stderr)
	case "vault":
		return vaultCmd(args[1:], stdout, stderr)
	case "import":
		return importCmd(args[1:], stdout, stderr)
	case "attach":
		return attachCmd(args[1:], stdin, stdout, stderr)
	case "doctor":
		return doctorCmd(args[1:], stdout, stderr)
	case "refresh":
		return refreshCmd(args[1:], stdout, stderr)
	case "audit":
		return auditCmd(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lox: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// auditVerify checks a hub data directory against the hub's pinned
// public key (never the key file next to the data: whoever could edit the
// data could re-sign it).
func auditVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "the hub's data directory")
	keyFile := fs.String("hub-key-file", "", "the hub's public keys (base64, one per line, oldest first: the current one last), as lox run pinned them (hub-keys.pub in its state directory)")
	var lockLogs lockLogFlag
	fs.Var(&lockLogs, "lock", "INSTANCE=PATH: also verify that lock's audit log (its audit.log, or the directory holding it); repeatable")
	anchorsFile := fs.String("anchors", "", "file keeping each lock log's anchor between runs (host only, 0600): a log cut or stripped since is refused")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if lockLogs.err != nil {
		fmt.Fprintln(stderr, "lox audit verify:", lockLogs.err)
		return 2
	}
	if *anchorsFile != "" && len(lockLogs.logs) == 0 {
		fmt.Fprintln(stderr, "lox audit verify: --anchors needs --lock")
		return 2
	}
	if *data == "" || *keyFile == "" {
		fmt.Fprintln(stderr, "lox audit verify: --data and --hub-key-file are required")
		return 2
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "lox audit verify:", err)
		return 1
	}
	pubs, err := keys.ParsePublics(b)
	if err == nil && len(pubs) == 0 {
		err = errors.New("no key")
	}
	if err != nil {
		fmt.Fprintln(stderr, "lox audit verify: the hub key file holds no list of base64 Ed25519 public keys:", err)
		return 1
	}
	r, err := verify.Hub(context.Background(), *data, pubs)
	if err != nil {
		fmt.Fprintln(stderr, "lox audit verify:", err)
		return 1
	}
	for _, p := range r.Problems {
		fmt.Fprintln(stdout, "FAIL", p)
	}
	if !r.OK() {
		fmt.Fprintf(stdout, "%d problem(s) in %d records, %d decisions\n", len(r.Problems), r.Records, r.Decisions)
		return 1
	}
	fmt.Fprintf(stdout, "OK: %d audit records chained, %d decisions signed and recorded\n", r.Records, r.Decisions)
	if r.Outboxed > 0 {
		fmt.Fprintf(stdout, "%d audit record(s) of committed changes not yet in the log: the hub appends them at its next start or change\n", r.Outboxed)
	}
	if len(lockLogs.logs) == 0 {
		return 0
	}
	return verifyLocks(*data, pubs, lockLogs.logs, *anchorsFile, stdout, stderr)
}

// verifyLocks is lox audit verify --lock: each lock's chain, against its
// kept anchor when there is one, and its records of hub decisions against
// the hub's.
func verifyLocks(data string, pub []ed25519.PublicKey, logs []verify.LockLog, anchorsFile string, stdout, stderr io.Writer) int {
	anchors := map[string]lkaudit.Anchor{}
	if anchorsFile != "" {
		var err error
		if anchors, err = verify.LoadAnchors(anchorsFile); err != nil {
			fmt.Fprintln(stderr, "lox audit verify:", err)
			return 1
		}
	}
	kept := maps.Clone(anchors)
	reps, err := verify.Locks(context.Background(), data, pub, logs, anchors)
	if err != nil {
		fmt.Fprintln(stderr, "lox audit verify:", err)
		return 1
	}
	code := 0
	for _, r := range reps {
		for _, p := range r.Problems {
			fmt.Fprintf(stdout, "FAIL %s: %s\n", r.Instance, p)
		}
		if !r.OK() {
			code = 1
			continue
		}
		how := "not anchored (pass --anchors FILE to see a cut tail next time)"
		switch {
		case r.Anchored:
			how = fmt.Sprintf("anchored at line %d of the last run", kept[r.Instance].Line)
		case anchorsFile != "":
			how = "not anchored: no anchor kept for it yet (a first run, or its entry or the file was removed)"
		}
		fmt.Fprintf(stdout, "OK: %s: %d audit records chained (%d before the chain), %d hub decisions match the hub's, %s\n", r.Instance, r.Records, r.Legacy, r.HubDecisions, how)
		if r.Unsigned > 0 {
			fmt.Fprintf(stdout, "  %s: %d of them without the hub's signature (checked on ticket, outcome, approver and facade)\n", r.Instance, r.Unsigned)
		}
		if r.Unrecorded > 0 {
			fmt.Fprintf(stdout, "  %s: %d hub decision(s) on it not in this log (not acted on yet, or cut from it)\n", r.Instance, r.Unrecorded)
		}
		anchors[r.Instance] = r.Anchor
	}
	if anchorsFile != "" {
		// Only verified logs move their anchor forward.
		if err := verify.SaveAnchors(anchorsFile, anchors); err != nil {
			fmt.Fprintln(stderr, "lox audit verify:", err)
			return 1
		}
	}
	return code
}

// lockLogFlag is the repeatable --lock INSTANCE=PATH. A bad value is
// noted, not refused: the flag package would quote it in its error.
type lockLogFlag struct {
	logs []verify.LockLog
	err  error
}

func (f *lockLogFlag) String() string { return "" }

func (f *lockLogFlag) Set(v string) error {
	inst, path, ok := strings.Cut(v, "=")
	switch {
	case f.err != nil:
	case !ok || !keys.ValidInstance(inst) || path == "":
		f.err = errors.New("--lock: want INSTANCE=PATH")
	case slices.ContainsFunc(f.logs, func(l verify.LockLog) bool { return l.Instance == inst }):
		f.err = fmt.Errorf("--lock %s given twice", inst)
	default:
		f.logs = append(f.logs, verify.LockLog{Instance: inst, Path: path})
	}
	return nil
}

func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("lockhub-%d", os.Getuid()))
}

func stateHome() string {
	d := os.Getenv("XDG_STATE_HOME")
	if d == "" {
		home, _ := os.UserHomeDir()
		d = filepath.Join(home, ".local", "state")
	}
	return d
}

func stateDir(project string) string { return filepath.Join(stateHome(), "lockfamily", project) }

// hubUser is the uid:gid that makes the hub's files and facade socket the
// host user's: root under a rootless engine (it is the host user there),
// the host user's ids otherwise.
func hubUser(ctx context.Context, r family.Runner) string {
	// Docker reports rootless in SecurityOptions, Podman in Host.Security.
	if out, err := r.Run(ctx, nil, "docker", "info", "--format", "{{.SecurityOptions}}"); err == nil && strings.Contains(string(out), "rootless") {
		return "0:0"
	}
	if out, err := r.Run(ctx, nil, "docker", "info", "--format", "{{.Host.Security.Rootless}}"); err == nil && strings.TrimSpace(string(out)) == "true" {
		return "0:0"
	}
	return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
}

// lockFile is the lockfamily.yaml a command works on: the --file given,
// else the current directory's (family.Locate), as an absolute path. A
// legacy one at the workspace's root is used, with a warning.
func lockFile(flagged string, stderr io.Writer) (string, error) {
	f := flagged
	if f == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		f = family.Locate(wd)
	}
	abs, err := filepath.Abs(f)
	if err != nil {
		return "", err
	}
	abs = family.Canonical(abs)
	if family.Legacy(abs) {
		fmt.Fprintln(stderr, family.LegacyWarning(abs))
	} else if h := family.MissingHint(abs); h != "" {
		if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "lox: "+abs+" does not exist"+h)
		}
	}
	return abs, nil
}

func upCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	dry := fs.Bool("dry-run", false, "show the review, apply nothing")
	pin := fs.String("pin", "", "the hub image by digest (sha256:…, or the whole ghcr.io/davidgodefroid/lockhub@sha256:… reference): lockfamily.yaml takes it once applied")
	verbose := fs.Bool("v", false, "show cosign's and docker's own output (default: only when a step fails)")
	review := fs.Bool("review", false, "show everything, the profiles line by line, and ask (even for a hub with no lock)")
	var rotate stringsFlag
	fs.Var(&rotate, "rotate", "replace a key: hub, a lock instance, or all (repeatable, or comma-separated)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox up: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 2
	}
	if fi, err := stdin.Stat(); !*dry && (err != nil || fi.Mode()&os.ModeCharDevice == 0) {
		fmt.Fprintln(stderr, "lox up: changes are confirmed at a terminal; stdin is not one")
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox up:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := family.QuietExec{Verbose: *verbose, Stderr: stderr}
	u := &family.Up{File: abs, State: stateDir(family.Project(family.Workspace(abs))), Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
		User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: r, In: bufio.NewReader(stdin), Out: stdout, DryRun: *dry,
		Pin: *pin, Rotate: rotate, Review: *review}
	if err := u.Do(ctx); err != nil {
		return failed(ctx, stderr, "up", err)
	}
	return 0
}

// defaultSocket is where lox run publishes the hub's facade socket.
func defaultSocket() string { return filepath.Join(runtimeDir(), "lockhub", "facade.sock") }

func approveCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	once := fs.Bool("once", false, "answer what is waiting, then exit")
	keysDir := fs.String("facade-keys", family.FacadeKeysDir(stateHome()), "the host facades' keys and the pinned lock keys, as lox run wrote them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Approvals are typed by a human at a terminal, never piped.
	if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stderr, "lox approve: stdin is not a terminal")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &approve.Session{C: approve.Dial(*sock), In: bufio.NewReader(stdin), Out: stdout, Display: os.Getenv("USER"), Once: *once}
	// Clear values (Ctrl-O) need this terminal's facade key, which the
	// locks pin, and the lock keys lox up pinned to check their answers.
	if fk, err := keys.Load(family.FacadeKeyPath(*keysDir, "tty")); err == nil {
		if lk, err := keys.LoadLocks(filepath.Join(*keysDir, family.LockKeysFile)); err == nil {
			s.FacadeKey, s.LockKeys = fk, lk
		}
	}
	if s.FacadeKey == nil {
		fmt.Fprintln(stderr, "lox approve: no facade key or pinned lock keys in", *keysDir, "(run lox run): clear values cannot be shown")
	}
	if err := s.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "lox approve:", err)
		return 1
	}
	return 0
}

// parse parses fs, with flags allowed after the positional arguments, and
// returns the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// attachCmd attaches the terminal to a lock's console, which asks the
// human its start-up questions there (lox up runs it with a terminal).
func attachCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: lox attach INSTANCE")
		return 2
	}
	if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stderr, "lox attach: a console's questions are answered at a terminal; stdin is not one")
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox attach:", err)
		return 1
	}
	c, err := family.Load(abs)
	if err != nil {
		fmt.Fprintln(stderr, "lox attach:", err)
		return 1
	}
	if _, ok := c.Locks[pos[0]]; !ok {
		fmt.Fprintf(stderr, "lox attach: no lock %q in %s\n", pos[0], abs)
		return 1
	}
	if err := attachConsole(abs, pos[0], stdin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "lox attach:", err)
		return 1
	}
	return 0
}

// attachConsole attaches the terminal to the console of lock name, through
// the compose file lox up applied (never one from the workspace).
func attachConsole(abs, name string, stdin *os.File, stdout, stderr io.Writer) error {
	project := family.Project(family.Workspace(abs))
	state := stateDir(project)
	// The console has no log (it would keep its screens): attaching
	// replays nothing, and lox cannot tell which question it waits for.
	fmt.Fprintf(stdout, "attached to lock %s (its pending question is not shown again: the policy review, \"Apply these changes? [y/N]\", on a first start or after a loosening; for a production profile, \"Type the profile name %q to continue:\"; or a password its profile does not take from Vault; detach with Ctrl-P Ctrl-Q)\n", name, name)
	cmd := exec.Command("docker", "compose", "-p", project, "--project-directory", state, "--env-file", os.DevNull,
		"-f", filepath.Join(state, "compose.yaml"), "attach", "lock-"+name)
	detach := &escapeWatch{w: stderr}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, detach
	err := cmd.Run()
	// Detaching (Ctrl-P Ctrl-Q) ends docker's attach with status 1 and
	// "read escape sequence": the console keeps running.
	if err != nil && detach.seen {
		fmt.Fprintf(stdout, "detached from %s: its console keeps running\n", name)
		return nil
	}
	return err
}

// escapeSequence is docker's message when the terminal detaches.
const escapeSequence = "read escape sequence"

// escapeWatch passes docker's stderr through and notes whether it said
// escapeSequence.
type escapeWatch struct {
	w    io.Writer
	tail string
	seen bool
}

func (e *escapeWatch) Write(p []byte) (int, error) {
	if !e.seen {
		e.tail += string(p)
		e.seen = strings.Contains(e.tail, escapeSequence)
		if n := len(escapeSequence) - 1; len(e.tail) > n {
			e.tail = e.tail[len(e.tail)-n:]
		}
	}
	return e.w.Write(p)
}

// pinRelease is the image of repo's release tag (the latest when tag is
// empty), by its digest, once cosign verified it.
func pinRelease(ctx context.Context, rel *family.Releases, repo, tag string, stdout io.Writer) (string, error) {
	return pinVariant(ctx, rel, repo, tag, "", stdout)
}

// pinVariant is pinRelease for the release's variant image ("vault"; ""
// is the plain image).
func pinVariant(ctx context.Context, rel *family.Releases, repo, tag, variant string, stdout io.Writer) (string, error) {
	if tag == "" {
		t, pre, err := rel.Latest(ctx, repo)
		if err != nil {
			return "", err
		}
		if pre {
			fmt.Fprintf(stdout, "%s has only pre-releases: pinning %s\n", repo, t)
		}
		tag = t
	}
	ref, err := rel.ImageVariant(ctx, repo, tag, variant)
	if err != nil {
		return "", err
	}
	if variant != "" {
		tag += " (" + variant + ")"
	}
	fmt.Fprintf(stdout, "%s %s: %s (signature verified)\n", repo, tag, ref)
	return ref, nil
}

func importCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	srcs, err := parse(fs, args)
	if err != nil {
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox import:", err)
		return 1
	}
	if len(srcs) == 0 {
		srcs = family.SubProjects(family.Workspace(abs))
		if len(srcs) == 0 {
			fmt.Fprintln(stderr, "lox import: no sub-project lockfamily.yaml in", family.Workspace(abs))
			return 1
		}
	}
	for i, s := range srcs {
		if fi, err := os.Stat(s); err == nil && fi.IsDir() {
			srcs[i] = family.Locate(s)
		}
	}
	notes, err := family.Import(abs, srcs)
	for _, n := range notes {
		fmt.Fprintln(stdout, n)
	}
	if err != nil {
		fmt.Fprintln(stderr, "lox import:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s updated; run lox run to review and apply it\n", abs)
	return 0
}

// refreshCmd is lox refresh: a locklog lock's containers map, rewritten
// once from the globs the last confirmed lox run applied.
func refreshCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: lox refresh INSTANCE [--file lockfamily.yaml]")
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox refresh:", err)
		return 1
	}
	c, err := family.Load(abs)
	if err != nil {
		fmt.Fprintln(stderr, "lox refresh:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	msg, err := family.Refresh(ctx, family.Exec{Stderr: stderr}, stateDir(family.Project(family.Workspace(abs))), c, pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "lox refresh:", err)
		return 1
	}
	fmt.Fprintln(stdout, msg)
	return 0
}

func doctorCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox doctor:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := &family.Doctor{File: abs, State: stateDir(family.Project(family.Workspace(abs))), Runtime: runtimeDir(), Root: "/",
		Run: family.Exec{Stderr: io.Discard}, Out: stdout}
	if n := d.Do(ctx); n > 0 {
		fmt.Fprintf(stdout, "%d problem(s)\n", n)
		return 1
	}
	return 0
}

// strings is a repeatable flag.
type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func addSlackCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add slack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	var s chatconf.Slack
	var users stringsFlag
	fs.StringVar(&s.Team, "team", "", "the Slack workspace id (T…)")
	fs.StringVar(&s.Channel, "channel", "", "the channel id (C…) where tickets are posted; invite the app there")
	fs.Var(&users, "user", "a member id (U…) who may answer (repeat)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	s.Users = users
	if len(pos) != 0 || s.Team == "" || s.Channel == "" || len(s.Users) == 0 {
		fmt.Fprintln(stderr, "usage: lox add slack --team T… --channel C… --user U… [--user U…]")
		return 2
	}
	if err := s.Validate(); err != nil {
		fmt.Fprintln(stderr, "lox add slack:", err)
		return 2
	}
	ask, err := tokenPrompt(stdin, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "lox add slack:", err)
		return 1
	}
	app, err := ask("Slack app-level token (xapp-…, scope connections:write): ")
	if err != nil {
		fmt.Fprintln(stderr, "lox add slack:", err)
		return 1
	}
	bot, err := ask("Slack bot token (xoxb-…, scope chat:write): ")
	if err != nil {
		fmt.Fprintln(stderr, "lox add slack:", err)
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox add slack:", err)
		return 1
	}
	if err := family.AddSlack(abs, stateDir(family.Project(family.Workspace(abs))), s, app, bot); err != nil {
		fmt.Fprintln(stderr, "lox add slack:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: slack enabled for %s; tokens stored with the hub's data, not in the workspace. Run lox run to review and apply.\n", abs, strings.Join(s.Users, ", "))
	return 0
}

// tokenPrompt reads secrets typed (or pasted) at a terminal without echo,
// never from the command line, where other processes and the shell
// history see them.
func tokenPrompt(stdin *os.File, stdout io.Writer) (func(string) (string, error), error) {
	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("tokens are typed at a terminal; stdin is not one")
	}
	return func(prompt string) (string, error) {
		fmt.Fprint(stdout, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stdout)
		return strings.TrimSpace(string(b)), err
	}, nil
}

// int64sFlag is a repeatable integer flag. A bad value is noted, not
// refused: the flag package would quote it (a token pasted there) in its
// error.
type int64sFlag struct {
	ids []int64
	bad bool
}

func (s *int64sFlag) String() string { return fmt.Sprint(s.ids) }
func (s *int64sFlag) Set(v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		s.bad = true
		return nil
	}
	s.ids = append(s.ids, n)
	return nil
}

func addTelegramCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add telegram", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	var chats, froms int64sFlag
	fs.Var(&chats, "chat", "a chat id where the bot posts tickets (a private chat: your user id; a group: negative, and every member of the group sees the tickets)")
	fs.Var(&froms, "from", "the user id who may answer in the --chat before it (repeat in pairs)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	for name, f := range map[string]*int64sFlag{"--chat": &chats, "--from": &froms} {
		if f.bad {
			fmt.Fprintf(stderr, "lox add telegram: %s: want a decimal integer id\n", name)
			return 2
		}
	}
	if len(pos) != 0 || len(chats.ids) == 0 || len(chats.ids) != len(froms.ids) {
		fmt.Fprintln(stderr, "usage: lox add telegram --chat ID --from ID [--chat ID --from ID …]")
		return 2
	}
	var tg chatconf.Telegram
	for i := range chats.ids {
		tg.Chats = append(tg.Chats, chatconf.TelegramChat{Chat: chats.ids[i], From: froms.ids[i]})
	}
	if err := tg.Validate(); err != nil {
		fmt.Fprintln(stderr, "lox add telegram:", err)
		return 2
	}
	ask, err := tokenPrompt(stdin, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "lox add telegram:", err)
		return 1
	}
	tok, err := ask("Telegram bot token (from BotFather): ")
	if err != nil {
		fmt.Fprintln(stderr, "lox add telegram:", err)
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox add telegram:", err)
		return 1
	}
	if err := family.AddTelegram(abs, stateDir(family.Project(family.Workspace(abs))), tg, tok); err != nil {
		fmt.Fprintln(stderr, "lox add telegram:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: telegram enabled for %d chat(s); the token is stored with the hub's data, not in the workspace. Run lox run to review and apply.\n", abs, len(tg.Chats))
	return 0
}

func mobileCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	const use = "usage: lox mobile pair --name NAME | list | revoke NAME|ID  [--file FILE] [--socket PATH]"
	if len(args) == 0 {
		fmt.Fprintln(stderr, use)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("mobile "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	name := fs.String("name", "", "the phone's name (a-z, 0-9, -)")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox mobile:", err)
		return 1
	}
	state := stateDir(family.Project(family.Workspace(abs)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := mobilecli.Dial(*sock)
	switch {
	case sub == "pair" && len(pos) == 0 && *name != "":
		if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			fmt.Fprintln(stderr, "lox mobile pair: the device is confirmed at a terminal; stdin is not one")
			return 1
		}
		// The origin lox up applied (reviewed), not the yaml as it is now.
		var origin string
		if origin, err = family.AppliedMobileOrigin(state); err == nil {
			err = mobilecli.Pair(ctx, c, *name, origin, state, bufio.NewReader(stdin), stdout)
		}
	case sub == "list" && len(pos) == 0:
		err = mobilecli.List(ctx, c, state, stdout)
	case sub == "revoke" && len(pos) == 1:
		err = mobilecli.Revoke(ctx, c, pos[0], state, stdout)
	default:
		fmt.Fprintln(stderr, use)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "lox mobile:", err)
		return 1
	}
	return 0
}
