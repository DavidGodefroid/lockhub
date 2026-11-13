package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxadd"
	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// exitInterrupted is the exit status of lox add, remove, up and init after
// a Ctrl-C (or SIGTERM): 128 + SIGINT, as a shell reports a command its
// Ctrl-C stopped. The other failures exit 1, usage errors 2, as every lox
// command.
const exitInterrupted = 130

// failed reports err of command cmd on stderr and returns the exit status:
// after an interrupt, one "interrupted" line and 130, whatever the step
// the interrupt broke said; else the error and 1.
func failed(ctx context.Context, stderr io.Writer, cmd string, err error) int {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "lox %s: interrupted\n", cmd)
		return exitInterrupted
	}
	fmt.Fprintf(stderr, "lox %s: %v\n", cmd, err)
	var me *family.ManagedError
	if errors.As(err, &me) {
		return exitManaged
	}
	return 1
}

// exitManaged is the exit of a command the company's managed file
// refuses (lockfamily docs/managed.md: 3, as the locks).
const exitManaged = 3

// answerFlags are the answers lox add TYPE takes as flags; each is the
// form's key of the same name, except --dir (lockfile's directory, key
// path) and --vault-ca-file (key vault-ca). There is never a password
// flag: the console asks for it at start.
var answerFlags = []struct{ name, usage string }{
	{"engine", "locksql: postgres, mysql, mariadb or sqlite"},
	{"host", "locksql, lockfile sftp, lockssh: the server's host (no port, no scheme)"},
	{"port", "locksql, lockfile sftp, lockssh: the server's port"},
	{"user", "the user (locksql, lockmq: empty = the console asks for it at start with the password; lockfile sftp, lockssh: required)"},
	{"database", "locksql: the database (empty: the server's default)"},
	{"tls", "locksql: disable, prefer, require, verify-ca or verify-full (never asked; empty: the driver's default, prefer)"},
	{"path", "locksql: the sqlite file, an absolute path"},
	{"url", "lockmq: the management URL"},
	{"vhost", "lockmq: the vhost (empty: all vhosts the user can see)"},
	{"amqp-url", "lockmq: the AMQP URL (empty: no stream reads)"},
	{"source", "lockfile: local, s3 or sftp"},
	{"bucket", "lockfile: the bucket name, not a URL"},
	{"endpoint", "lockfile: the S3 endpoint, a URL with its scheme (empty: AWS)"},
	{"region", "lockfile: the S3 region"},
	{"dir", "lockfile: the local directory, an absolute path"},
	{"auth", "lockfile sftp, lockssh: key or password (password: the console asks for it at start)"},
	{"only", "locklog: only the log files under these directories, comma-separated absolute paths (empty: every log this host shows)"},
	{"key", "lockfile sftp: the private key file, an absolute path; lockssh: the key file in the lock's home, such as ~/.ssh/id_ed25519 (lox run offers to copy yours there)"},
	{"known-hosts", "lockfile sftp: the known hosts file; lockssh: one in the lock's home (empty: the console's own, a new host key confirmed at the console)"},
	{"allow", "lockssh: the commands the agent runs freely, separated by ; (such as \"uptime; df -h\")"},
	{"base-dir", "lockfile sftp: the base directory (empty: the login directory)"},
	{"credentials", "ask (typed, masked, at the console's start) or vault (lockssh with a key: none too, an unencrypted key)"},
	{"vault-path", "the Vault path of the lock's credentials"},
	{"vault-address", "the Vault address, for the first lock with vault (the vault block)"},
	{"vault-namespace", "the Vault namespace (empty: the root namespace)"},
	{"vault-ca-file", "the Vault CA file (empty: the system's CA certificates)"},
	{"name", "the lock's (and its profile's) name"},
}

// flagKeys are the form's keys given under another flag name.
var flagKeys = map[string]string{"dir": "path", "vault-ca-file": "vault-ca"}

// declareOnly are the flags of lox add TYPE INSTANCE alone.
var declareOnly = []string{"image", "hub-image", "profile"}

// addCmd is lox add: TYPE alone is one source guided (or from flags) and
// applied at once; TYPE INSTANCE only declares it in lockfamily.yaml.
func addCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	version := fs.String("version", "", "the lock's release to pin, vX.Y.Z (default: the latest)")
	var o family.AddOptions
	fs.StringVar(&o.Image, "image", "", "TYPE INSTANCE only: the lock's image, ghcr.io/davidgodefroid/TYPE@sha256:<digest> (default: its latest signed release's)")
	fs.StringVar(&o.HubImage, "hub-image", "", "TYPE INSTANCE only: the hub's image, to start a new lockfamily.yaml (default: lockhub's latest signed release's)")
	fs.StringVar(&o.Profile, "profile", "", "TYPE INSTANCE only: the profile the console serves, from the lock's own configuration")
	values := map[string]*string{}
	for _, f := range answerFlags {
		values[f.name] = fs.String(f.name, "", f.usage)
	}
	production := fs.Bool("production", false, "tickets flagged production; the profile name is typed at the console's start")
	execOther := fs.Bool("exec", false, "lockssh: the agent may ask for commands outside the allow list, each on a ticket")
	nonInteractive := fs.Bool("non-interactive", false, "ask nothing: the flags and the defaults answer; without a terminal, stop once the lock is declared")
	review := fs.Bool("review", false, "lox run shows this lock's whole profile and asks (needs a terminal)")
	verbose := fs.Bool("v", false, "show cosign's and docker's own output (default: only when a step fails)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch len(pos) {
	case 2:
		for name := range set {
			if !slices.Contains(append([]string{"file", "version"}, declareOnly...), name) {
				fmt.Fprintf(stderr, "lox add: --%s: only lox add TYPE (the guided form) takes it, not TYPE INSTANCE\n", name)
				return 2
			}
		}
		o.Type, o.Name = pos[0], pos[1]
		return declareCmd(o, *file, *version, stdout, stderr)
	case 1:
	default:
		fmt.Fprintln(stderr, "usage: lox add TYPE [--non-interactive --host H …] | lox add TYPE INSTANCE [--version vX.Y.Z | --image ghcr.io/davidgodefroid/TYPE@sha256:<digest>] [--hub-image REF]")
		return 2
	}
	typ := pos[0]
	for _, name := range declareOnly {
		if set[name] {
			fmt.Fprintf(stderr, "lox add: --%s: only lox add TYPE INSTANCE takes it\n", name)
			return 2
		}
	}
	if !slices.Contains(family.Types, typ) {
		fmt.Fprintf(stderr, "lox add: unknown type %q: want one of %s\n", typ, strings.Join(family.Types, ", "))
		return 2
	}
	if typ == "lockfile" && set["path"] {
		fmt.Fprintln(stderr, "lox add: --path: lox add lockfile takes --dir")
		return 2
	}
	if *review && *nonInteractive {
		fmt.Fprintln(stderr, "lox add: --review asks at a terminal: not with --non-interactive")
		return 2
	}
	fi, _ := stdin.Stat()
	terminal := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	if !terminal && !*nonInteractive {
		fmt.Fprintf(stderr, "lox add: the questions are answered at a terminal; stdin is not one (lox add %s --non-interactive takes the answers as flags)\n", typ)
		return 1
	}
	given := loxadd.Answers{}
	for name := range set {
		switch {
		case name == "production":
			given["production"] = map[bool]string{true: "y", false: "n"}[*production]
		case name == "exec":
			given["exec"] = map[bool]string{true: "y", false: "n"}[*execOther]
		case values[name] != nil:
			key := name
			if k, ok := flagKeys[name]; ok && (name != "dir" || typ == "lockfile") {
				key = k
			}
			given[key] = *values[name]
		}
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 1
	}
	ws := family.Workspace(abs)
	if err := family.CheckWorkspace(ws); err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 1
	}
	project := family.Project(ws)
	state := stateDir(project)
	draftPath := filepath.Join(state, "add-"+typ+".json")
	d, hints, err := addDefaults(abs, ws, typ, draftPath, *nonInteractive, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 1
	}
	fields, err := loxadd.Fields(typ, d)
	if err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 2
	}
	if *nonInteractive {
		// Where the source is, is never guessed for a script: --host (or
		// lockmq's --url) is required.
		for i := range fields {
			if fields[i].Key == "host" || fields[i].Key == "url" {
				fields[i].Default = ""
			}
		}
	}
	in := bufio.NewReader(stdin)
	// The form runs before the interrupt is caught: a Ctrl-C there ends lox
	// add at once, with nothing written.
	form := &loxadd.Form{In: in, Out: stdout, NonInteractive: *nonInteractive, Hints: hints}
	a, err := form.Run(typ, fields, given)
	if err == nil {
		var l loxadd.Lock
		if l, err = loxadd.Build(typ, a); err == nil {
			return applyAdd(abs, project, state, draftPath, l, a, *version, *review, *verbose, terminal && !*nonInteractive, in, stdin, stdout, stderr)
		}
	}
	fmt.Fprintln(stderr, "lox add:", flagNames(typ, err.Error()))
	// A flag refused (or, without questions, a value missing) is a usage
	// error; an answer that could not be read is not.
	if *nonInteractive || errors.Is(err, loxadd.ErrUsage) {
		return 2
	}
	return 1
}

// addDefaults are the form's defaults: the locks declared, whether the
// vault block is there, and, at a terminal, the draft of an earlier try
// and the sources the project names (the only one of this type, if one,
// proposes its values).
func addDefaults(abs, ws, typ, draftPath string, nonInteractive bool, stderr io.Writer) (loxadd.Defaults, []loxinit.Source, error) {
	var d loxadd.Defaults
	if _, err := os.Stat(abs); err == nil {
		c, err := family.Load(abs)
		if err != nil {
			return d, nil, err
		}
		d.Declared, d.VaultSet = c.Instances(), c.Vault != nil
	}
	if nonInteractive {
		// A script's answers are its flags: no draft, no detection.
		return d, nil, nil
	}
	draft, err := loxadd.LoadDraft(draftPath)
	if err != nil {
		fmt.Fprintln(stderr, "lox add: the answers of the last try are not offered:", err)
	}
	d.Draft = draft
	var hints []loxinit.Source
	sources, warnings := loxinit.Detect(ws)
	if len(warnings) > 0 {
		// The warnings name files, never values.
		fmt.Fprintln(stderr, "lox add: hints:", strings.Join(warnings, "; "))
	}
	if typ == "locklog" {
		if s := loxinit.HostLogs(loxinit.HostLogDirs(runtime.GOOS, loxinit.RealIsDir)); s != nil {
			sources = append(sources, *s)
		}
	}
	if typ == "lockssh" {
		sources = append(sources, loxinit.SSHHosts(loxinit.UserSSHConfig())...)
	}
	for _, s := range sources {
		if s.Lock() == typ {
			hints = append(hints, s)
		}
	}
	if len(hints) == 1 {
		d.Source = &hints[0]
	}
	return d, hints, nil
}

// applyAdd applies lock l at once, under the interrupt (Ctrl-C rolls back).
func applyAdd(abs, project, state, draftPath string, l loxadd.Lock, a loxadd.Answers, version string, review, verbose, terminal bool,
	in *bufio.Reader, stdin *os.File, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rel := newReleases()
	_, leaErr := exec.LookPath("lea")
	steps := &loxadd.Steps{
		Root: family.Workspace(abs), File: abs, DraftPath: draftPath, Run: addRunner, Out: stdout, Terminal: terminal,
		AllowedUIDs: loxadd.UIDsFor(l.Type, leaErr == nil, os.Getuid()),
		PinImage: func(ctx context.Context, lock string, vault bool) (string, error) {
			variant := ""
			if vault {
				variant = "vault"
			}
			return pinVariant(ctx, rel, lock, version, variant, stdout)
		},
		PinHub: func(ctx context.Context) (string, error) { return pinRelease(ctx, rel, "lockhub", "", stdout) },
		Up: func(ctx context.Context, focus string) error {
			u := &family.Up{File: abs, State: state, Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
				User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: family.QuietExec{Verbose: verbose, Stderr: stderr},
				Resolve: upgrader(family.QuietExec{Verbose: verbose, Stderr: stderr}),
				In:      in, Out: stdout, Review: review, Focus: focus, OfferCopy: true}
			return u.Do(ctx)
		},
		Attach: func(_ context.Context, name string) error { return attachConsole(abs, name, stdin, stdout, stderr) },
		ConsoleAlive: func(ctx context.Context, name string) bool {
			m, err := consoles(ctx, project)
			return err == nil && m["lock-"+name] != ""
		},
		LeaRunning: func(ctx context.Context) bool { return leaRunning(ctx, family.Workspace(abs)) },
	}
	if err := steps.Apply(ctx, l, a); err != nil {
		// Apply showed each failing step; an interrupt it did not show as
		// one. Its error is the rollback's message.
		fmt.Fprintln(stderr, "lox add:", err)
		if errors.Is(err, context.Canceled) {
			return exitInterrupted
		}
		return 1
	}
	return 0
}

// flagNames words the form's refusals with the flag names: --path is
// lockfile's --dir, --vault-ca is --vault-ca-file.
func flagNames(typ, msg string) string {
	for flagName, key := range flagKeys {
		if flagName == "dir" && typ != "lockfile" {
			continue
		}
		for _, sep := range []string{":", " "} {
			msg = strings.ReplaceAll(msg, "--"+key+sep, "--"+flagName+sep)
		}
	}
	return msg
}

// declareCmd is lox add TYPE INSTANCE: the lock declared in
// lockfamily.yaml, pinned by digest, nothing else run.
func declareCmd(o family.AddOptions, file, version string, stdout, stderr io.Writer) int {
	if o.Image != "" && version != "" {
		fmt.Fprintln(stderr, "usage: lox add TYPE INSTANCE [--version vX.Y.Z | --image ghcr.io/davidgodefroid/TYPE@sha256:<digest>] [--hub-image REF]")
		return 2
	}
	abs, err := lockFile(file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 1
	}
	if !slices.Contains(family.Types, o.Type) {
		fmt.Fprintf(stderr, "lox add: unknown type %q: want one of %s\n", o.Type, strings.Join(family.Types, ", "))
		return 2
	}
	if err := family.CheckWorkspace(family.Workspace(abs)); err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rel := newReleases()
	if o.Image == "" {
		if o.Image, err = pinRelease(ctx, rel, o.Type, version, stdout); err != nil {
			fmt.Fprintln(stderr, "lox add:", err)
			return 1
		}
	}
	if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) && o.HubImage == "" {
		if o.HubImage, err = pinRelease(ctx, rel, "lockhub", "", stdout); err != nil {
			fmt.Fprintln(stderr, "lox add:", err)
			return 1
		}
	}
	if err := family.Add(abs, o); err != nil {
		fmt.Fprintln(stderr, "lox add:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: lock %s (%s) declared; run lox run to review and start it\n", abs, o.Name, o.Type)
	return 0
}

// addRunner runs the launchers' verbs (tests replace it).
var addRunner loxinit.Runner = loxinit.ExecRunner{}

// newReleases finds release images (tests replace it).
var newReleases = func() *family.Releases {
	rel := family.DefaultReleases(family.Exec{Stderr: io.Discard})
	rel.Token = os.Getenv("GITHUB_TOKEN")
	return rel
}

// leaRunning reports a lea container running for the projects directory
// dir. lea labels its container with the physical path (symlinks
// resolved), so dir is resolved the same way. Any docker error means not
// running.
func leaRunning(ctx context.Context, dir string) bool {
	phys, err := filepath.EvalSymlinks(dir)
	if err != nil {
		phys = dir
	}
	out, err := exec.CommandContext(ctx, "docker", "ps", "--quiet", "--filter", "label=lea.projects="+phys).Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}
