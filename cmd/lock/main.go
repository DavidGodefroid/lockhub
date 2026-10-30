// Command lock is the Lock Family CLI on the host: it answers approvals
// in a terminal (lock approve) and, with the issues that add them, sets
// up the hub and the locks of a workspace (lock up, add, import, doctor).
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

	"golang.org/x/term"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/verify"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lock: the Lock Family CLI

Usage:
  lock up [--file lockfamily.yaml] [--dry-run]
                                          review and start the hub and the workspace's locks
  lock add TYPE INSTANCE [--version vX.Y.Z | --image REF] [--profile P] [--hub-image REF] [--file lockfamily.yaml]
                                          declare a lock (TYPE: locksql, lockmq, lockfile, lockhttp), pinned by
                                          digest to its latest (or the given) release, cosign-verified
  lock add slack --team T… --channel C… --user U… [--user U…] [--file lockfamily.yaml]
                                          enable the Slack facade; asks for its tokens at the terminal
  lock add telegram --chat ID --from ID [--chat ID --from ID …] [--file lockfamily.yaml]
                                          enable the Telegram facade; asks for the bot token at the terminal
  lock import [--file lockfamily.yaml] [SUB...]
                                          merge sub-projects' lockfamily.yaml (default: every */lockfamily.yaml),
                                          keeping the strictest routing
  lock attach INSTANCE [--file lockfamily.yaml]
                                          answer a lock console's start-up questions (policy, credentials);
                                          detach with Ctrl-P Ctrl-Q
  lock doctor [--file lockfamily.yaml]    check the hub, the locks, keys, socket and network; changes nothing
  lock approve [--socket PATH] [--once]   answer approval tickets in this terminal
  lock audit verify --data DIR --hub-key-file FILE
                                          check the hub's audit chain and decision signatures
  lock version                            print the version
  lock help                               show this help

lockfamily.yaml lives in the workspace's .lockfamily/ (lea's agents only read it there); a legacy
./lockfamily.yaml is still read, with a warning. lock add and lock import only edit it: the next
lock up reviews the change with you.
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
		fmt.Fprintln(stdout, "lock", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "approve":
		return approveCmd(args[1:], stdin, stdout, stderr)
	case "up":
		return upCmd(args[1:], stdin, stdout, stderr)
	case "add":
		if len(args) > 1 && args[1] == "slack" {
			return addSlackCmd(args[2:], stdin, stdout, stderr)
		}
		if len(args) > 1 && args[1] == "telegram" {
			return addTelegramCmd(args[2:], stdin, stdout, stderr)
		}
		return addCmd(args[1:], stdout, stderr)
	case "import":
		return importCmd(args[1:], stdout, stderr)
	case "attach":
		return attachCmd(args[1:], stdin, stdout, stderr)
	case "doctor":
		return doctorCmd(args[1:], stdout, stderr)
	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			fmt.Fprintln(stderr, "usage: lock audit verify --data DIR --hub-key-file FILE")
			return 2
		}
		return auditVerify(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lock: unknown command %q\n\n%s", args[0], usage)
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
	keyFile := fs.String("hub-key-file", "", "the hub's public key (base64), as lock up pinned it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *data == "" || *keyFile == "" {
		fmt.Fprintln(stderr, "lock audit verify: --data and --hub-key-file are required")
		return 2
	}
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "lock audit verify:", err)
		return 1
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintln(stderr, "lock audit verify: the hub key file holds no base64 Ed25519 public key")
		return 1
	}
	r, err := verify.Hub(context.Background(), *data, ed25519.PublicKey(pub))
	if err != nil {
		fmt.Fprintln(stderr, "lock audit verify:", err)
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
	return 0
}

func runtimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("lockhub-%d", os.Getuid()))
}

func stateDir(project string) string {
	d := os.Getenv("XDG_STATE_HOME")
	if d == "" {
		home, _ := os.UserHomeDir()
		d = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(d, "lockfamily", project)
}

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
	}
	return abs, nil
}

func upCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	dry := fs.Bool("dry-run", false, "show the review, apply nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fi, err := stdin.Stat(); !*dry && (err != nil || fi.Mode()&os.ModeCharDevice == 0) {
		fmt.Fprintln(stderr, "lock up: changes are confirmed at a terminal; stdin is not one")
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lock up:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := family.Exec{Stderr: stderr}
	u := &family.Up{File: abs, State: stateDir(family.Project(family.Workspace(abs))), Runtime: runtimeDir(),
		User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: r, In: bufio.NewReader(stdin), Out: stdout, DryRun: *dry}
	if err := u.Do(ctx); err != nil {
		fmt.Fprintln(stderr, "lock up:", err)
		return 1
	}
	return 0
}

// defaultSocket is where lock up publishes the hub's facade socket.
func defaultSocket() string { return filepath.Join(runtimeDir(), "lockhub", "facade.sock") }

func approveCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sock := fs.String("socket", defaultSocket(), "the hub's facade socket")
	once := fs.Bool("once", false, "answer what is waiting, then exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Approvals are typed by a human at a terminal, never piped.
	if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stderr, "lock approve: stdin is not a terminal")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &approve.Session{C: approve.Dial(*sock), In: bufio.NewReader(stdin), Out: stdout, Display: os.Getenv("USER"), Once: *once}
	if err := s.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "lock approve:", err)
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

func addCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	var o family.AddOptions
	fs.StringVar(&o.Image, "image", "", "the lock's image, ghcr.io/davidgodefroid/TYPE@sha256:<digest> (default: its latest signed release's)")
	version := fs.String("version", "", "the lock's release to pin, vX.Y.Z (default: the latest)")
	fs.StringVar(&o.HubImage, "hub-image", "", "the hub's image, to start a new lockfamily.yaml (default: lockhub's latest signed release's)")
	fs.StringVar(&o.Profile, "profile", "", "the profile the console serves, from the lock's own configuration")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 2 || (o.Image != "" && *version != "") {
		fmt.Fprintln(stderr, "usage: lock add TYPE INSTANCE [--version vX.Y.Z | --image ghcr.io/davidgodefroid/TYPE@sha256:<digest>] [--hub-image REF]")
		return 2
	}
	o.Type, o.Name = pos[0], pos[1]
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lock add:", err)
		return 1
	}
	if !slices.Contains(family.Types, o.Type) {
		fmt.Fprintf(stderr, "lock add: unknown type %q: want one of %s\n", o.Type, strings.Join(family.Types, ", "))
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rel := newReleases()
	if o.Image == "" {
		if o.Image, err = pinRelease(ctx, rel, o.Type, *version, stdout); err != nil {
			fmt.Fprintln(stderr, "lock add:", err)
			return 1
		}
	}
	if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) && o.HubImage == "" {
		if o.HubImage, err = pinRelease(ctx, rel, "lockhub", "", stdout); err != nil {
			fmt.Fprintln(stderr, "lock add:", err)
			return 1
		}
	}
	if err := family.Add(abs, o); err != nil {
		fmt.Fprintln(stderr, "lock add:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: lock %s (%s) declared; run lock up to review and start it\n", abs, o.Name, o.Type)
	return 0
}

// newReleases finds release images (tests replace it).
var newReleases = func() *family.Releases {
	rel := family.DefaultReleases(family.Exec{Stderr: io.Discard})
	rel.Token = os.Getenv("GITHUB_TOKEN")
	return rel
}

// attachCmd attaches the terminal to a lock's console, which asks the
// human its start-up questions there (lock up runs it with a terminal).
func attachCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: lock attach INSTANCE")
		return 2
	}
	if fi, err := stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stderr, "lock attach: a console's questions are answered at a terminal; stdin is not one")
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lock attach:", err)
		return 1
	}
	c, err := family.Load(abs)
	if err != nil {
		fmt.Fprintln(stderr, "lock attach:", err)
		return 1
	}
	if _, ok := c.Locks[pos[0]]; !ok {
		fmt.Fprintf(stderr, "lock attach: no lock %q in %s\n", pos[0], abs)
		return 1
	}
	project := family.Project(family.Workspace(abs))
	state := stateDir(project)
	// The compose file lock up applied, never one from the workspace.
	compose := func(a ...string) *exec.Cmd {
		return exec.Command("docker", append([]string{"compose", "-p", project, "--project-directory", state, "--env-file", os.DevNull,
			"-f", filepath.Join(state, "compose.yaml")}, a...)...)
	}
	// Attaching replays nothing: the console's pending question is in its
	// last lines.
	logs := compose("logs", "--no-log-prefix", "--tail", "20", "lock-"+pos[0])
	logs.Stdout, logs.Stderr = stdout, stderr
	_ = logs.Run()
	fmt.Fprintln(stdout, "--- attached to lock", pos[0], "(answer its last question above; detach with Ctrl-P Ctrl-Q)")
	cmd := compose("attach", "lock-"+pos[0])
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(stderr, "lock attach:", err)
		return 1
	}
	return 0
}

// pinRelease is the image of repo's release tag (the latest when tag is
// empty), by its digest, once cosign verified it.
func pinRelease(ctx context.Context, rel *family.Releases, repo, tag string, stdout io.Writer) (string, error) {
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
	ref, err := rel.Image(ctx, repo, tag)
	if err != nil {
		return "", err
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
		fmt.Fprintln(stderr, "lock import:", err)
		return 1
	}
	if len(srcs) == 0 {
		srcs = family.SubProjects(family.Workspace(abs))
		if len(srcs) == 0 {
			fmt.Fprintln(stderr, "lock import: no sub-project lockfamily.yaml in", family.Workspace(abs))
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
		fmt.Fprintln(stderr, "lock import:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s updated; run lock up to review and apply it\n", abs)
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
		fmt.Fprintln(stderr, "lock doctor:", err)
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
		fmt.Fprintln(stderr, "usage: lock add slack --team T… --channel C… --user U… [--user U…]")
		return 2
	}
	if err := s.Validate(); err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 2
	}
	ask, err := tokenPrompt(stdin, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	app, err := ask("Slack app-level token (xapp-…, scope connections:write): ")
	if err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	bot, err := ask("Slack bot token (xoxb-…, scope chat:write): ")
	if err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	if err := family.AddSlack(abs, stateDir(family.Project(family.Workspace(abs))), s, app, bot); err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: slack enabled for %s; tokens stored with the hub's data, not in the workspace. Run lock up to review and apply.\n", abs, strings.Join(s.Users, ", "))
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

// int64sFlag is a repeatable integer flag.
type int64sFlag []int64

func (s *int64sFlag) String() string { return fmt.Sprint(*s) }
func (s *int64sFlag) Set(v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return err
	}
	*s = append(*s, n)
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
	if len(pos) != 0 || len(chats) == 0 || len(chats) != len(froms) {
		fmt.Fprintln(stderr, "usage: lock add telegram --chat ID --from ID [--chat ID --from ID …]")
		return 2
	}
	var tg chatconf.Telegram
	for i := range chats {
		tg.Chats = append(tg.Chats, chatconf.TelegramChat{Chat: chats[i], From: froms[i]})
	}
	if err := tg.Validate(); err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 2
	}
	ask, err := tokenPrompt(stdin, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 1
	}
	tok, err := ask("Telegram bot token (from BotFather): ")
	if err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 1
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 1
	}
	if err := family.AddTelegram(abs, stateDir(family.Project(family.Workspace(abs))), tg, tok); err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: telegram enabled for %d chat(s); the token is stored with the hub's data, not in the workspace. Run lock up to review and apply.\n", abs, len(tg.Chats))
	return 0
}
