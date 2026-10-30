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
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	lkaudit "github.com/DavidGodefroid/lockkit/audit"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/verify"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lock: the Lock Family CLI

Usage:
  lock up [--file lockfamily.yaml] [--dry-run]
                                          review and start the hub and the workspace's locks
  lock add TYPE INSTANCE --image REF [--hub-image REF] [--file lockfamily.yaml]
                                          declare a lock (TYPE: locksql, lockmq, lockfile, lockhttp; REF pinned @sha256)
  lock add slack --team T… --channel C… --user U… [--user U…] [--file lockfamily.yaml]
                                          enable the Slack facade; asks for its tokens at the terminal
  lock add telegram --chat ID --from ID [--chat ID --from ID …] [--file lockfamily.yaml]
                                          enable the Telegram facade; asks for the bot token at the terminal
  lock import [--file lockfamily.yaml] [SUB...]
                                          merge sub-projects' lockfamily.yaml (default: every */lockfamily.yaml),
                                          keeping the strictest routing
  lock doctor [--file lockfamily.yaml]    check the hub, the locks, keys, socket and network; changes nothing
  lock approve [--socket PATH] [--once]   answer approval tickets in this terminal
  lock audit verify --data DIR --hub-key-file FILE
                                          check the hub's audit chain and decision signatures
  lock version                            print the version
  lock help                               show this help

lock add and lock import only edit lockfamily.yaml: the next lock up reviews the change with you.
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
	var lockLogs lockLogFlag
	fs.Var(&lockLogs, "lock", "INSTANCE=PATH: also verify that lock's audit log (its audit.log, or the directory holding it); repeatable")
	anchorsFile := fs.String("anchors", "", "file keeping each lock log's anchor between runs (host only, 0600): a log cut or stripped since is refused")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *anchorsFile != "" && len(lockLogs) == 0 {
		fmt.Fprintln(stderr, "lock audit verify: --anchors needs --lock")
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
	if len(lockLogs) == 0 {
		return 0
	}
	return verifyLocks(*data, ed25519.PublicKey(pub), lockLogs, *anchorsFile, stdout, stderr)
}

// verifyLocks is lock audit verify --lock: each lock's chain, against its
// kept anchor when there is one, and its records of hub decisions against
// the hub's.
func verifyLocks(data string, pub ed25519.PublicKey, logs []verify.LockLog, anchorsFile string, stdout, stderr io.Writer) int {
	anchors := map[string]lkaudit.Anchor{}
	if anchorsFile != "" {
		var err error
		if anchors, err = verify.LoadAnchors(anchorsFile); err != nil {
			fmt.Fprintln(stderr, "lock audit verify:", err)
			return 1
		}
	}
	kept := maps.Clone(anchors)
	reps, err := verify.Locks(context.Background(), data, pub, logs, anchors)
	if err != nil {
		fmt.Fprintln(stderr, "lock audit verify:", err)
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
			fmt.Fprintln(stderr, "lock audit verify:", err)
			return 1
		}
	}
	return code
}

// lockLogFlag is the repeatable --lock INSTANCE=PATH.
type lockLogFlag []verify.LockLog

func (f *lockLogFlag) String() string { return "" }

func (f *lockLogFlag) Set(v string) error {
	inst, path, ok := strings.Cut(v, "=")
	if !ok || !keys.ValidInstance(inst) || path == "" {
		return fmt.Errorf("want INSTANCE=PATH, got %q", v)
	}
	for _, l := range *f {
		if l.Instance == inst {
			return fmt.Errorf("--lock %s given twice", inst)
		}
	}
	*f = append(*f, verify.LockLog{Instance: inst, Path: path})
	return nil
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

func upCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "lockfamily.yaml", "the workspace's lockfamily.yaml")
	dry := fs.Bool("dry-run", false, "show the review, apply nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fi, err := stdin.Stat(); !*dry && (err != nil || fi.Mode()&os.ModeCharDevice == 0) {
		fmt.Fprintln(stderr, "lock up: changes are confirmed at a terminal; stdin is not one")
		return 1
	}
	abs, err := filepath.Abs(*file)
	if err != nil {
		fmt.Fprintln(stderr, "lock up:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := family.Exec{Stderr: stderr}
	u := &family.Up{File: abs, State: stateDir(family.Project(filepath.Dir(abs))), Runtime: runtimeDir(),
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
	file := fs.String("file", "lockfamily.yaml", "the workspace's lockfamily.yaml")
	var o family.AddOptions
	fs.StringVar(&o.Image, "image", "", "the lock's image, ghcr.io/davidgodefroid/TYPE@sha256:<digest> of its signed release")
	fs.StringVar(&o.HubImage, "hub-image", "", "the hub's image, to start a new lockfamily.yaml")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 2 || o.Image == "" {
		fmt.Fprintln(stderr, "usage: lock add TYPE INSTANCE --image ghcr.io/davidgodefroid/TYPE@sha256:<digest> [--hub-image REF]")
		return 2
	}
	o.Type, o.Name = pos[0], pos[1]
	if err := family.Add(*file, o); err != nil {
		fmt.Fprintln(stderr, "lock add:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: lock %s (%s) declared; run lock up to review and start it\n", *file, o.Name, o.Type)
	return 0
}

func importCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "lockfamily.yaml", "the workspace's lockfamily.yaml")
	srcs, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(srcs) == 0 {
		srcs, _ = filepath.Glob(filepath.Join(filepath.Dir(*file), "*", "lockfamily.yaml"))
		if len(srcs) == 0 {
			fmt.Fprintln(stderr, "lock import: no sub-project lockfamily.yaml next to", *file)
			return 1
		}
	}
	for i, s := range srcs {
		if fi, err := os.Stat(s); err == nil && fi.IsDir() {
			srcs[i] = filepath.Join(s, "lockfamily.yaml")
		}
	}
	notes, err := family.Import(*file, srcs)
	for _, n := range notes {
		fmt.Fprintln(stdout, n)
	}
	if err != nil {
		fmt.Fprintln(stderr, "lock import:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s updated; run lock up to review and apply it\n", *file)
	return 0
}

func doctorCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "lockfamily.yaml", "the workspace's lockfamily.yaml")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	abs, err := filepath.Abs(*file)
	if err != nil {
		fmt.Fprintln(stderr, "lock doctor:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d := &family.Doctor{File: abs, State: stateDir(family.Project(filepath.Dir(abs))), Runtime: runtimeDir(), Root: "/",
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
	file := fs.String("file", "lockfamily.yaml", "the workspace's lockfamily.yaml")
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
	abs, err := filepath.Abs(*file)
	if err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	if err := family.AddSlack(abs, stateDir(family.Project(filepath.Dir(abs))), s, app, bot); err != nil {
		fmt.Fprintln(stderr, "lock add slack:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: slack enabled for %s; tokens stored with the hub's data, not in the workspace. Run lock up to review and apply.\n", *file, strings.Join(s.Users, ", "))
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
	file := fs.String("file", "lockfamily.yaml", "the workspace's lockfamily.yaml")
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
	abs, err := filepath.Abs(*file)
	if err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 1
	}
	if err := family.AddTelegram(abs, stateDir(family.Project(filepath.Dir(abs))), tg, tok); err != nil {
		fmt.Fprintln(stderr, "lock add telegram:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: telegram enabled for %d chat(s); the token is stored with the hub's data, not in the workspace. Run lock up to review and apply.\n", *file, len(tg.Chats))
	return 0
}
