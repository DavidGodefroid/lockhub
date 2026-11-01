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
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxadd"
	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// vaultPathsFlag is the repeatable --vault-path INSTANCE=PATH. A bad
// value is noted, not refused: the flag package would quote it.
type vaultPathsFlag struct {
	m   map[string]string
	bad bool
}

func (f *vaultPathsFlag) String() string { return "" }
func (f *vaultPathsFlag) Set(v string) error {
	inst, p, ok := strings.Cut(v, "=")
	if !ok || inst == "" || p == "" {
		f.bad = true
		return nil
	}
	if f.m == nil {
		f.m = map[string]string{}
	}
	f.m[inst] = p
	return nil
}

// initCmd is lox init: the project's locks set up in one command.
func initCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml of the current directory)")
	yes := fs.Bool("yes", false, "answer lox init's questions from the flags and defaults (auto mode); lox up's review still asks at the terminal")
	manual := fs.Bool("manual", false, "the checklist instead of auto mode (interactive)")
	fs.Bool("prod", false, "production locks (each approval types the profile name)")
	cred := fs.String("credentials", "", "where each console gets its password: ask (it asks at its start, masked; default) or vault")
	var vault vaultPathsFlag
	fs.Var(&vault, "vault-path", "INSTANCE=PATH: the Vault path of that lock's login, with --credentials vault (repeatable)")
	tls := fs.String("tls", "", "locksql's TLS mode for a database whose files say none: disable, prefer, require, verify-ca or verify-full (default: disable on this machine, else verify-full)")
	fs.Bool("no-attach", false, "after lox up, do not attach to the consoles (answer them later with lox attach INSTANCE)")
	hubImage := fs.String("hub-image", "", "the hub's image for a new lockfamily.yaml, ghcr.io/davidgodefroid/lockhub@sha256:<digest> (default: lockhub's latest signed release's)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox init: unexpected arguments (flags only)")
		return 2
	}
	switch {
	case vault.bad:
		fmt.Fprintln(stderr, "lox init: --vault-path: want INSTANCE=PATH")
		return 2
	case *cred != "" && *cred != loxadd.CredAsk && *cred != loxadd.CredVault:
		fmt.Fprintln(stderr, "lox init: --credentials: want ask or vault (a password is never given on the command line)")
		return 2
	case *tls != "" && !slices.Contains(loxadd.TLSModes, *tls):
		fmt.Fprintln(stderr, "lox init: --tls: want one of", strings.Join(loxadd.TLSModes, ", "))
		return 2
	case *manual && *yes:
		fmt.Fprintln(stderr, "lox init: --manual is interactive; --yes runs auto mode")
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox init:", err)
		return 1
	}
	ws := family.Workspace(abs)
	fi, _ := stdin.Stat()
	terminal := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	in := bufio.NewReader(stdin)
	project := family.Project(ws)
	state := stateDir(project)
	rel := newReleases()
	ini := &loxinit.Init{
		Root: ws, Out: stdout, Terminal: terminal,
		Env: loxinit.Env{GOOS: runtime.GOOS, LookPath: exec.LookPath, DockerVersion: loxinit.RealDockerVersion,
			Types: family.Types, UID: os.Getuid()},
		Declared: func() ([]loxinit.Declared, error) { return declared(abs) },
		Hub: func(ctx context.Context) (bool, error) {
			img := *hubImage
			if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) && img == "" {
				var err error
				if img, err = pinRelease(ctx, rel, "lockhub", "", indentWriter{stdout}); err != nil {
					return false, err
				}
			}
			return family.InitHub(abs, img)
		},
		Up: func(ctx context.Context) error {
			r := family.Exec{Stderr: stderr}
			u := &family.Up{File: abs, State: state, Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
				User: hubUser(ctx, family.Exec{Stderr: io.Discard}), Run: r, In: in, Out: stdout}
			return u.Do(ctx)
		},
		Running: func(ctx context.Context) bool {
			m, err := consoles(ctx, project)
			return err == nil && m["lockhub"] != ""
		},
	}
	if err := ini.Do(ctx); err != nil {
		fmt.Fprintln(stderr, "lox init:", err)
		return 1
	}
	return 0
}

// declared are the locks of the lockfamily.yaml at path (none when it
// does not exist yet).
func declared(path string) ([]loxinit.Declared, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	c, err := family.Load(path)
	if err != nil {
		return nil, err
	}
	var out []loxinit.Declared
	for _, n := range c.Instances() {
		l := c.Locks[n]
		out = append(out, loxinit.Declared{Instance: n, Lock: l.Type, Profile: l.Profile})
	}
	return out, nil
}

// consoles are the containers of the workspace's compose project, by
// compose service.
func consoles(ctx context.Context, project string) (map[string]string, error) {
	out, err := exec.CommandContext(ctx, "docker", "ps", "--no-trunc", "--filter", "label=com.docker.compose.project="+project,
		"--format", `{{.Label "com.docker.compose.service"}} {{.ID}}`).Output()
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if svc, id, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			m[svc] = id
		}
	}
	return m, nil
}

// indentWriter indents what lox add prints under the lock lox init sets
// up.
type indentWriter struct{ w io.Writer }

func (i indentWriter) Write(b []byte) (int, error) {
	if _, err := io.WriteString(i.w, "  "+string(b)); err != nil {
		return 0, err
	}
	return len(b), nil
}
