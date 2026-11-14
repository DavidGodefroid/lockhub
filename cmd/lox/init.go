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
	"strings"
	"sync"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// initCmd is lox init: the hub of the project started alone, without a
// question; the data sources its files name are hints (lox add sets a lock
// up).
func initCmd(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml of the current directory)")
	hubImage := fs.String("hub-image", "", "the hub's image for a new lockfamily.yaml, ghcr.io/davidgodefroid/lockhub@sha256:<digest> (default: lockhub's latest signed release's)")
	review := fs.Bool("review", false, "lox run shows everything and asks, even for a hub with no lock (needs a terminal)")
	verbose := fs.Bool("v", false, "show cosign's and docker's own output (default: only when a step fails)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "lox init: unexpected arguments (flags only)")
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
	if *review && !terminal {
		fmt.Fprintln(stderr, "lox init: --review asks at a terminal; stdin is not one")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	in := bufio.NewReader(stdin)
	project := family.Project(ws)
	state := stateDir(project)
	rel := newReleases()
	user := sync.OnceValue(func() string { return hubUser(ctx, family.Exec{Stderr: io.Discard}) })
	newUp := func(out io.Writer, runErr io.Writer) *family.Up {
		return &family.Up{File: abs, State: state, Runtime: runtimeDir(), Facades: family.FacadeKeysDir(stateHome()),
			User: user(), Run: family.QuietExec{Verbose: *verbose, Stderr: runErr},
			In: in, Out: out, Review: *review}
	}
	ini := &loxinit.Init{
		Root: ws, Out: stdout, Terminal: terminal, Review: *review, HubImageGiven: *hubImage != "",
		Env: loxinit.Env{GOOS: runtime.GOOS, LookPath: exec.LookPath, DockerVersion: loxinit.RealDockerVersion,
			CosignVersion: func(ctx context.Context) (string, error) {
				return family.CosignVersion(ctx, family.Exec{Stderr: io.Discard})
			},
			Types: family.Types, UID: os.Getuid(),
			HostLogs: func() []string { return loxinit.HostLogDirs(runtime.GOOS, loxinit.RealIsDir) },
			SSHHosts: func() []loxinit.Source { return loxinit.SSHHosts(loxinit.UserSSHConfig()) }},
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
		Up: func(ctx context.Context) error { return newUp(stdout, stderr).Do(ctx) },
		Running: func(ctx context.Context) bool {
			m, err := consoles(ctx, project)
			return err == nil && m["lockhub"] != ""
		},
		// The same fingerprint lox up compares: its review, without the
		// apply and without a question.
		Unchanged: func(ctx context.Context) bool {
			u := newUp(io.Discard, io.Discard)
			u.Probe = true
			return u.Do(ctx) == nil && u.Same
		},
		Applied: func() (int, error) { return family.AppliedLocks(state) },
	}
	if err := ini.Do(ctx); err != nil {
		return failed(ctx, stderr, "init", err)
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

// indentWriter indents what pinning the hub's release prints under lox
// init's own line.
type indentWriter struct{ w io.Writer }

func (i indentWriter) Write(b []byte) (int, error) {
	if _, err := io.WriteString(i.w, "  "+string(b)); err != nil {
		return 0, err
	}
	return len(b), nil
}
