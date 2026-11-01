package loxinit

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

var update = flag.Bool("update", false, "rewrite the golden screens")

// golden compares got with testdata/name, the project root written as
// /project.
func golden(t *testing.T, name, root, got string) {
	t.Helper()
	got = strings.ReplaceAll(got, root, "/project")
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (go test -run %s -update writes it)", err, t.Name())
	}
	if got != string(want) {
		t.Errorf("%s differs (go test -update rewrites it):\n--- got\n%s\n--- want\n%s", p, got, want)
	}
}

// endLine is lox init's last line, verbatim.
const endLine = "Ready. Run `lea` (or `claude` + `lox approve`). Add a source: `lox add locksql|lockmq|lockfile|lockhttp`."

// hubRef is a pinned hub image, as lox init writes it.
const hubRef = "ghcr.io/davidgodefroid/lockhub@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type harness struct {
	in   *Init
	out  bytes.Buffer
	hubs int
	ups  int
	// created is what Hub answers; running what Running answers.
	created, running bool
	decl             []Declared
}

func newHarness(root string) *harness {
	h := &harness{created: true}
	found := map[string]bool{"docker": true, "cosign": true, "lea": true, "locksql": true, "lockmq": true, "lockfile": true, "lockhttp": true}
	h.in = &Init{
		Root: root, Out: &h.out,
		Env: Env{GOOS: "linux", Types: []string{"locksql", "lockmq", "lockfile", "lockhttp"}, UID: 1000,
			LookPath: func(n string) (string, error) {
				if found[n] {
					return "/usr/bin/" + n, nil
				}
				return "", errors.New("not found")
			},
			DockerVersion: func(context.Context) (string, error) { return "29.0.0", nil }},
		Declared: func() ([]Declared, error) { return h.decl, nil },
		Hub:      func(context.Context) (bool, error) { h.hubs++; return h.created, nil },
		// The marker shows where lox up's own lines go.
		Up:      func(context.Context) error { h.ups++; h.out.WriteString("[lox up]\n"); return nil },
		Running: func(context.Context) bool { return h.running },
	}
	return h
}

// A fresh project: lox init writes the hub alone and runs lox up once;
// the sources its files name are hints, never a lock set up.
func TestInitHubOnly(t *testing.T) {
	root := shopProject(t)
	h := newHarness(root)
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	golden(t, "init-hub-only.golden", root, h.out.String())
	if h.hubs != 1 || h.ups != 1 {
		t.Errorf("hub %d, up %d: want once each", h.hubs, h.ups)
	}
	out := h.out.String()
	if !strings.HasSuffix(out, "\n"+endLine+"\n") {
		t.Errorf("the end line is not the last line:\n%s", out)
	}
	for _, w := range []string{
		"found: postgres on host.docker.internal:55432 (compose.yaml, .env) → `lox add locksql`",
		"found: rabbitmq on http://host.docker.internal:55672 (compose.yaml) → `lox add lockmq`",
		"found: mysql on inventory.internal:3307 (config/inventory.yaml) → `lox add locksql`",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("no hint %q in\n%s", w, out)
		}
	}
	for _, v := range []string{"profile add", "init claude", "doctor", "Plan", "Go on?"} {
		if strings.Contains(out, v) {
			t.Errorf("%q in lox init's output: it sets up no lock\n%s", v, out)
		}
	}
}

// lox init asks nothing: no input, no terminal, and it still writes the
// hub and runs lox up (whose first, zero-lock run asks nothing either).
func TestInitAsksNothing(t *testing.T) {
	root := shopProject(t)
	h := newHarness(root)
	h.in.Terminal = false
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if strings.Contains(h.out.String(), "?") {
		t.Errorf("a question in\n%s", h.out.String())
	}
	if h.ups != 1 {
		t.Errorf("up %d, want once", h.ups)
	}
}

// A re-run while the hub runs and lockfamily.yaml is unchanged runs no
// lox up and ends with the same line.
func TestInitRerunNoop(t *testing.T) {
	root := t.TempDir()
	h := newHarness(root)
	h.created, h.running = false, true
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.ups != 0 {
		t.Errorf("up %d on a re-run: want none", h.ups)
	}
	if !strings.HasSuffix(h.out.String(), "\n\n"+endLine+"\n") {
		t.Errorf("not the end line:\n%s", h.out.String())
	}
	// Not running (a reboot): lox up starts it again.
	h.running = false
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.ups != 1 {
		t.Errorf("up %d with the hub stopped: want once", h.ups)
	}
}

// A workspace whose lockfamily.yaml declares locks (the old multi-lock
// lox init): its bytes are kept, no launcher verb runs, and lox up
// reviews them at a terminal; without one, lox init says to run it.
func TestInitKeepsDeclaredLocks(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, ".lockfamily", "lockfamily.yaml")
	body := "version: 1\nhub:\n  image: " + hubRef + "\nlocks:\n  orders:\n    type: locksql\n    image: ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("1", 64) + "\n    profile: orders\n"
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	newDecl := func() *harness {
		h := newHarness(root)
		h.decl = []Declared{{Instance: "orders", Lock: "locksql", Profile: "orders"}}
		h.in.Hub = func(context.Context) (bool, error) { h.hubs++; return family.InitHub(file, hubRef) }
		return h
	}

	h := newDecl()
	h.in.Terminal = true
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	golden(t, "init-declared.golden", root, h.out.String())
	if h.ups != 1 {
		t.Errorf("up %d at a terminal: want once (its review asks)", h.ups)
	}
	if b, _ := os.ReadFile(file); string(b) != body {
		t.Errorf("lockfamily.yaml changed:\n%s", b)
	}

	h = newDecl()
	h.in.Terminal = false
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if h.ups != 0 {
		t.Errorf("up %d without a terminal: want none", h.ups)
	}
	for _, w := range []string{"lockfamily.yaml declares locks: run lox up at a terminal to review and start them", endLine} {
		if !strings.Contains(h.out.String(), w) {
			t.Errorf("no %q in\n%s", w, h.out.String())
		}
	}
	if b, _ := os.ReadFile(file); string(b) != body {
		t.Errorf("lockfamily.yaml changed:\n%s", b)
	}
}

// Prerequisites missing stop lox init before anything, with the command
// that installs them.
func TestInitPrereqsMissing(t *testing.T) {
	root := shopProject(t)
	h := newHarness(root)
	h.in.Env.GOOS = "darwin"
	h.in.Env.DockerVersion = func(context.Context) (string, error) { return "", errors.New("Cannot connect") }
	look := h.in.Env.LookPath
	h.in.Env.LookPath = func(n string) (string, error) {
		if n == "cosign" || n == "lea" {
			return "", errors.New("not found")
		}
		return look(n)
	}
	err := h.in.Do(context.Background())
	if err == nil || err.Error() != "prerequisites missing (above): nothing done" {
		t.Fatalf("err %v", err)
	}
	if h.hubs != 0 || h.ups != 0 {
		t.Errorf("hub %d, up %d: want nothing done", h.hubs, h.ups)
	}
	golden(t, "prereqs-missing-darwin.golden", root, h.out.String())
}

// A hub or lox up that fails ends lox init with its error, not the end
// line.
func TestInitStepFails(t *testing.T) {
	h := newHarness(t.TempDir())
	h.in.Hub = func(context.Context) (bool, error) {
		return false, errors.New("--hub-image: want ghcr.io/davidgodefroid/lockhub@sha256:<digest>")
	}
	if err := h.in.Do(context.Background()); err == nil || !strings.Contains(err.Error(), "--hub-image") || h.ups != 0 {
		t.Fatalf("err %v, up %d", err, h.ups)
	}
	h = newHarness(t.TempDir())
	h.in.Up = func(context.Context) error { return errors.New("compose up failed") }
	if err := h.in.Do(context.Background()); err == nil || strings.Contains(h.out.String(), "Ready.") {
		t.Fatalf("err %v\n%s", err, h.out.String())
	}
}

// No secret is ever written or printed: the whole flow over a project
// whose files hold one, with lockfamily.yaml written for real.
func TestInitNoSecretWritten(t *testing.T) {
	root := shopProject(t)
	file := filepath.Join(root, ".lockfamily", "lockfamily.yaml")
	h := newHarness(root)
	h.in.Hub = func(context.Context) (bool, error) { return family.InitHub(file, hubRef) }
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("lockfamily.yaml was not written: the check below proves nothing")
	}
	planted := map[string]bool{"compose.yaml": true, ".env": true, filepath.Join("config", "inventory.yaml"): true}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if planted[rel] {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s holds the secret", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.out.String(), secret) {
		t.Error("the secret was printed")
	}
}
