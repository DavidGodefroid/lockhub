package loxadd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

var (
	testHubImage = "ghcr.io/davidgodefroid/lockhub@sha256:" + strings.Repeat("a", 64)
	testSQLImage = "ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("b", 64)
	testSQLVault = "ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("c", 64)
)

// applyFake is the launcher and lox up of an Apply test: it logs every
// call in order.
type applyFake struct {
	log []string
	// exists: profile add answers that the profile is there already.
	exists bool
	// initFails: init claude fails.
	initFails bool
	// killProfileAdd is called by profile add, which then ends as a
	// launcher killed by its context does.
	killProfileAdd func()
}

func (f *applyFake) Verb(_ context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
	f.log = append(f.log, name+" "+strings.Join(args[:min(2, len(args))], " "))
	switch {
	case len(args) >= 2 && args[0] == "profile" && args[1] == "add":
		if f.killProfileAdd != nil {
			f.killProfileAdd()
			return nil, []byte("signal: killed"), -1, nil
		}
		if f.exists {
			return []byte(`{"lock":"` + name + `","code":"exists","error":"profile orders exists"}`), nil, 1, nil
		}
		cfg := filepath.Join(dir, "."+name, "config.toml")
		if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
			return nil, nil, -1, err
		}
		fh, err := os.OpenFile(cfg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, -1, err
		}
		fh.WriteString("\n[profiles.orders]\nhost = \"db.example.com\"\n")
		fh.Close()
		return []byte(`{"lock":"` + name + `","profile":"orders","config":".` + name + `/config.toml","production":false,"credentials":"ask"}`), nil, 0, nil
	case len(args) >= 2 && args[0] == "init":
		if f.initFails {
			return nil, []byte("init claude: boom"), 1, nil
		}
		return nil, nil, 0, nil
	case len(args) >= 1 && args[0] == "version":
		return []byte(name + " launcher v0.13.1 (image x)\n" + name + " v0.13.1\n"), nil, 0, nil
	case len(args) >= 1 && args[0] == "doctor":
		return []byte(`{"lock":"` + name + `","ok":true,"fixed":[],"checks":[{"check":"profile","status":"ok","detail":"fine"}]}`), nil, 0, nil
	}
	return nil, []byte("unexpected verb"), 2, nil
}

type applyWorld struct {
	root, file, draft string
	out               bytes.Buffer
	fake              *applyFake
	steps             *Steps
}

func newApplyWorld(t *testing.T) *applyWorld {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	w := &applyWorld{root: t.TempDir(), fake: &applyFake{}}
	w.file = filepath.Join(w.root, ".lockfamily", "lockfamily.yaml")
	w.draft = filepath.Join(t.TempDir(), "state", "add-locksql.json")
	f := w.fake
	w.steps = &Steps{
		Root: w.root, File: w.file, DraftPath: w.draft, Run: f, Out: &w.out, Terminal: true,
		PinImage: func(_ context.Context, lock string, vault bool) (string, error) {
			if vault {
				f.log = append(f.log, "pin "+lock+" vault")
				return testSQLVault, nil
			}
			f.log = append(f.log, "pin "+lock)
			return testSQLImage, nil
		},
		PinHub: func(context.Context) (string, error) {
			f.log = append(f.log, "pin hub")
			return testHubImage, nil
		},
		Up: func(_ context.Context, focus string) error {
			f.log = append(f.log, "up "+focus)
			return nil
		},
		Attach: func(_ context.Context, name string) error {
			f.log = append(f.log, "attach "+name)
			return nil
		},
		ConsoleAlive: func(context.Context, string) bool { return true },
	}
	return w
}

func sqlAnswers(cred string) Answers {
	return Answers{"engine": "postgres", "host": "db.example.com", "port": "5432", "user": "", "database": "orders",
		"production": "n", "tls": "verify-full", "credentials": cred, "name": "orders"}
}

func mustBuild(t *testing.T, a Answers) Lock {
	t.Helper()
	l, err := Build("locksql", a)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func readOr(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeTestFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

const shopFamily = "version: 1\nhub:\n  image: ghcr.io/davidgodefroid/lockhub@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n# the shop lock\nlocks:\n    shop:\n        type: locksql\n        image: ghcr.io/davidgodefroid/locksql@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"

func TestApplyOrder(t *testing.T) {
	w := newApplyWorld(t)
	a := sqlAnswers(CredAsk)
	if err := SaveDraft(w.draft, a); err != nil {
		t.Fatal(err)
	}
	if err := w.steps.Apply(context.Background(), mustBuild(t, a), a); err != nil {
		t.Fatalf("Apply: %v\n%s", err, w.out.String())
	}
	want := []string{"locksql profile add", "locksql init claude", "locksql version", "locksql doctor --fix",
		"pin locksql", "pin hub", "up orders", "attach orders"}
	if !slices.Equal(w.fake.log, want) {
		t.Fatalf("order\n got %q\nwant %q", w.fake.log, want)
	}
	c, err := family.Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Locks["orders"]; l.Type != "locksql" || l.Image != testSQLImage || l.Profile != "orders" || l.Vault {
		t.Fatalf("lock orders = %+v", l)
	}
	if _, err := os.Stat(w.draft); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("draft kept after success: %v", err)
	}
	for _, s := range []string{"profile add: profile orders written to .locksql/config.toml (credentials ask)",
		"init claude: the agent's files written", "doctor --fix: 1 ok, 0 warning(s), 0 failed", "lock orders declared"} {
		if !strings.Contains(w.out.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, w.out.String())
		}
	}
	notice := strings.Index(w.out.String(), "locksql doctor --fix also wires your installed agents for your account")
	if notice < 0 || notice > strings.Index(w.out.String(), "doctor --fix: 1 ok") {
		t.Errorf("no notice before the doctor step:\n%s", w.out.String())
	}
}

func TestApplyDeclinedRollsBack(t *testing.T) {
	w := newApplyWorld(t)
	cfg := filepath.Join(w.root, ".locksql", "config.toml")
	shopProfile := "# kept as typed\n[profiles.shop]\nhost = \"shop.example.com\"   # spaces kept\n"
	writeTestFile(t, cfg, shopProfile)
	writeTestFile(t, w.file, shopFamily)
	w.steps.Up = func(context.Context, string) error {
		if !strings.Contains(readOr(t, cfg), "[profiles.orders]") || !strings.Contains(readOr(t, w.file), "orders:") {
			t.Fatal("up before the profile and the lock were written")
		}
		return family.ErrNotConfirmed
	}
	a := sqlAnswers(CredAsk)
	err := w.steps.Apply(context.Background(), mustBuild(t, a), a)
	if !errors.Is(err, ErrNothingKept) || !errors.Is(err, family.ErrNotConfirmed) {
		t.Fatalf("err = %v, want ErrNothingKept wrapping the decline", err)
	}
	const msg = "nothing kept: .locksql/config.toml and .lockfamily/lockfamily.yaml are as before; lox add locksql offers the same answers again"
	if err.Error() != msg {
		t.Fatalf("message\n got %q\nwant %q", err.Error(), msg)
	}
	if got := readOr(t, cfg); got != shopProfile {
		t.Fatalf("config.toml not restored:\n%s", got)
	}
	if got := readOr(t, w.file); got != shopFamily {
		t.Fatalf("lockfamily.yaml not restored:\n%s", got)
	}
	d, err := LoadDraft(w.draft)
	if err != nil {
		t.Fatal(err)
	}
	if d["name"] != "orders" || d["host"] != "db.example.com" {
		t.Fatalf("draft = %v", d)
	}
	if slices.Contains(w.fake.log, "attach orders") {
		t.Fatal("attached after a decline")
	}
}

func TestApplyInterruptedRollsBack(t *testing.T) {
	w := newApplyWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.steps.Up = func(ctx context.Context, _ string) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	a := sqlAnswers(CredAsk)
	err := w.steps.Apply(ctx, mustBuild(t, a), a)
	if !errors.Is(err, ErrNothingKept) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrNothingKept wrapping the interrupt", err)
	}
	if !strings.HasPrefix(err.Error(), "interrupted: nothing kept: ") {
		t.Fatalf("message = %q", err.Error())
	}
	// Neither file existed: both are gone, and the directories made for
	// them too.
	for _, p := range []string{filepath.Join(w.root, ".locksql", "config.toml"), w.file,
		filepath.Join(w.root, ".locksql"), filepath.Join(w.root, ".lockfamily")} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind (%v)", p, err)
		}
	}
	if d, err := LoadDraft(w.draft); err != nil || d["name"] != "orders" {
		t.Fatalf("draft = %v, %v", d, err)
	}
}

// assertInterrupted: an interrupt rolled back, wraps context.Canceled and
// printed no failure line.
func assertInterrupted(t *testing.T, w *applyWorld, err error) {
	t.Helper()
	if !errors.Is(err, ErrNothingKept) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrNothingKept wrapping context.Canceled", err)
	}
	if !strings.HasPrefix(err.Error(), "interrupted: nothing kept: ") {
		t.Fatalf("message = %q", err.Error())
	}
	// A failure line is "STEP failed: ..." or "STEP failed (CODE): ...".
	if regexp.MustCompile(`failed(?: \([a-z]+\))?: `).MatchString(w.out.String()) {
		t.Fatalf("an interrupt shown as a failure:\n%s", w.out.String())
	}
	for _, p := range []string{filepath.Join(w.root, ".locksql", "config.toml"), w.file} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind (%v)", p, err)
		}
	}
	if slices.Contains(w.fake.log, "up orders") {
		t.Fatal("up after an interrupt")
	}
}

func TestApplyInterruptedDuringProfileAdd(t *testing.T) {
	w := newApplyWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.fake.killProfileAdd = cancel
	a := sqlAnswers(CredAsk)
	assertInterrupted(t, w, w.steps.Apply(ctx, mustBuild(t, a), a))
}

func TestApplyInterruptedDuringPin(t *testing.T) {
	w := newApplyWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.steps.PinImage = func(context.Context, string, bool) (string, error) {
		cancel()
		return "", errors.New("cosign verify: signal: killed")
	}
	a := sqlAnswers(CredAsk)
	assertInterrupted(t, w, w.steps.Apply(ctx, mustBuild(t, a), a))
}

// A Ctrl-C that lands once the last declare step succeeded, with no
// terminal (no lox up to notice it), still rolls back as an interrupt.
func TestApplyInterruptedAfterDeclareNoTerminal(t *testing.T) {
	w := newApplyWorld(t)
	w.steps.Terminal = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.steps.PinHub = func(context.Context) (string, error) {
		cancel()
		return testHubImage, nil
	}
	a := sqlAnswers(CredAsk)
	assertInterrupted(t, w, w.steps.Apply(ctx, mustBuild(t, a), a))
	if strings.Contains(w.out.String(), "run lox up at a terminal") {
		t.Fatalf("declared after an interrupt:\n%s", w.out.String())
	}
	if d, err := LoadDraft(w.draft); err != nil || d["name"] != "orders" {
		t.Fatalf("draft = %v, %v", d, err)
	}
}

func TestApplyRestoreFailureSaysSo(t *testing.T) {
	w := newApplyWorld(t)
	writeTestFile(t, w.file, shopFamily)
	w.steps.Up = func(context.Context, string) error {
		// The file is gone and its directory replaced by a file: neither
		// the restore's temporary file nor the file itself can be written.
		if err := os.RemoveAll(filepath.Dir(w.file)); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Dir(w.file), "x")
		return family.ErrNotConfirmed
	}
	a := sqlAnswers(CredAsk)
	err := w.steps.Apply(context.Background(), mustBuild(t, a), a)
	if err == nil || errors.Is(err, ErrNothingKept) {
		t.Fatalf("err = %v, want a not-restored error, not ErrNothingKept", err)
	}
	if !errors.Is(err, family.ErrNotConfirmed) {
		t.Fatalf("err = %v, want the cause wrapped", err)
	}
	if !strings.Contains(err.Error(), ".lockfamily/lockfamily.yaml could not be restored (") {
		t.Fatalf("message = %q", err.Error())
	}
}

func TestApplyRelKeepsDotDotNames(t *testing.T) {
	s := &Steps{Root: "/p"}
	if got := s.rel("/p/..cfg/config.toml"); got != "..cfg/config.toml" {
		t.Fatalf("rel = %q", got)
	}
	if got := s.rel("/q/lockfamily.yaml"); got != "/q/lockfamily.yaml" {
		t.Fatalf("rel outside = %q", got)
	}
}

func TestApplyInitFailureRollsBack(t *testing.T) {
	w := newApplyWorld(t)
	w.fake.initFails = true
	a := sqlAnswers(CredAsk)
	err := w.steps.Apply(context.Background(), mustBuild(t, a), a)
	if !errors.Is(err, ErrNothingKept) || strings.HasPrefix(err.Error(), "interrupted") {
		t.Fatalf("err = %v", err)
	}
	if got := readOr(t, filepath.Join(w.root, ".locksql", "config.toml")); got != "<absent>" {
		t.Fatalf("profile kept:\n%s", got)
	}
	if !strings.Contains(w.out.String(), "init claude failed (failed): init claude: boom") {
		t.Fatalf("output:\n%s", w.out.String())
	}
	if slices.Contains(w.fake.log, "up orders") {
		t.Fatal("up after a failed step")
	}
}

func TestApplyProfileExistsKept(t *testing.T) {
	w := newApplyWorld(t)
	w.fake.exists = true
	a := sqlAnswers(CredAsk)
	if err := w.steps.Apply(context.Background(), mustBuild(t, a), a); err != nil {
		t.Fatalf("Apply: %v\n%s", err, w.out.String())
	}
	if !strings.Contains(w.out.String(), "profile add: profile orders is there already: kept as it is") {
		t.Fatalf("output:\n%s", w.out.String())
	}
	if !slices.Contains(w.fake.log, "up orders") || !slices.Contains(w.fake.log, "attach orders") {
		t.Fatalf("log = %q", w.fake.log)
	}
}

func TestApplyNoTerminalStopsBeforeUp(t *testing.T) {
	w := newApplyWorld(t)
	w.steps.Terminal = false
	a := sqlAnswers(CredAsk)
	if err := w.steps.Apply(context.Background(), mustBuild(t, a), a); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if slices.Contains(w.fake.log, "up orders") || slices.Contains(w.fake.log, "attach orders") {
		t.Fatalf("log = %q", w.fake.log)
	}
	if !strings.HasSuffix(w.out.String(), "lock orders declared: run lox up at a terminal to review and start it\n") {
		t.Fatalf("output:\n%s", w.out.String())
	}
	if !strings.Contains(readOr(t, w.file), "orders:") {
		t.Fatal("lock not declared")
	}
}

func TestApplyVaultPinsVariant(t *testing.T) {
	w := newApplyWorld(t)
	a := sqlAnswers(CredVault)
	a["vault-path"] = "database/creds/orders"
	a["vault-address"] = "https://vault.example.com:8200"
	a["vault-namespace"] = "shop"
	if err := w.steps.Apply(context.Background(), mustBuild(t, a), a); err != nil {
		t.Fatalf("Apply: %v\n%s", err, w.out.String())
	}
	if !slices.Contains(w.fake.log, "pin locksql vault") || slices.Contains(w.fake.log, "pin locksql") {
		t.Fatalf("log = %q", w.fake.log)
	}
	if !slices.Contains(w.fake.log, "attach orders") {
		t.Fatalf("no attach for vault: %q", w.fake.log)
	}
	c, err := family.Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Locks["orders"]; l.Image != testSQLVault || !l.Vault {
		t.Fatalf("lock = %+v", l)
	}
	if c.Vault == nil || c.Vault.Address != "https://vault.example.com:8200" || c.Vault.Namespace != "shop" {
		t.Fatalf("vault = %+v", c.Vault)
	}
}

func TestApplyConsoleStoppedAfterVaultSaysHow(t *testing.T) {
	w := newApplyWorld(t)
	w.steps.Attach = func(context.Context, string) error { return errors.New("exit status 1") }
	w.steps.ConsoleAlive = func(context.Context, string) bool { return false }
	a := sqlAnswers(CredVault)
	a["vault-path"] = "database/creds/orders"
	a["vault-address"] = "https://vault.example.com:8200"
	err := w.steps.Apply(context.Background(), mustBuild(t, a), a)
	const msg = "lock orders is declared and its console stopped (above): for Vault, check the address and token (lox vault set --address URL, then lox up); else lox up, then lox attach orders"
	if err == nil || err.Error() != msg {
		t.Fatalf("err = %v\nwant %s", err, msg)
	}
	if errors.Is(err, ErrNothingKept) {
		t.Fatal("rolled back after up")
	}
	if !strings.Contains(readOr(t, w.file), "orders:") || readOr(t, filepath.Join(w.root, ".locksql", "config.toml")) == "<absent>" {
		t.Fatal("lock or profile undone")
	}

	// A console still running was detached from: no error.
	w2 := newApplyWorld(t)
	w2.steps.Attach = func(context.Context, string) error { return errors.New("read escape sequence") }
	if err := w2.steps.Apply(context.Background(), mustBuild(t, a), a); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if !strings.Contains(w2.out.String(), "detached from orders") {
		t.Fatalf("output:\n%s", w2.out.String())
	}
}

func TestDraftHoldsNoSecret(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "state", "add-locksql.json")
	const secret = "s3cretpw"
	a := Answers{"name": "orders", "host": "db.example.com", "engine": "postgres",
		"user": "app:" + secret, "url": "http://guest:" + secret + "@mq.example.com:15672",
		"vault-address": "https://vault.example.com:8200?password=" + secret}
	if err := SaveDraft(path, a); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("draft mode %v, want 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), secret) {
		t.Fatalf("draft holds the secret:\n%s", b)
	}
	d, err := LoadDraft(path)
	if err != nil {
		t.Fatal(err)
	}
	if d["name"] != "orders" || d["host"] != "db.example.com" || d["engine"] != "postgres" {
		t.Fatalf("draft lost plain answers: %v", d)
	}

	// An older draft written with a secret in it: LoadDraft drops it, so
	// no default ever shows it.
	raw, _ := json.Marshal(a)
	writeTestFile(t, path, string(raw))
	d, err = LoadDraft(path)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range d {
		if strings.Contains(v, secret) {
			t.Fatalf("LoadDraft kept %s", k)
		}
	}
	if d["name"] != "orders" {
		t.Fatalf("draft = %v", d)
	}

	// No draft yet: no answers, no error.
	if d, err := LoadDraft(filepath.Join(t.TempDir(), "none.json")); err != nil || len(d) != 0 {
		t.Fatalf("missing draft: %v, %v", d, err)
	}
}

func TestApplyLeaHint(t *testing.T) {
	const hint = "lea gets lock orders at its next start: lea stop, then lea\n"
	a := sqlAnswers(CredAsk)
	for name, tc := range map[string]struct {
		running func(context.Context) bool
		want    bool
	}{
		"lea running": {func(context.Context) bool { return true }, true},
		"lea stopped": {func(context.Context) bool { return false }, false},
		"no detector": {nil, false},
	} {
		w := newApplyWorld(t)
		w.steps.LeaRunning = tc.running
		if tc.running != nil {
			running := tc.running
			w.steps.LeaRunning = func(ctx context.Context) bool {
				w.fake.log = append(w.fake.log, "lea check")
				return running(ctx)
			}
		}
		if err := w.steps.Apply(context.Background(), mustBuild(t, a), a); err != nil {
			t.Fatalf("%s: Apply: %v", name, err)
		}
		if tc.want {
			up, check, attach := slices.Index(w.fake.log, "up orders"), slices.Index(w.fake.log, "lea check"), slices.Index(w.fake.log, "attach orders")
			if up < 0 || !(up < check && check < attach) {
				t.Errorf("%s: order = %q, want up, lea check, attach", name, w.fake.log)
			}
		}
		if got := strings.Contains(w.out.String(), hint); got != tc.want {
			t.Errorf("%s: hint shown = %v, want %v\n%s", name, got, tc.want, w.out.String())
		}
	}
}
