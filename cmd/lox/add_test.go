package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxadd"
)

type okRunner struct{ calls []string }

func (o *okRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	o.calls = append(o.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

// lox add without --image pins the lock's (and, for a new workspace,
// the hub's) latest release by digest, once cosign verified it, in
// .lockfamily/lockfamily.yaml.
func TestAddResolvesLatestSignedRelease(t *testing.T) {
	d := map[string]string{"locksql": strings.Repeat("a", 64), "lockhub": strings.Repeat("b", 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases"):
			w.Write([]byte(`[{"tag_name":"v1.2.3"}]`))
		case r.URL.Path == "/token":
			w.Write([]byte(`{"token":"t"}`))
		case strings.HasSuffix(r.URL.Path, "/manifests/1.2.3"):
			repo := strings.Split(r.URL.Path, "/")[3]
			w.Header().Set("Docker-Content-Digest", "sha256:"+d[repo])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cos := &okRunner{}
	old := newReleases
	newReleases = func() *family.Releases {
		return &family.Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: cos}
	}
	t.Cleanup(func() { newReleases = old })
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	wd, _ := os.Getwd()
	os.Chdir(ws)
	t.Cleanup(func() { os.Chdir(wd) })
	var out, errb bytes.Buffer
	if code := run([]string{"add", "locksql", "crm"}, devNull(t), &out, &errb); code != 0 {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	b, err := os.ReadFile(filepath.Join(ws, ".lockfamily", "lockfamily.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ghcr.io/davidgodefroid/locksql@sha256:" + d["locksql"], "ghcr.io/davidgodefroid/lockhub@sha256:" + d["lockhub"]} {
		if !strings.Contains(string(b), want) {
			t.Errorf("lockfamily.yaml lacks %s:\n%s", want, b)
		}
	}
	if len(cos.calls) != 2 || !strings.Contains(out.String(), "signature verified") {
		t.Errorf("cosign: %v\n%s", cos.calls, out.String())
	}
	if code := run([]string{"add", "locksql", "x", "--version", "v1", "--image", "y"}, devNull(t), &out, &errb); code != 2 {
		t.Error("--version and --image together accepted")
	}
	if code := run([]string{"add", "lockdb", "x"}, devNull(t), &out, &errb); code != 2 {
		t.Error("unknown type accepted")
	}
}

// fakeReleases serves release v1.2.3 of every repo, the plain image and
// its -vault variant by their digests, with cosign as a recording runner.
func fakeReleases(t *testing.T) (digests map[string]string, cos *okRunner) {
	t.Helper()
	digests = map[string]string{
		"locksql:1.2.3":       strings.Repeat("a", 64),
		"locksql:1.2.3-vault": strings.Repeat("c", 64),
		"lockhub:1.2.3":       strings.Repeat("b", 64),
		"lockfile:1.2.3":      strings.Repeat("d", 64),
		"locklog:1.2.3":       strings.Repeat("e", 64),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases"):
			w.Write([]byte(`[{"tag_name":"v1.2.3"}]`))
		case r.URL.Path == "/token":
			w.Write([]byte(`{"token":"t"}`))
		case len(parts) == 6 && parts[4] == "manifests" && digests[parts[3]+":"+parts[5]] != "":
			w.Header().Set("Docker-Content-Digest", "sha256:"+digests[parts[3]+":"+parts[5]])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	cos = &okRunner{}
	old := newReleases
	newReleases = func() *family.Releases {
		return &family.Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: cos}
	}
	t.Cleanup(func() { newReleases = old })
	return digests, cos
}

// verbFake is the launchers of a lox add test: it logs each verb and
// answers it as the verbs contract does.
type verbFake struct {
	calls [][]string
	// onProfileAdd runs during profile add, with the verb's context.
	onProfileAdd func(ctx context.Context)
}

func (f *verbFake) Verb(ctx context.Context, _, name string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	switch {
	case len(args) >= 2 && args[0] == "profile" && args[1] == "add":
		if f.onProfileAdd != nil {
			f.onProfileAdd(ctx)
			return nil, []byte("signal: killed"), -1, nil
		}
		return []byte(`{"lock":"` + name + `","profile":"orders","config":".` + name + `/config.toml","production":false,"credentials":"vault"}`), nil, 0, nil
	case len(args) >= 1 && args[0] == "version":
		return []byte(name + " launcher v0.13.1 (image x)\n" + name + " v0.13.1\n"), nil, 0, nil
	case len(args) >= 1 && args[0] == "doctor":
		return []byte(`{"lock":"` + name + `","ok":true,"fixed":[],"checks":[]}`), nil, 0, nil
	}
	return nil, nil, 0, nil
}

// addWorld is a scratch HOME, state and workspace, the fake launchers and
// a PATH holding only a fake lea.
func addWorld(t *testing.T) (ws, file string, verbs *verbFake) {
	t.Helper()
	dir, _ := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a link
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "lea"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	t.Setenv("PATH", bin)
	ws = filepath.Join(dir, "shop")
	os.MkdirAll(ws, 0o755)
	verbs = &verbFake{}
	old := addRunner
	addRunner = verbs
	t.Cleanup(func() { addRunner = old })
	return ws, filepath.Join(ws, ".lockfamily", "lockfamily.yaml"), verbs
}

// lox add TYPE --non-interactive asks nothing; with no terminal it stops
// once lockfamily.yaml declares the lock: the vault block, vault: true and
// the -vault image variant, lea's uid allowed.
func TestAddNonInteractiveDeclares(t *testing.T) {
	digests, _ := fakeReleases(t)
	ws, file, verbs := addWorld(t)
	var out, errb bytes.Buffer
	code := run([]string{"add", "locksql", "--non-interactive", "--file", file, "--host", "db.example.com", "--port", "55432",
		"--database", "orders", "--credentials", "vault", "--vault-path", "database/creds/orders",
		"--vault-address", "https://vault.example.com:8200", "--vault-namespace", "shop", "--name", "orders"}, devNull(t), &out, &errb)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, out.String(), errb.String())
	}
	if !strings.HasSuffix(out.String(), "run lox run at a terminal to review and start it\n") {
		t.Fatalf("output:\n%s", out.String())
	}
	if strings.Contains(out.String(), "lox add locksql: one database") {
		t.Fatalf("--non-interactive showed the form:\n%s", out.String())
	}
	c, err := family.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault == nil || c.Vault.Address != "https://vault.example.com:8200" || c.Vault.Namespace != "shop" {
		t.Fatalf("vault block = %+v", c.Vault)
	}
	l := c.Locks["orders"]
	if !l.Vault || l.Image != "ghcr.io/davidgodefroid/locksql@sha256:"+digests["locksql:1.2.3-vault"] || l.Profile != "orders" {
		t.Fatalf("lock orders = %+v", l)
	}
	if len(l.AllowedUIDs) != 1 || l.AllowedUIDs[0] != os.Getuid() {
		t.Fatalf("allowed_uids = %v, want lea's uid", l.AllowedUIDs)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), "vault: true") {
		t.Fatalf("lockfamily.yaml:\n%s", b)
	}
	want := []string{"locksql", "profile", "add", "--non-interactive", "--json", "--project", ws, "--profile", "orders",
		"--credentials", "vault", "--vault-path", "database/creds/orders",
		"--engine", "postgres", "--host", "db.example.com", "--port", "55432", "--database", "orders"}
	if len(verbs.calls) == 0 || !slices.Equal(verbs.calls[0], want) {
		t.Fatalf("profile add\n got %q\nwant %q", verbs.calls, want)
	}
	draft := filepath.Join(stateDir(family.Project(ws)), "add-locksql.json")
	if _, err := os.Stat(draft); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("draft left after success: %v", err)
	}
}

// lox add locklog (the guided form, no instance): its profile add on this
// host's logs (--only narrows it), init claude, its doctor (advisory: its
// --fix wires agents, nothing lox run needs), the lock declared with lea's
// uid allowed.
func TestAddLocklogNonInteractive(t *testing.T) {
	digests, _ := fakeReleases(t)
	ws, file, verbs := addWorld(t)
	var out, errb bytes.Buffer
	code := run([]string{"add", "locklog", "--non-interactive", "--file", file, "--only", "/var/log/nginx,/var/log/app", "--name", "web-logs"},
		devNull(t), &out, &errb)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, out.String(), errb.String())
	}
	var got []string
	for _, c := range verbs.calls {
		got = append(got, strings.Join(c, " "))
	}
	want := []string{
		"locklog profile add --non-interactive --json --project " + ws + " --profile web-logs --only /var/log/nginx,/var/log/app",
		"locklog init claude",
		"locklog doctor --json",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("verbs\n got %q\nwant %q", got, want)
	}
	c, err := family.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	l := c.Locks["web-logs"]
	if l.Type != "locklog" || l.Profile != "web-logs" || l.Image != "ghcr.io/davidgodefroid/locklog@sha256:"+digests["locklog:1.2.3"] || l.Vault {
		t.Fatalf("lock = %+v", l)
	}
	if len(l.AllowedUIDs) != 1 || l.AllowedUIDs[0] != os.Getuid() {
		t.Fatalf("allowed_uids = %v, want lea's uid", l.AllowedUIDs)
	}
	// --only takes absolute directories only.
	code = run([]string{"add", "locklog", "--non-interactive", "--file", file, "--only", "var/log", "--name", "x"}, devNull(t), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "only: absolute directories") {
		t.Fatalf("relative --only: code %d\n%s", code, errb.String())
	}
}

// A Ctrl-C while lox add applies rolls back, keeps the draft and exits
// 130, with no failure line: only the rollback's own message.
func TestAddInterruptedExits130(t *testing.T) {
	fakeReleases(t)
	ws, file, verbs := addWorld(t)
	verbs.onProfileAdd = func(ctx context.Context) {
		syscall.Kill(os.Getpid(), syscall.SIGINT)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("SIGINT did not cancel lox add's context")
		}
	}
	var out, errb bytes.Buffer
	code := run([]string{"add", "locksql", "--non-interactive", "--file", file, "--host", "db.example.com", "--name", "orders"}, devNull(t), &out, &errb)
	if code != 130 {
		t.Fatalf("code %d, want 130\n%s\n%s", code, out.String(), errb.String())
	}
	if !strings.HasPrefix(errb.String(), "lox add: interrupted: nothing kept: ") || strings.Count(errb.String(), "\n") != 1 {
		t.Fatalf("stderr = %q", errb.String())
	}
	if strings.Contains(out.String(), "failed") {
		t.Fatalf("an interrupt shown as a failure:\n%s", out.String())
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lockfamily.yaml left behind: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir(family.Project(ws)), "add-locksql.json")); err != nil {
		t.Fatalf("draft not kept: %v", err)
	}
}

// lox add lockfile --non-interactive takes an sftp source from flags:
// with a key file, or with auth password (the console asks for it at
// start) and no --key.
func TestAddNonInteractiveSFTP(t *testing.T) {
	for _, c := range []struct {
		name  string
		extra []string
		want  []string
	}{
		{"key", []string{"--key", "KEY"}, []string{"--auth", "key", "--key", "KEY"}},
		{"password", []string{"--auth", "password"}, []string{"--auth", "password"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			fakeReleases(t)
			ws, file, verbs := addWorld(t)
			key, known := filepath.Join(ws, "id_shop"), filepath.Join(ws, "known_hosts")
			os.WriteFile(key, []byte("not a real key\n"), 0o600)
			os.WriteFile(known, []byte("sftp.example.com ssh-ed25519 AAAA\n"), 0o644)
			args := []string{"add", "lockfile", "--non-interactive", "--file", file, "--source", "sftp", "--host", "sftp.example.com",
				"--user", "shop", "--known-hosts", known, "--base-dir", "inbox", "--name", "orders"}
			for _, a := range c.extra {
				args = append(args, strings.ReplaceAll(a, "KEY", key))
			}
			var out, errb bytes.Buffer
			if code := run(args, devNull(t), &out, &errb); code != 0 {
				t.Fatalf("code %d\n%s\n%s", code, out.String(), errb.String())
			}
			if !strings.HasSuffix(out.String(), "lock orders declared: run lox run at a terminal to review and start it\n") {
				t.Fatalf("output:\n%s", out.String())
			}
			want := []string{"lockfile", "profile", "add", "--non-interactive", "--json", "--project", ws, "--profile", "orders",
				"--credentials", "ask", "--source", "sftp", "--host", "sftp.example.com", "--port", "22", "--user", "shop"}
			for _, a := range c.want {
				want = append(want, strings.ReplaceAll(a, "KEY", key))
			}
			want = append(want, "--known-hosts", known, "--base-dir", "inbox")
			if len(verbs.calls) == 0 || !slices.Equal(verbs.calls[0], want) {
				t.Fatalf("profile add\n got %q\nwant %q", verbs.calls, want)
			}
		})
	}
}

// addDefaults proposes the values of the only detected source of the
// type; with several, they are hints only.
func TestAddDefaultsDetection(t *testing.T) {
	_, _, _ = addWorld(t)
	for _, c := range []struct {
		name, compose string
		hints         int
		source        bool
	}{
		{"one", "services:\n  orders:\n    image: postgres:17\n    ports: [\"55432:5432\"]\n  mq:\n    image: rabbitmq:4.1.8-management\n", 1, true},
		{"several", "services:\n  orders:\n    image: postgres:17\n    ports: [\"55432:5432\"]\n  inventory:\n    image: postgres:17\n    ports: [\"55433:5432\"]\n", 2, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ws := t.TempDir()
			os.WriteFile(filepath.Join(ws, "compose.yaml"), []byte(c.compose), 0o644)
			file := filepath.Join(ws, ".lockfamily", "lockfamily.yaml")
			var errb bytes.Buffer
			d, hints, err := addDefaults(file, ws, "locksql", filepath.Join(ws, "none.json"), false, &errb)
			if err != nil {
				t.Fatal(err)
			}
			if len(hints) != c.hints || (d.Source != nil) != c.source {
				t.Fatalf("hints %d, source %+v", len(hints), d.Source)
			}
			if c.source && (d.Source.Service != "orders" || d.Source.Port != 55432) {
				t.Fatalf("source = %+v", d.Source)
			}
			if errb.Len() != 0 {
				t.Fatalf("stderr = %q", errb.String())
			}
		})
	}
}

// --non-interactive never offers the draft of an earlier try (nor any
// detected source); the guided form does.
func TestAddDefaultsNonInteractiveIgnoresDraft(t *testing.T) {
	_, _, _ = addWorld(t)
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "compose.yaml"), []byte("services:\n  orders:\n    image: postgres:17\n"), 0o644)
	file := filepath.Join(ws, ".lockfamily", "lockfamily.yaml")
	draft := filepath.Join(t.TempDir(), "add-locksql.json")
	if err := loxadd.SaveDraft(draft, loxadd.Answers{"host": "db.example.com", "name": "orders"}); err != nil {
		t.Fatal(err)
	}
	d, hints, err := addDefaults(file, ws, "locksql", draft, true, io.Discard)
	if err != nil || len(d.Draft) != 0 || d.Source != nil || len(hints) != 0 {
		t.Fatalf("non-interactive: %+v %v %v", d, hints, err)
	}
	d, _, err = addDefaults(file, ws, "locksql", draft, false, io.Discard)
	if err != nil || d.Draft["host"] != "db.example.com" || d.Source == nil {
		t.Fatalf("guided: %+v %v", d, err)
	}
}

// A project file detection could not read is said in one line, naming the
// file only.
func TestAddDefaultsDetectionWarning(t *testing.T) {
	_, _, _ = addWorld(t)
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, ".env"), bytes.Repeat([]byte("# shop\n"), 50000), 0o644)
	var errb bytes.Buffer
	if _, _, err := addDefaults(filepath.Join(ws, ".lockfamily", "lockfamily.yaml"), ws, "locksql", filepath.Join(ws, "none.json"), false, &errb); err != nil {
		t.Fatal(err)
	}
	if errb.String() != "lox add: hints: .env: over 256 KiB, not read\n" {
		t.Fatalf("stderr = %q", errb.String())
	}
}

// The two-argument form still only declares the lock, as before.
func TestAddOldFormStillDeclares(t *testing.T) {
	_, file, verbs := addWorld(t)
	var out, errb bytes.Buffer
	if code := run([]string{"add", "locksql", "crm", "--file", file, "--image", sqlImg, "--hub-image", hubImg}, devNull(t), &out, &errb); code != 0 {
		t.Fatalf("code %d\n%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "lock crm (locksql) declared; run lox run to review and start it") {
		t.Fatalf("output:\n%s", out.String())
	}
	if len(verbs.calls) != 0 {
		t.Fatalf("the declare-only form ran launchers: %q", verbs.calls)
	}
	c, err := family.Load(file)
	if err != nil || c.Locks["crm"].Image != sqlImg {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestLegacyFileWarns(t *testing.T) {
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(ws, "lockfamily.yaml"), []byte("version: 1\n"), 0o644)
	wd, _ := os.Getwd()
	os.Chdir(ws)
	t.Cleanup(func() { os.Chdir(wd) })
	var errb bytes.Buffer
	f, err := lockFile("", &errb)
	if err != nil || f != filepath.Join(ws, "lockfamily.yaml") || !strings.Contains(errb.String(), "lea's agents can write") {
		t.Errorf("%s %v %q", f, err, errb.String())
	}
}
