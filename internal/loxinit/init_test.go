package loxinit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

// fakeRunner answers the launcher verbs as the released launchers do,
// and records every call.
type fakeRunner struct {
	calls []string
	// answer gives a verb's stdout, stderr and status; nil: success.
	answer func(lock string, args []string) (string, string, int)
}

func (f *fakeRunner) Verb(_ context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.answer != nil {
		if o, e, c := f.answer(name, args); o != "" || e != "" || c != 0 {
			return []byte(o), []byte(e), c, nil
		}
	}
	switch args[0] {
	case "profile":
		prof := args[slices.Index(args, "--profile")+1]
		cred := ""
		if i := slices.Index(args, "--credentials"); i >= 0 {
			cred = `,"credentials":"` + args[i+1] + `"`
		}
		return []byte(fmt.Sprintf("Profile %s written.\n{\"lock\":%q,\"profile\":%q,\"config\":%q,\"production\":%v%s}\n",
			prof, name, prof, filepath.Join(dir, "."+name, "config.toml"), slices.Contains(args, "--production"), cred)), nil, 0, nil
	case "version":
		// The releases whose doctor --fix leaves the lock's directory as
		// lox up reads it.
		v := map[string]string{"locksql": "0.13.1", "lockmq": "0.6.1"}[name]
		if v == "" {
			v = "0.7.0"
		}
		return []byte(fmt.Sprintf("%s launcher %s (image ghcr.io/davidgodefroid/%s@sha256:0)\n%s v%s\n", name, v, name, name, v)), nil, 0, nil
	case "doctor":
		fixed := "[]"
		if slices.Contains(args, "--fix") {
			fixed = `["chmod go-w .` + name + `/config.toml"]`
		}
		return []byte(`{"lock":"` + name + `","ok":false,"fixed":` + fixed + `,"checks":[{"check":"config","status":"ok","detail":"ok"},{"check":"console","status":"warn","detail":"not running"},{"check":"agents","status":"warn","detail":"not wired: codex","fix":"` + name + ` doctor --fix wires it"},{"check":"project","status":"fail","detail":"owned by you","fix":"chown"}]}`), nil, 1, nil
	}
	return []byte("created .mcp.json\n"), nil, 0, nil
}

type harness struct {
	in       *Init
	out      bytes.Buffer
	run      *fakeRunner
	added    []Planned
	removed  []string
	ups      int
	attached []string
	decl     []Declared
	// after are the consoles after lox up (before: none).
	after map[string]string
}

func newHarness(t *testing.T, root, input string) *harness {
	h := &harness{run: &fakeRunner{}, after: map[string]string{}}
	found := map[string]bool{"docker": true, "cosign": true, "lea": true, "locksql": true, "lockmq": true, "lockfile": true, "lockhttp": true}
	h.in = &Init{
		Root: root, Run: h.run, In: bufio.NewReader(strings.NewReader(input)), Out: &h.out, Terminal: true,
		Env: Env{GOOS: "linux", Types: []string{"locksql", "lockmq", "lockfile", "lockhttp"}, UID: 1000,
			LookPath: func(n string) (string, error) {
				if found[n] {
					return "/usr/bin/" + n, nil
				}
				return "", errors.New("not found")
			},
			DockerVersion: func(context.Context) (string, error) { return "29.0.0", nil }},
		Declared: func() ([]Declared, error) { return h.decl, nil },
		AddLock: func(_ context.Context, p Planned) error {
			h.added = append(h.added, p)
			h.after["lock-"+p.Instance] = "id-" + p.Instance
			return nil
		},
		RemoveLock: func(n string) error { h.removed = append(h.removed, n); return nil },
		Up:         func(context.Context) error { h.ups++; return nil },
		Consoles: func(context.Context) (map[string]string, error) {
			if h.ups == 0 {
				m := map[string]string{}
				for _, d := range h.decl {
					m["lock-"+d.Instance] = "id-" + d.Instance
				}
				return m, nil
			}
			m := map[string]string{"lockhub": "id-hub"}
			for _, d := range h.decl {
				m["lock-"+d.Instance] = "id-" + d.Instance
			}
			for k, v := range h.after {
				m[k] = v
			}
			return m, nil
		},
		Attach: func(_ context.Context, n string) error { h.attached = append(h.attached, n); return nil },
	}
	return h
}

func (h *harness) verbs(lock string) []string {
	var out []string
	for _, c := range h.run.calls {
		if strings.HasPrefix(c, lock+" ") {
			out = append(out, c)
		}
	}
	return out
}

// Auto mode with --yes: one lock per source, each lock's verbs from the
// project root, lox add, lox up, then each new console attached.
func TestAutoYes(t *testing.T) {
	root := shopProject(t)
	h := newHarness(t, root, "")
	h.in.Yes = true
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	golden(t, "auto-yes.golden", root, h.out.String())
	want := []string{
		"locksql profile add --non-interactive --json --project " + root + " --profile db --credentials ask --engine postgres --host host.docker.internal --port 55432 --user shop --database shop --tls disable",
		"locksql init claude",
		"locksql version",
		"locksql doctor --fix --yes --json",
		"lockmq profile add --non-interactive --json --project " + root + " --profile mq --credentials ask --url http://host.docker.internal:55672 --user orders --vhost orders --amqp-url amqp://host.docker.internal:55673",
		"lockmq init claude",
		"lockmq version",
		"lockmq doctor --fix --yes --json",
		"locksql profile add --non-interactive --json --project " + root + " --profile stock --credentials ask --engine mysql --host inventory.internal --port 3307 --user stock --database stock --tls verify-full",
		"locksql init claude",
		"locksql doctor --fix --yes --json",
	}
	if strings.Join(h.run.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("verbs:\n%s\nwant:\n%s", strings.Join(h.run.calls, "\n"), strings.Join(want, "\n"))
	}
	if len(h.added) != 3 || h.ups != 1 || strings.Join(h.attached, ",") != "db,mq,stock" {
		t.Errorf("added %d, ups %d, attached %q", len(h.added), h.ups, h.attached)
	}
	for _, p := range h.added {
		if !slices.Equal(p.AllowedUIDs, []int{1000}) {
			t.Errorf("%s: allowed_uids %v, want lea's uid", p.Instance, p.AllowedUIDs)
		}
	}
}

// doctor --fix runs only with a launcher and an image at or after the
// release whose --fix leaves the lock's directory as lox up reads it;
// older (or unknown), lox init runs the advisory doctor and says why. A
// launcher from a clone ("dev") is judged by its image.
func TestDoctorFixNeedsFixedLauncher(t *testing.T) {
	for _, c := range []struct {
		name     string
		version  string // locksql version's stdout
		code     int
		fix      bool
		wantNote string
	}{
		{"fixed release", "locksql launcher 0.13.1 (image x)\nlocksql v0.13.1\n", 0, true, ""},
		{"later release", "locksql launcher 0.14.0 (image x)\nlocksql v0.14.0\n", 0, true, ""},
		{"clone, fixed image", "locksql launcher dev (image x)\nlocksql v0.13.1\n", 0, true, ""},
		{"older release", "locksql launcher 0.13.0 (image x)\nlocksql v0.13.0\n", 0, false, "launcher 0.13.0 is older than v0.13.1"},
		{"clone, older image", "locksql launcher dev (image x)\nlocksql v0.13.0\n", 0, false, "image v0.13.0 is older than v0.13.1"},
		{"pre-release image", "locksql launcher 0.13.1 (image x)\nlocksql v0.13.1-rc1\n", 0, false, "image v0.13.1-rc1 is older than v0.13.1"},
		{"image does not answer", "locksql launcher 0.13.1 (image x)\n", 1, false, "image of unknown version is older than v0.13.1"},
		{"no version at all", "", 2, false, "locksql version did not say its versions"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := shopProject(t)
			h := newHarness(t, root, "")
			h.in.Yes = true
			h.run.answer = func(lock string, args []string) (string, string, int) {
				if lock == "locksql" && args[0] == "version" {
					if c.version == "" {
						return "", "locksql: docker is required\n", c.code
					}
					return c.version, "", c.code
				}
				return "", "", 0
			}
			if err := h.in.Do(context.Background()); err != nil {
				t.Fatalf("%v\n%s", err, h.out.String())
			}
			var doctors []string
			versions := 0
			for _, v := range h.verbs("locksql") {
				switch {
				case strings.HasPrefix(v, "locksql doctor"):
					doctors = append(doctors, v)
				case v == "locksql version":
					versions++
				}
			}
			want := "locksql doctor --json"
			if c.fix {
				want = "locksql doctor --fix --yes --json"
			}
			if len(doctors) != 2 || doctors[0] != want || doctors[1] != want {
				t.Errorf("doctors %q, want %q twice", doctors, want)
			}
			if versions != 1 {
				t.Errorf("locksql version asked %d times, want once", versions)
			}
			out := h.out.String()
			if c.fix {
				if strings.Contains(out, "lox init runs locksql doctor without --fix") {
					t.Errorf("fallback note with a fixed launcher:\n%s", out)
				}
				if !strings.Contains(out, "doctor --fix: fixed chmod go-w .locksql/config.toml") {
					t.Errorf("the repairs are not shown:\n%s", out)
				}
				return
			}
			note := "lox init runs locksql doctor without --fix: " + c.wantNote + ", whose doctor --fix gives .locksql/ to the console account (lox up then refuses it); update locksql to v0.13.1 or later, then run locksql doctor --fix"
			if !strings.Contains(out, note) {
				t.Errorf("no note %q in\n%s", note, out)
			}
			// lockmq's launcher is a fixed release: its --fix runs.
			if !slices.Contains(h.verbs("lockmq"), "lockmq doctor --fix --yes --json") {
				t.Errorf("lockmq: %q", h.verbs("lockmq"))
			}
		})
	}
}

// lockmq's fixed release is v0.6.1: v0.6.0 gets the advisory doctor.
func TestDoctorFixLockmqOlder(t *testing.T) {
	root := shopProject(t)
	h := newHarness(t, root, "")
	h.in.Yes = true
	h.run.answer = func(lock string, args []string) (string, string, int) {
		if lock == "lockmq" && args[0] == "version" {
			return "lockmq launcher 0.6.0 (image x)\nlockmq v0.6.0\n", "", 0
		}
		return "", "", 0
	}
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	if !slices.Contains(h.verbs("lockmq"), "lockmq doctor --json") || slices.Contains(h.verbs("lockmq"), "lockmq doctor --fix --yes --json") {
		t.Errorf("lockmq: %q", h.verbs("lockmq"))
	}
	if !strings.Contains(h.out.String(), "lox init runs lockmq doctor without --fix: launcher 0.6.0 is older than v0.6.1") {
		t.Errorf("no note in\n%s", h.out.String())
	}
}

func TestAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		want   bool
	}{
		{"0.13.1", "0.13.1", true}, {"v0.13.1", "0.13.1", true}, {"0.13.10", "0.13.1", true},
		{"1.0.0", "0.13.1", true}, {"0.14.0", "0.13.1", true},
		{"0.13.0", "0.13.1", false}, {"0.12.9", "0.13.1", false}, {"v0.13.1-rc1", "0.13.1", false},
		{"dev", "0.13.1", false}, {"", "0.13.1", false}, {"0.13", "0.13.1", false},
	} {
		if got := atLeast(c.v, c.min); got != c.want {
			t.Errorf("atLeast(%q, %q) = %v", c.v, c.min, got)
		}
	}
}

func TestParseVersions(t *testing.T) {
	got := parseVersions("lockmq", []byte("lockmq launcher dev (image ghcr.io/davidgodefroid/lockmq:0.6.1)\nlockmq v0.6.1\n"))
	if got != (LauncherVersions{Launcher: "dev", Image: "v0.6.1"}) {
		t.Errorf("%+v", got)
	}
	if got := parseVersions("locksql", []byte("lockmq launcher 0.6.1 (image x)\nlockmq v0.6.1\n")); got != (LauncherVersions{}) {
		t.Errorf("another lock's lines read: %+v", got)
	}
}

// Detection never activates anything without a yes: declined at the plan,
// at the mode question, or with no answer at all, no verb runs and
// nothing is declared.
func TestDetectionNeedsConfirmation(t *testing.T) {
	for _, c := range []struct {
		name, input string
		terminal    bool
		want        string
	}{
		{"declined at the plan", "a\ndev\nask\n\nn\n", true, "not confirmed"},
		{"Enter at the plan is no", "a\n\n\n\n\n", true, "not confirmed"},
		{"quit at the mode", "q\n", true, "nothing done"},
		{"no answer", "", true, "end of input"},
		{"not a terminal, no --yes", "", false, "stdin is not one"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := shopProject(t)
			h := newHarness(t, root, c.input)
			h.in.Terminal = c.terminal
			err := h.in.Do(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q\n%s", err, c.want, h.out.String())
			}
			if len(h.run.calls) != 0 || len(h.added) != 0 || h.ups != 0 {
				t.Errorf("activated without a yes: verbs %q, added %d, ups %d", h.run.calls, len(h.added), h.ups)
			}
		})
	}
}

// A re-run starts from lockfamily.yaml: the sources it declares already
// are kept (no verb runs for them, nothing declared again), a new one is
// added, and only its console (the new container) is attached.
func TestRerunAddsWithoutTouching(t *testing.T) {
	root := shopProject(t)
	h := newHarness(t, root, "")
	h.in.Yes = true
	h.decl = []Declared{{Instance: "db", Lock: "locksql", Profile: "db"}, {Instance: "mq", Lock: "lockmq", Profile: "mq"}}
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	for _, c := range h.run.calls {
		if strings.Contains(c, "--profile db ") || strings.Contains(c, "--profile mq ") {
			t.Errorf("a verb ran for a declared lock: %s", c)
		}
	}
	if len(h.added) != 1 || h.added[0].Instance != "stock" {
		t.Errorf("added %+v, want stock only", h.added)
	}
	if strings.Join(h.attached, ",") != "stock" {
		t.Errorf("attached %q, want the new console only", h.attached)
	}
	for _, w := range []string{"kept: db (locksql, profile db), declared already: not changed", "kept: mq (lockmq, profile mq)"} {
		if !strings.Contains(h.out.String(), w) {
			t.Errorf("no %q in\n%s", w, h.out.String())
		}
	}
}

// A profile the lock's config has already (code exists) is kept: lox init
// goes on with init, doctor and lox add. A lock whose profile add fails
// (no JSON) is not declared, its stderr is shown, the others go on, and
// lox init fails at the end.
func TestExistsKeptFailedShown(t *testing.T) {
	root := shopProject(t)
	h := newHarness(t, root, "")
	h.in.Yes = true
	h.run.answer = func(lock string, args []string) (string, string, int) {
		if args[0] != "profile" {
			return "", "", 0
		}
		switch args[slices.Index(args, "--profile")+1] {
		case "db":
			return `{"lock":"locksql","code":"exists","error":"--profile: a profile of that name is already in the project's config; nothing written"}`, "", 3
		case "mq":
			return "", "lockmq: docker is required\n", 1
		}
		return "", "", 0
	}
	err := h.in.Do(context.Background())
	if err == nil || !strings.Contains(err.Error(), "1 lock(s) not set up") {
		t.Fatalf("err %v\n%s", err, h.out.String())
	}
	out := h.out.String()
	for _, w := range []string{"profile db is there already: kept as it is", "profile add failed (failed): lockmq: docker is required"} {
		if !strings.Contains(out, w) {
			t.Errorf("no %q in\n%s", w, out)
		}
	}
	var names []string
	for _, p := range h.added {
		names = append(names, p.Instance)
	}
	if strings.Join(names, ",") != "db,stock" || h.ups != 1 {
		t.Errorf("added %q, ups %d", names, h.ups)
	}
	if len(h.verbs("lockmq")) != 1 {
		t.Errorf("lockmq went on after its profile add failed: %q", h.verbs("lockmq"))
	}
}

// Prerequisites missing stop lox init before anything, with the command
// that installs them.
func TestPrereqsMissing(t *testing.T) {
	root := shopProject(t)
	h := newHarness(t, root, "")
	h.in.Yes = true
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
	if err == nil || len(h.run.calls) != 0 {
		t.Fatalf("err %v, calls %q", err, h.run.calls)
	}
	golden(t, "prereqs-missing-darwin.golden", root, h.out.String())
}

// The manual checklist greys what cannot be checked, with the reason.
func TestChecklistScreens(t *testing.T) {
	root := shopProject(t)
	sources, _ := Detect(root)
	decl := []Declared{{Instance: "web", Lock: "lockhttp", Profile: "default"}}
	for _, c := range []struct {
		name  string
		goos  string
		lea   bool
		types []string
		miss  []string
	}{
		{"checklist-linux-lea.golden", "linux", true, []string{"locksql", "lockmq", "lockfile", "lockhttp"}, nil},
		{"checklist-darwin-nolea.golden", "darwin", false, []string{"locksql", "lockmq", "lockfile", "lockhttp"}, []string{"lockmq"}},
		{"checklist-locklog-in-types.golden", "linux", true, []string{"locksql", "lockmq", "lockfile", "lockhttp", "locklog"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			pre := Prereqs{Docker: "29.0.0", Cosign: "/usr/bin/cosign", Launchers: map[string]string{}}
			if c.lea {
				pre.Lea = "/usr/bin/lea"
			}
			for _, l := range Locks {
				if !slices.Contains(c.miss, l) {
					pre.Launchers[l] = "/usr/bin/" + l
				}
			}
			var b bytes.Buffer
			RenderChecklist(&b, BuildItems(Env{GOOS: c.goos, Types: c.types}, pre, decl, sources))
			golden(t, c.name, root, b.String())
		})
	}
}

// Manual mode end to end: lea unchecked greys lockhttp; a declared lock
// unchecked is removed; a new lockfile and a locksql on a detected source
// are planned with what was typed.
func TestManualFlow(t *testing.T) {
	root := shopProject(t)
	input := strings.Join([]string{
		"m",                // manual
		"1",                // uncheck lea: lockhttp greys
		"5",                // lockhttp: greyed, its reason shown
		"1 4 3 7",          // lea back, lockfile on, lockmq off, the declared web off
		"",                 // done
		"1",                // locksql: the first detected source
		"",                 // engine postgres
		"",                 // host
		"",                 // port
		"",                 // user
		"",                 // database
		"require",          // tls
		"orders",           // instance
		"",                 // lockfile: source local
		"/srv/" + "shared", // directory
		"",                 // instance files
		"prod",             // environment
		"",                 // ask
		"y",                // go on
	}, "\n") + "\n"
	h := newHarness(t, root, input)
	h.in.Env.GOOS = "linux"
	h.decl = []Declared{{Instance: "web", Lock: "lockhttp", Profile: "default"}}
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	golden(t, "manual-flow.golden", root, h.out.String())
	if strings.Join(h.removed, ",") != "web" {
		t.Errorf("removed %q", h.removed)
	}
	var names []string
	for _, p := range h.added {
		names = append(names, p.Lock+" "+p.Instance)
	}
	if strings.Join(names, ",") != "locksql orders,lockfile files" {
		t.Errorf("added %q", names)
	}
	want := []string{
		"locksql profile add --non-interactive --json --project " + root + " --profile orders --production --credentials ask --engine postgres --host host.docker.internal --port 55432 --user shop --database shop --tls require",
		"lockfile profile add --non-interactive --json --project " + root + " --profile files --production --source local --path /srv/shared",
	}
	for _, w := range want {
		if !slices.Contains(h.run.calls, w) {
			t.Errorf("no call %q in\n%s", w, strings.Join(h.run.calls, "\n"))
		}
	}
	// lockfile's only repair wires every installed agent for the user's
	// account: its doctor runs without --fix, and its version is not asked.
	if lf := h.verbs("lockfile"); !slices.Contains(lf, "lockfile doctor --json") || slices.ContainsFunc(lf, func(c string) bool {
		return strings.Contains(c, "--fix") || c == "lockfile version"
	}) {
		t.Errorf("lockfile: %q", lf)
	}
}

// A value that embeds a password is never taken: asked again, and
// never quoted back.
func TestManualRefusesEmbeddedPassword(t *testing.T) {
	root := t.TempDir()
	input := "3\n\n" + "http://u:" + secret + "@host.docker.internal:15672\nhttp://host.docker.internal:15672\nro\n\n-\n\n\n\nn\n"
	h := newHarness(t, root, input)
	h.in.Manual = true
	err := h.in.Do(context.Background())
	if !errors.Is(err, ErrDeclined) {
		t.Fatalf("err %v\n%s", err, h.out.String())
	}
	if strings.Contains(h.out.String(), secret) {
		t.Fatal("the password typed was echoed")
	}
	if !strings.Contains(h.out.String(), "it embeds a password") {
		t.Errorf("not refused:\n%s", h.out.String())
	}
}

// No secret is ever written: the whole flow over a project whose files
// hold one, with lockfamily.yaml written for real; the workspace (but the
// files that held it) and the state directory never contain it, nor does
// anything lox init printed or passed to a launcher.
func TestNoSecretWritten(t *testing.T) {
	root := shopProject(t)
	state := t.TempDir()
	h := newHarness(t, root, "")
	h.in.Yes = true
	add := h.in.AddLock
	h.in.AddLock = func(ctx context.Context, p Planned) error {
		// What lox add writes, as lockfamily.yaml would hold it.
		f, err := os.OpenFile(filepath.Join(root, ".lockfamily-test.yaml"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "%s: {type: %s, profile: %s, allowed_uids: %v}\n", p.Instance, p.Lock, p.Profile, p.AllowedUIDs)
		f.Close()
		return add(ctx, p)
	}
	h.in.Up = func(context.Context) error {
		// What lox up keeps: the plans' targets, as its review lists them.
		return os.WriteFile(filepath.Join(state, "applied.json"), []byte(strings.Join(h.run.calls, "\n")), 0o600)
	}
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	planted := map[string]bool{"compose.yaml": true, ".env": true, filepath.Join("config", "inventory.yaml"): true}
	for _, dir := range []string{root, state} {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			if dir == root && planted[rel] {
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
	}
	if strings.Contains(h.out.String(), secret) || strings.Contains(strings.Join(h.run.calls, " "), secret) {
		t.Error("the secret was printed or passed to a launcher")
	}
	if _, err := os.Stat(filepath.Join(state, "applied.json")); err != nil {
		t.Fatal("the state directory was not written: the check above proves nothing")
	}
}

// Detaching from a console (Ctrl-P Ctrl-Q) ends docker's attach with a
// non-zero status: a console still running is reported detached, one
// that stopped is reported with what to run.
func TestAttachDetachIsNotAFailure(t *testing.T) {
	root := shopProject(t)
	h := newHarness(t, root, "")
	h.in.Yes = true
	h.in.Attach = func(_ context.Context, n string) error {
		if n == "mq" {
			delete(h.after, "lock-mq") // its console stopped
		}
		return errors.New("exit status 1: read escape sequence")
	}
	if err := h.in.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, h.out.String())
	}
	out := h.out.String()
	for _, w := range []string{"detached from db", "detached from stock", "lox attach mq: exit status 1: read escape sequence (its console stopped: lox up, then lox attach mq)"} {
		if !strings.Contains(out, w) {
			t.Errorf("no %q in\n%s", w, out)
		}
	}
}
