package family

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/keys"
)

const (
	hubImg = "ghcr.io/davidgodefroid/lockhub@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	sqlImg = "ghcr.io/davidgodefroid/locksql@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	mqImg  = "ghcr.io/davidgodefroid/lockmq@sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func yamlConf(routing string) string {
	return `version: 1
hub:
  image: ` + hubImg + `
` + routing + `locks:
  crm-prod:
    type: locksql
    image: ` + sqlImg + `
  events:
    type: lockmq
    image: ` + mqImg + `
`
}

type fake struct {
	stdins    map[string][]byte
	upCompose string
	calls     []string
	keys      map[string]string
	failing   string
	// missing collects the bind sources of the device snapshots that did
	// not exist when a compose file was run (docker refuses those).
	missing []string
}

func pubKey() string {
	p, _, _ := ed25519.GenerateKey(rand.Reader)
	return keys.Public(p)
}

func (f *fake) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if f.stdins == nil {
		f.stdins = map[string][]byte{}
	}
	f.stdins[line] = stdin
	for _, l := range strings.Split(string(stdin), "\n") {
		if src, ok := strings.CutPrefix(strings.TrimSpace(l), "source: "); ok && strings.Contains(src, "devices-") {
			if _, err := os.Stat(strings.Trim(src, `"`)); err != nil {
				f.missing = append(f.missing, src)
			}
		}
	}
	if strings.Contains(line, " up -d") {
		f.upCompose = string(stdin)
	}
	if f.failing != "" && strings.Contains(line, f.failing) {
		return nil, errors.New("refused")
	}
	for _, a := range args {
		if a == "keygen" {
			return []byte(f.keys["hub"] + "\n"), nil
		}
	}
	if i := strings.Index(line, "--no-deps gatekey-"); i >= 0 {
		return []byte(f.keys[line[i+len("--no-deps gatekey-"):]] + "\n"), nil
	}
	if i := strings.Index(line, "hub-key --instance "); i >= 0 {
		return []byte(f.keys[line[i+len("hub-key --instance "):]] + "\n"), nil
	}
	return nil, nil
}

func (f *fake) ran(s string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

type ws struct {
	dir, file string
	up        func(input string, f *fake) (string, error)
}

func newWS(t *testing.T, conf string) ws {
	dir, _ := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a link
	file := filepath.Join(dir, "projects", Dir, FileName)
	os.MkdirAll(filepath.Dir(file), 0o755)
	for _, t := range Types {
		os.Mkdir(filepath.Join(dir, "projects", "."+t), 0o755)
	}
	os.WriteFile(file, []byte(conf), 0o644)
	state, run := filepath.Join(dir, "state"), filepath.Join(dir, "run")
	return ws{dir, file, func(input string, f *fake) (string, error) {
		var out strings.Builder
		u := &Up{File: file, State: state, Runtime: run, User: "1000:1000", Run: f, In: bufio.NewReader(strings.NewReader(input)), Out: &out}
		err := u.Do(context.Background())
		return out.String(), err
	}}
}

func newFake() *fake {
	return &fake{keys: map[string]string{"hub": pubKey(), "crm-prod": pubKey(), "events": pubKey()}}
}

func TestFirstRunReviewsEverything(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"First lock up", "lock crm-prod type locksql", "hub facades tty,deck", "lock events key " + f.keys["events"], "hub key " + f.keys["hub"]} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	if !f.ran("compose -p lockfamily-") || !f.ran("up -d --remove-orphans") {
		t.Errorf("stack not started: %v", f.calls)
	}
	lj, _ := os.ReadFile(filepath.Join(w.dir, "state", "hub", "locks.json"))
	if !strings.Contains(string(lj), f.keys["crm-prod"]) || !strings.Contains(string(lj), f.keys["events"]) {
		t.Errorf("locks.json %s", lj)
	}
	if _, err := keys.LoadLocks(filepath.Join(w.dir, "state", "hub", "locks.json")); err != nil {
		t.Errorf("hub cannot load locks.json: %v", err)
	}
	// Unchanged: no question, still up.
	f2 := &fake{keys: f.keys}
	out, err = w.up("", f2)
	if err != nil || !strings.Contains(out, "unchanged") || !f2.ran("up -d") {
		t.Errorf("second run: %v\n%s", err, out)
	}
	if f2.ran("keygen") {
		t.Error("hub key generated twice")
	}
}

func TestChangeNeedsConfirmation(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	// Narrow routing: shown as a diff; "n" applies nothing.
	os.WriteFile(w.file, []byte(yamlConf("  routing:\n    crm-prod: [tty]\n")), 0o644)
	f2 := &fake{keys: f.keys}
	out, err := w.up("n\n", f2)
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "+ lock crm-prod routed only to tty") || f2.ran("up -d") {
		t.Errorf("declined change: %v %v\n%s", err, f2.calls, out)
	}
	// A lock key that changed is shown too.
	f3 := &fake{keys: map[string]string{"hub": f.keys["hub"], "crm-prod": pubKey(), "events": f.keys["events"]}}
	out, _ = w.up("n\n", f3)
	if !strings.Contains(out, "- lock crm-prod key "+f.keys["crm-prod"]) {
		t.Errorf("key change not shown:\n%s", out)
	}
}

func TestPreexistingDirStillFullReview(t *testing.T) {
	// A .lockfamily/ left by someone else in the workspace is never read:
	// the first run on this host gets the full review, not a diff.
	w := newWS(t, yamlConf(""))
	os.MkdirAll(filepath.Join(filepath.Dir(w.file), ".lockfamily", "keys"), 0o755)
	os.WriteFile(filepath.Join(filepath.Dir(w.file), ".lockfamily", "applied.json"), []byte(`{"fingerprint":"x"}`), 0o644)
	out, _ := w.up("n\n", newFake())
	if !strings.Contains(out, "First lock up") {
		t.Errorf("planted state trusted:\n%s", out)
	}
}

func TestUnsignedImageStops(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	f.failing = "cosign verify"
	if _, err := w.up("y\n", f); err == nil || f.ran("docker") {
		t.Errorf("unsigned image: %v %v", err, f.calls)
	}
}

func TestConfigRefusals(t *testing.T) {
	for name, conf := range map[string]string{
		"literal secret": strings.Replace(yamlConf(""), "    image: "+sqlImg, "    image: "+sqlImg+"\n    password: hunter2", 1),
		"profile field":  strings.Replace(yamlConf(""), "    image: "+sqlImg, "    image: "+sqlImg+"\n    production: true", 1),
		"tag not digest": strings.Replace(yamlConf(""), sqlImg, "ghcr.io/davidgodefroid/locksql:0.9.0", 1),
		"wrong repo":     strings.Replace(yamlConf(""), sqlImg, strings.Replace(sqlImg, "locksql", "lockmq", 1), 1),
		"bad routing":    yamlConf("  routing:\n    crm-prod: [slack]\n"),
		"unknown lock":   yamlConf("  routing:\n    nope: [tty]\n"),
	} {
		p := filepath.Join(t.TempDir(), "lockfamily.yaml")
		os.WriteFile(p, []byte(conf), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestComposeIsolation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	os.WriteFile(p, []byte(yamlConf("")), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0"})
	for _, want := range []string{
		"  lockhub:\n    internal: true",
		`networks: [lockhub, "egress-crm-prod"]`,
		"    networks: [lockhub]\n    restart", // the hub has no egress
		"read_only: true", "cap_drop: [ALL]", `"no-new-privileges:true"`,
		`"--instance", "crm-prod"`, `"--hub-key-file", "/run/lockfamily/hub.pub"`,
		`extra_hosts: ["host.docker.internal:host-gateway"]`, `user: "10001:10000"`, "tty: true", "stdin_open: true", `working_dir: "/w"`, "    logging:\n      driver: none", "mem_limit: 1g",
		"      - hubkey:/run/lockfamily:ro", `      - "profile-locksql:/w/.locksql:ro"`,
		"dev.lockfamily.role: \"socket\"", "dev.lockfamily.instance: \"crm-prod\"",
		`"--hub", "http://lockhub:8443", "--hub-plain-http"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose lacks %q", want)
		}
	}
	if strings.Contains(out, "docker.sock") || strings.Contains(out, "privileged") {
		t.Error("compose grants the engine or privileges")
	}
	if out != Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0"}) {
		t.Error("compose output is not deterministic")
	}
}

func TestComposeFileOutsideWorkspace(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(w.file), ".lockfamily", "compose.yaml")); err == nil {
		t.Error("compose file written in the workspace")
	}
	if !f.ran("compose -p lockfamily-") || f.ran("-f "+filepath.Join(w.dir, "projects")) || !f.ran("-f - up -d") {
		t.Errorf("compose not passed on stdin: %v", f.calls)
	}
	if fi, err := os.Stat(filepath.Join(w.dir, "state", "compose.yaml")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("reference copy of the compose file: %v", err)
	}
}

func TestEveryImageVerified(t *testing.T) {
	two := yamlConf("") + `  crm-test:
    type: locksql
    image: ghcr.io/davidgodefroid/locksql@sha256:4444444444444444444444444444444444444444444444444444444444444444
`
	w := newWS(t, two)
	f := newFake()
	f.keys["crm-test"] = pubKey()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"2222", "4444", "3333", "1111"} {
		if !f.ran("cosign verify") || !f.ran("@sha256:"+strings.Repeat(d, 16)) {
			t.Errorf("image %s… not verified: %v", d, f.calls)
		}
	}
	f2 := newFake()
	f2.keys["crm-test"] = pubKey()
	f2.failing = "4444444444444444"
	if _, err := newWS(t, two).up("y\n", f2); err == nil {
		t.Error("second image of the same type not verified")
	}
}

func TestStateDirMustBePrivate(t *testing.T) {
	w := newWS(t, yamlConf(""))
	os.MkdirAll(filepath.Join(w.dir, "state"), 0o755)
	os.Chmod(filepath.Join(w.dir, "state"), 0o755)
	if _, err := w.up("y\n", newFake()); err == nil || !strings.Contains(err.Error(), "want 0700") {
		t.Errorf("open state dir: %v", err)
	}
	w2 := newWS(t, yamlConf(""))
	os.Symlink(t.TempDir(), filepath.Join(w2.dir, "state"))
	if _, err := w2.up("y\n", newFake()); err == nil {
		t.Error("state dir behind a link accepted")
	}
}

func TestRoutingApplied(t *testing.T) {
	w := newWS(t, yamlConf("  facades: [tty]\n  routing:\n    crm-prod: [tty]\n"))
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(w.dir, "state", "hub", "routing.json"))
	if err != nil || !strings.Contains(string(b), `"facades": [`) || !strings.Contains(string(b), `"crm-prod": [`) {
		t.Errorf("routing.json: %s %v", b, err)
	}
	for _, f := range []string{"locks.json", "routing.json"} {
		if fi, _ := os.Stat(filepath.Join(w.dir, "state", "hub", f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
}

func TestConfigChangeRecreatesHub(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.upCompose, "lockfamily.config: \"sha256:") {
		t.Fatalf("no config label on the hub:\n%s", f.upCompose)
	}
	if !f.ran("--project-directory "+filepath.Join(w.dir, "state")) || !f.ran("--env-file "+os.DevNull) {
		t.Errorf("compose not pinned to the state dir: %v", f.calls)
	}
	first := f.upCompose
	os.WriteFile(w.file, []byte(yamlConf("  routing:\n    crm-prod: [tty]\n")), 0o644)
	f2 := &fake{keys: f.keys}
	if _, err := w.up("y\n", f2); err != nil {
		t.Fatal(err)
	}
	if f2.upCompose == first {
		t.Error("a confirmed routing change leaves the hub service unchanged: compose would not recreate it")
	}
	f3 := &fake{keys: f.keys}
	w.up("", f3)
	if f3.upCompose != f2.upCompose {
		t.Error("an unchanged config changes the hub service")
	}
}
