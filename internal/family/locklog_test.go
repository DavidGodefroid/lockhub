package family

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const logImg = "ghcr.io/davidgodefroid/locklog@sha256:6666666666666666666666666666666666666666666666666666666666666666"

// logConf is yamlConf with a locklog lock, logs, and its extra lines.
func logConf(extra string) string {
	return yamlConf("") + "  logs:\n    type: locklog\n    image: " + logImg + "\n" + extra
}

// A locklog lock is a lock type of lockfamily.yaml: digest-pinned to its
// own repository, and it takes allowed_uids (never its console's uid).
func TestLocklogConfig(t *testing.T) {
	load := func(conf string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "lockfamily.yaml")
		os.WriteFile(p, []byte(conf), 0o644)
		return Load(p)
	}
	c, err := load(logConf("    profile: app\n    allowed_uids: [1000]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Locks["logs"]; l.Type != "locklog" || l.Image != logImg || l.Profile != "app" || l.AllowedUIDsFlag() != "1000" {
		t.Errorf("logs: %+v", l)
	}
	for name, conf := range map[string]string{
		"allowed_uids console's": logConf("    allowed_uids: [10051]\n"),
		"allowed_uids root":      logConf("    allowed_uids: [0]\n"),
		"wrong repo":             strings.Replace(logConf(""), logImg, strings.Replace(logImg, "locklog", "locksql", 1), 1),
		"tag not digest":         strings.Replace(logConf(""), logImg, "ghcr.io/davidgodefroid/locklog:0.2.0", 1),
	} {
		if _, err := load(conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// lox add declares one.
	w := newWS(t, yamlConf(""))
	if err := Add(w.file, AddOptions{Type: "locklog", Name: "logs", Image: logImg}); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(w.file); err != nil || c.Locks["logs"].Type != "locklog" {
		t.Errorf("lox add locklog: %v", err)
	}
}

// The locklog console's service, line for line: the project kind's
// (working directory, the profile copy at <workspace>/.locklog), hub
// mode, no docker log, its limits and the CPU cap.
func TestComposeLocklog(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{
		"logs":     {Type: "locklog", Image: logImg, AllowedUIDs: UIDList{1000}},
		"crm-prod": {Type: "locksql", Image: sqlImg},
	}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	paths := Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0", NCPU: 8}
	out := Compose(c, paths)
	want := `  lock-logs:
    image: "` + logImg + `"
    user: "10051:10050"
    tty: true
    stdin_open: true
    environment:
      HOME: "/home/locklog"
      LOCKLOG_PII_DIR: "/home/locklog/pii-rules"
    working_dir: "/w"
    command: ["console", "--allowed-uids", "1000", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/lockfamily/hub.pub", "--instance", "logs"]
    logging:
      driver: none
    labels:
      locklog.console: "1"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m"]
    pids_limit: 256
    mem_limit: 1g
    cpus: 2
    volumes:
      - "logs-run:/run/locklog"
      - "logs-home:/home/locklog"
      - hubkey:/run/lockfamily:ro
      - "profile-locklog:/w/.locklog:ro"
    networks: [lockhub]
    depends_on: [lockhub]
    restart: unless-stopped
`
	if got := block(out, "lock-logs"); got != want {
		t.Errorf("lock-logs:\n%s\nwant:\n%s", got, want)
	}
	// The profile copy belongs to the console's account.
	if blk := block(out, "profile-locklog"); !strings.Contains(blk, "chown 10051:10050 /p") || !strings.Contains(blk, "profiles: [setup]") || !strings.Contains(blk, "network_mode: none") {
		t.Errorf("profile-locklog:\n%s", blk)
	}
	if !strings.Contains(block(out, "logs-run"), `dev.lockfamily.type: "locklog"`) {
		t.Errorf("socket volume:\n%s", out)
	}
	// Only the kind that sets CPUs gets a cap.
	if n := strings.Count(out, "cpus:"); n != 1 || strings.Contains(block(out, "lock-crm-prod"), "cpus:") {
		t.Errorf("%d cpus caps:\n%s", n, out)
	}
	// Capped by the Docker host's CPUs.
	for ncpu, cap := range map[int]string{1: "cpus: 1\n", 2: "cpus: 2\n", 64: "cpus: 2\n", 0: "cpus: 2\n"} {
		paths.NCPU = ncpu
		if blk := block(Compose(c, paths), "lock-logs"); !strings.Contains(blk, "    "+cap) {
			t.Errorf("NCPU %d: want %q:\n%s", ncpu, cap, blk)
		}
	}
	// Compose reads cpus as a number.
	var v struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if n, ok := v.Services["lock-logs"]["cpus"].(int); !ok || n != 2 {
		t.Errorf("cpus %#v", v.Services["lock-logs"]["cpus"])
	}
}

// The other kinds set no CPU cap: their compose output does not change.
func TestOnlyLocklogSetsCPUs(t *testing.T) {
	for typ, k := range Kinds {
		if (k.CPUs != 0) != (typ == "locklog") {
			t.Errorf("%s CPUs %d", typ, k.CPUs)
		}
	}
	if k := Kinds["locklog"]; k.UID != "10051" || k.GID != "10050" || !k.Project || k.Gate || k.Mem != "1g" || k.Pids != 256 || k.CPUs != 2 {
		t.Errorf("locklog kind %+v", k)
	}
}

// lox run reads the Docker host's CPUs only when a lock's kind caps them,
// renders the cap from them, and stops when docker cannot say.
func TestUpCapsLocklogCPUsAtHostNCPU(t *testing.T) {
	const info = "docker info --format {{.NCPU}}"
	w := newWS(t, yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.ran(info) || strings.Contains(f.upCompose, "cpus:") {
		t.Errorf("no locklog lock: docker info ran %v, compose:\n%s", f.ran(info), f.upCompose)
	}

	w = newWS(t, logConf(""))
	f = newFake()
	f.keys["logs"], f.keys["ncpu"] = pubKey(), "1"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !f.ran(info) || !strings.Contains(block(f.upCompose, "lock-logs"), "    cpus: 1\n") {
		t.Errorf("one-CPU host: compose:\n%s", f.upCompose)
	}
	if !strings.Contains(out, "lock logs (locklog)") {
		t.Errorf("review:\n%s", out)
	}
	// up.json: lea's agents join the clients group 10050.
	ws := filepath.Dir(filepath.Dir(w.file))
	b, err := os.ReadFile(filepath.Join(ws, Dir, UpFile))
	var s UpState
	if err != nil || json.Unmarshal(b, &s) != nil || s.Locks["logs"].Type != "locklog" || s.Locks["logs"].GID != "10050" || s.Locks["logs"].GateHome != "" {
		t.Errorf("up.json: %v\n%s", err, b)
	}

	for name, f := range map[string]*fake{
		"docker info fails": {keys: map[string]string{"hub": pubKey(), "crm-prod": pubKey(), "events": pubKey(), "logs": pubKey()}, failing: "docker info"},
		"no count":          {keys: map[string]string{"hub": pubKey(), "crm-prod": pubKey(), "events": pubKey(), "logs": pubKey(), "ncpu": "many"}},
		"zero":              {keys: map[string]string{"hub": pubKey(), "crm-prod": pubKey(), "events": pubKey(), "logs": pubKey(), "ncpu": "0"}},
	} {
		w := newWS(t, logConf(""))
		if out, err := w.up("y\n", f); err == nil || !strings.Contains(err.Error(), "Docker host's CPUs") || f.ran(" up -d") {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// lox add pins only locklog releases with hub mode (v0.2.0 or later).
func TestLocklogMinRelease(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	r := &Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: &cosignFake{}}
	if _, err := r.Image(context.Background(), "locklog", "v0.1.9"); err == nil || !strings.Contains(err.Error(), "v0.2.0 or later") {
		t.Errorf("locklog v0.1.9 pinned: %v", err)
	}
	// v0.2.0 passes the release check (the registry here has no image).
	if _, err := r.Image(context.Background(), "locklog", "v0.2.0"); err == nil || strings.Contains(err.Error(), "or later") {
		t.Errorf("locklog v0.2.0: %v", err)
	}
}
