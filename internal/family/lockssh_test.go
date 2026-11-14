package family

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/route"
)

const sshImg = "ghcr.io/davidgodefroid/lockssh@sha256:7777777777777777777777777777777777777777777777777777777777777777"

// sshConf is yamlConf with a lockssh lock, web, and its extra lines.
func sshConf(extra string) string {
	return yamlConf("") + "  web:\n    type: lockssh\n    image: " + sshImg + "\n" + extra
}

// sshRulesJSON is lockssh profile rules --json for profiles, each with
// the rules connect, run, exec, unmask.
func sshRulesJSON(connect, run, exec, unmask string, profiles ...string) string {
	type pr struct {
		Profile string            `json:"profile"`
		Rules   map[string]string `json:"rules"`
		Source  string            `json:"source"`
	}
	o := struct {
		Lock     string   `json:"lock"`
		Actions  []string `json:"actions"`
		Profiles []pr     `json:"profiles"`
	}{Lock: "lockssh", Actions: SSHRuleActions}
	for _, p := range profiles {
		o.Profiles = append(o.Profiles, pr{p, map[string]string{"connect": connect, "run": run, "exec": exec, "unmask": unmask}, "files"})
	}
	b, _ := json.Marshal(o)
	return string(b) + "\n"
}

// A lockssh lock is a lock type of lockfamily.yaml: digest-pinned to its
// own repository, and it takes allowed_uids (never its console's uid).
func TestLocksshConfig(t *testing.T) {
	load := func(conf string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "lockfamily.yaml")
		os.WriteFile(p, []byte(conf), 0o644)
		return Load(p)
	}
	c, err := load(sshConf("    profile: prod\n    allowed_uids: [1000]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Locks["web"]; l.Type != "lockssh" || l.Image != sshImg || l.Profile != "prod" || l.AllowedUIDsFlag() != "1000" {
		t.Errorf("web: %+v", l)
	}
	for name, conf := range map[string]string{
		"allowed_uids console's": sshConf("    allowed_uids: [10041]\n"),
		"allowed_uids root":      sshConf("    allowed_uids: [0]\n"),
		"wrong repo":             strings.Replace(sshConf(""), sshImg, strings.Replace(sshImg, "lockssh", "locksql", 1), 1),
		"tag not digest":         strings.Replace(sshConf(""), sshImg, "ghcr.io/davidgodefroid/lockssh:0.1.0", 1),
	} {
		if _, err := load(conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	w := newWS(t, yamlConf(""))
	if err := Add(w.file, AddOptions{Type: "lockssh", Name: "web", Image: sshImg}); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(w.file); err != nil || c.Locks["web"].Type != "lockssh" {
		t.Errorf("lox add lockssh: %v", err)
	}
	if k := Kinds["lockssh"]; k.UID != "10041" || k.GID != "10040" || !k.Project || k.Gate || k.Mounts || !k.HomeFiles || !k.Rules || k.Agent != "10042:10040" || k.Mem != "1g" || k.Pids != 256 {
		t.Errorf("lockssh kind %+v", k)
	}
	if ShippedLocks["lockssh"] == "" || MinRelease["lockssh"] != "v0.1.0" {
		t.Errorf("shipped %q, min %q", ShippedLocks["lockssh"], MinRelease["lockssh"])
	}
}

// The lockssh console's service, line for line: the project kind's
// (working directory, the profile copy at <workspace>/.lockssh), hub
// mode, no docker log, its launcher's limits; its rules and home files
// services as the image's agent and console accounts.
func TestComposeLockssh(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{
		"web":      {Type: "lockssh", Image: sshImg, Profile: "prod", AllowedUIDs: UIDList{1000}},
		"crm-prod": {Type: "locksql", Image: sqlImg},
	}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0", NCPU: 8})
	want := `  lock-web:
    image: "` + sshImg + `"
    user: "10041:10040"
    tty: true
    stdin_open: true
    environment:
      HOME: "/home/lockssh"
    working_dir: "/w"
    command: ["console", "--profile", "prod", "--allowed-uids", "1000", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/lockfamily/hub.pub", "--instance", "web"]
    logging:
      driver: none
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m"]
    pids_limit: 256
    mem_limit: 1g
    volumes:
      - "web-run:/run/lockssh"
      - "web-home:/home/lockssh"
      - hubkey:/run/lockfamily:ro
      - "profile-lockssh:/w/.lockssh:ro"
    networks: [lockhub, "locknet-web"]
    depends_on: [lockhub]
    restart: "no"
`
	if got := block(out, "lock-web"); got != want {
		t.Errorf("lock-web:\n%s\nwant:\n%s", got, want)
	}
	rules := `  "rules-web":
    image: "` + sshImg + `"
    profiles: [setup]
    user: "10042:10040"
    environment:
      HOME: "/tmp"
    entrypoint: ["/bin/sh", "-c", "mkdir -p \"$0/.lockssh\" && head -c 526336 | tar -x -C \"$0/.lockssh\" && cd \"$0\" && exec lockssh profile rules --json \"$@\"", "/w", "--profile", "prod"]
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m", "/w:size=2m,uid=10042,gid=10040,mode=0700"]
    pids_limit: 64
    mem_limit: 256m
`
	if got := block(out, "rules-web"); got != rules {
		t.Errorf("rules-web:\n%s\nwant:\n%s", got, rules)
	}
	if strings.Contains(out, `"mounts-web"`) {
		t.Errorf("a mount plan for lockssh:\n%s", out)
	}
	for _, svc := range []string{"homefiles-web", "homecopy-web"} {
		if blk := block(out, svc); !strings.Contains(blk, `user: "10041:10040"`) || !strings.Contains(blk, `"web-home:/home/lockssh"`) || !strings.Contains(blk, "network_mode: none") {
			t.Errorf("%s:\n%s", svc, blk)
		}
	}
	if blk := block(out, "profile-lockssh"); !strings.Contains(blk, "chown 10041:10040 /p") {
		t.Errorf("profile-lockssh:\n%s", blk)
	}
	if !strings.Contains(block(out, "web-run"), `dev.lockfamily.type: "lockssh"`) {
		t.Errorf("socket volume:\n%s", out)
	}
}

// A lockssh profile reaches its SSH host:port only (22 by default),
// through the lock's gateway; an IP address is refused, a missing host
// reaches nothing.
func TestEgressLockssh(t *testing.T) {
	eg := func(profile string, lock Lock) (Egress, error) {
		c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"web": lock}}
		return lockEgress(c, "web", profileOf(t, profile))
	}
	e, err := eg("[profiles.prod]\nhost = \"web1.example.com\"\nuser = \"deploy\"\n[profiles.dev]\nhost = \"dev.example.com\"\nport = 2222\n", Lock{Type: "lockssh", Image: sshImg})
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{Host: "dev.example.com", Port: 2222, What: "ssh"}, {Host: "web1.example.com", Port: 22, What: "ssh"}}
	if !reflect.DeepEqual(e.Endpoints, want) || len(e.None) != 0 {
		t.Errorf("both profiles: %+v", e)
	}
	e, err = eg("[profiles.prod]\nhost = \"web1.example.com\"\n[profiles.dev]\nhost = \"dev.example.com\"\n", Lock{Type: "lockssh", Image: sshImg, Profile: "prod"})
	if err != nil || !reflect.DeepEqual(e.Endpoints, []Endpoint{{Host: "web1.example.com", Port: 22, What: "ssh"}}) {
		t.Errorf("the lock's profile only: %+v %v", e, err)
	}
	if e, _ := eg("[profiles.prod]\nhost = \"10.0.0.5\"\n", Lock{Type: "lockssh", Image: sshImg}); len(e.Refused) != 1 || !strings.Contains(e.Refused[0], "profiles.prod.host") {
		t.Errorf("an IP address: %+v", e)
	}
	if e, _ := eg("[profiles.prod]\nuser = \"deploy\"\n", Lock{Type: "lockssh", Image: sshImg}); len(e.Endpoints) != 0 || len(e.None) != 1 || !strings.Contains(e.None[0], "ssh: no host") {
		t.Errorf("no host: %+v", e)
	}
	if e, _ := eg("[profiles.prod]\nhost = \"web1\"\nport = \"22\"\n", Lock{Type: "lockssh", Image: sshImg}); len(e.Endpoints) != 0 || len(e.None) != 1 {
		t.Errorf("a port that is not a number: %+v", e)
	}
}

// The short review's facts of a lockssh profile: user@host:port, the
// login, which host keys it trusts, exec.
func TestProfileFactsLockssh(t *testing.T) {
	p := tomlProfile(`[profiles.prod]`, `host = "web1.example.com"`, `user = "deploy"`, `key = "~/.ssh/id_ed25519"`, `production = true`)
	f := ProfileFacts(p, "lockssh", "prod")
	if want := "ssh deploy@web1.example.com:22, auth key ~/.ssh/id_ed25519, host keys: the console's known_hosts (a new key is confirmed at the console)"; f.Target != want || !f.Production {
		t.Errorf("target %q, want %q (%+v)", f.Target, want, f)
	}
	p = tomlProfile(`[profiles.dev]`, `host = "dev"`, `port = 2222`, `user = "ops"`, `auth = "password"`, `credentials = "vault"`, `vault_path = "secret/data/lockssh/dev"`, `known_hosts = "~/.ssh/pinned"`, `exec = true`)
	f = ProfileFacts(p, "lockssh", "")
	if want := "ssh ops@dev:2222, auth password, host keys ~/.ssh/pinned only, exec on (commands outside the allow list asked)"; f.Target != want || f.Credentials != "vault" || f.VaultPath != "secret/data/lockssh/dev" {
		t.Errorf("target %q, want %q (%+v)", f.Target, want, f)
	}
	p = tomlProfile(`[profiles.dev]`, `host = "dev"`, `port = "x"`, `user = "ops"`)
	if f := ProfileFacts(p, "lockssh", ""); !strings.HasPrefix(f.Target, "ssh ops@dev, ") || !strings.Contains(f.Target, `? (port = "x" in the profile)`) {
		t.Errorf("odd port: %q", f.Target)
	}
}

// lockssh's file keys: the key with auth = "key" (its default), and a
// known_hosts the profile names.
func TestProfileFileKeysLockssh(t *testing.T) {
	p := tomlProfile(`[profiles.prod]`, `host = "web1"`, `key = "~/.ssh/id_ed25519"`, `known_hosts = "~/.ssh/known_hosts.prod"`)
	got, odd := ProfileFileKeys(p, "lockssh", "prod")
	if want := []FileKey{{"key", "~/.ssh/id_ed25519"}, {"known_hosts", "~/.ssh/known_hosts.prod"}}; !reflect.DeepEqual(got, want) || odd != nil {
		t.Errorf("got %v %v, want %v", got, odd, want)
	}
	if !got[0].private() || got[1].private() {
		t.Error("the key is private, known_hosts is not")
	}
	p = tomlProfile(`[profiles.prod]`, `auth = "password"`, `key = "~/k"`, `known_hosts = ""`)
	if got, odd := ProfileFileKeys(p, "lockssh", ""); got != nil || odd != nil {
		t.Errorf("password auth: %v %v", got, odd)
	}
	// locksql's keys are not lockssh's, nor the reverse.
	if got, _ := ProfileFileKeys(tomlProfile(`[profiles.p]`, `tls_ca = "~/ca.pem"`), "lockssh", ""); got != nil {
		t.Errorf("tls_ca on lockssh: %v", got)
	}
	if got, _ := ProfileFileKeys(tomlProfile(`[profiles.p]`, `key = "~/k"`), "locksql", ""); got != nil {
		t.Errorf("key on locksql: %v", got)
	}
	// An inline ssh table is locksql's bastion (lockhub#167): on lockssh it
	// adds no ssh.key and is not listed as unreadable; its own keys stay.
	for _, v := range []string{`{ auth = "key", key = "~/.ssh/bastion" }`, `{ auth = "key", opts = { x = 1 } }`} {
		p = tomlProfile(`[profiles.prod]`, `host = "web1"`, `key = "~/.ssh/id"`, `ssh = `+v)
		if got, odd := ProfileFileKeys(p, "lockssh", ""); !reflect.DeepEqual(got, []FileKey{{"key", "~/.ssh/id"}}) || odd != nil {
			t.Errorf("inline ssh on lockssh %s: %v %v", v, got, odd)
		}
	}
}

// lockhub#167 on lockssh: a key and known_hosts into the profile's
// directory are checked in the reviewed copy, not in the home volume.
func TestUpLocksshProfileFiles(t *testing.T) {
	w := newWS(t, sshConf("    profile: prod\n"))
	dir := filepath.Join(w.dir, "projects", ".lockssh")
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[profiles.prod]\nhost = \"web1.example.com\"\nuser = \"deploy\"\nkey = \".lockssh/id\"\nknown_hosts = \".lockssh/known_hosts\"\nssh = { auth = \"key\", key = \"~/.ssh/bastion\" }\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "id"), []byte("KEY\n"), 0o640)
	f := newFake()
	f.keys["web"] = pubKey()
	f.keys["rules/web"] = sshRulesJSON("ask", "auto", "ask", "ask", "prod")
	f.keys["homefiles/web"] = "missing\nmissing\n"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"WARNING: key: .lockssh/id is readable by others (mode 0644): chmod 600 " + filepath.Join(dir, "id"),
		"WARNING: known_hosts: .lockssh/known_hosts is not in the profile's directory: write it " + filepath.Join(dir, "known_hosts") + " (the review copies it)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ssh.key") || strings.Contains(out, "ssh: not a table") || f.ran("homefiles-") {
		t.Errorf("inline ssh or volume check on lockssh: %v\n%s", f.calls, out)
	}
}

// lockssh profile rules --json is read strictly, as locklog's: the four
// actions, each auto, ask or deny; every profile when the lock names
// none; anything else unknown (every ticket asked).
func TestDeriveSSHRules(t *testing.T) {
	m := DeriveSSHRules([]byte(sshRulesJSON("ask", "auto", "deny", "ask", "dev", "prod")), "prod")
	r := m["prod"]
	if len(m) != 1 || r == nil || r.Unknown != "" || r.Get("connect") != "ask" || r.Get("run") != "auto" || r.Get("exec") != "deny" || r.Get("unmask") != "ask" {
		t.Fatalf("rules %+v", m)
	}
	if got := r.Line("web"); got != "lock web auto rules of profile prod: connect ask · run auto · exec deny · unmask ask (lockssh profile rules, on the reviewed copy)" {
		t.Errorf("line %q", got)
	}
	m = DeriveSSHRules([]byte(sshRulesJSON("ask", "auto", "ask", "ask", "dev", "prod")), "")
	if len(m) != 2 || m["dev"].Unknown != "" || m["prod"].Get("run") != "auto" {
		t.Errorf("every profile: %+v", m)
	}
	if lines := SSHRulesLines("web", m); len(lines) != 2 || !strings.Contains(lines[0], "profile dev:") || !strings.Contains(lines[1], "profile prod:") {
		t.Errorf("lines %q", lines)
	}
	for name, out := range map[string]string{
		"empty":        "",
		"not json":     "lockssh: no .lockssh/ here\n",
		"another lock": rulesJSON("auto", "auto", "auto", "prod"),
		"bad value":    sshRulesJSON("ask", "yes", "ask", "ask", "prod"),
		"missing":      `{"lock":"lockssh","profiles":[{"profile":"prod","rules":{"run":"auto"}}]}`,
	} {
		for _, profile := range []string{"prod", ""} {
			m := DeriveSSHRules([]byte(out), profile)
			if len(m) != 1 {
				t.Errorf("%s %q: %+v", name, profile, m)
			}
			for _, r := range m {
				if r.Unknown == "" {
					t.Errorf("%s %q: read as %+v", name, profile, r)
				}
				for _, a := range SSHRuleActions {
					if r.Get(a) != "ask" {
						t.Errorf("%s %q: %s is %s", name, profile, a, r.Get(a))
					}
				}
			}
		}
	}
}

// lox run reads a lockssh lock's rules from its reviewed copy, shows them
// in the review, keeps them for its engine, and routes its read-pii to
// the local facades only.
func TestUpLockssh(t *testing.T) {
	w := newWS(t, sshConf("    profile: prod\n"))
	os.WriteFile(filepath.Join(w.dir, "projects", ".lockssh", "config.toml"), []byte("[profiles.prod]\nhost = \"web1.example.com\"\nuser = \"deploy\"\nkey = \"~/.ssh/id_ed25519\"\n"), 0o644)
	f := newFake()
	f.keys["web"] = pubKey()
	f.keys["rules/web"] = sshRulesJSON("ask", "auto", "ask", "ask", "prod")
	f.keys["homefiles/web"] = "missing\n"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"lock web (lockssh)",
		"ssh deploy@web1.example.com:22",
		"key: /home/lockssh/.ssh/id_ed25519 (~/.ssh/id_ed25519) is not in the lock's home volume; copy it there: docker run --rm -i --network none --user 10041:10040 -v lockfamily-",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(f.upCompose, "web1.example.com") {
		t.Errorf("no gateway for the SSH host:\n%s", f.upCompose)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	m := AppliedSSHRules(filepath.Join(w.dir, "state"), c)
	if r := m["web"]["prod"]; r == nil || r.Get("run") != "auto" || r.Get("connect") != "ask" {
		t.Errorf("applied rules %+v", m)
	}
	sum := strings.Join(Summary(c, "", nil, nil), "\n")
	if !strings.Contains(sum, "lock web answers read-pii on the local facades only, never in a chat") {
		t.Errorf("summary:\n%s", sum)
	}
	r := Routes(c)
	if !reflect.DeepEqual(r.LocalRisks, map[string][]string{"web": {route.ReadPII}}) {
		t.Errorf("routes %+v", r)
	}
	if err := r.Allowed("web", route.Slack, route.ReadPII); err == nil {
		t.Error("slack answers a lockssh read-pii")
	}
	if err := (route.Rules{Enabled: []string{route.TTY, route.Slack}, LocalRisks: r.LocalRisks}).Allowed("web", route.Slack, route.Write); err != nil {
		t.Errorf("slack refused a lockssh write: %v", err)
	}
	// Rules that cannot be read: kept unknown, said, every ticket asked.
	f2 := newFake()
	f2.keys["web"] = pubKey()
	f2.keys["rules/web"] = "garbage\n"
	f2.keys["homefiles/web"] = "ok 600\n"
	if out, err := w.up("y\n", f2); err != nil || !strings.Contains(out, "warning: lock web: auto rules unknown") {
		t.Errorf("unknown rules: %v\n%s", err, out)
	}
	if r := AppliedSSHRules(filepath.Join(w.dir, "state"), c)["web"]["prod"]; r == nil || r.Unknown == "" || r.Get("run") != "ask" {
		t.Errorf("unknown rules applied as %+v", r)
	}
	// Another workspace with no lockssh lock: no local risks.
	if r := Routes(&Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"crm": {Type: "locksql", Image: sqlImg}}}); r.LocalRisks != nil {
		t.Errorf("local risks without lockssh: %+v", r.LocalRisks)
	}
}

// lox add pins only lockssh releases with hub mode (v0.1.0 or later).
func TestLocksshMinRelease(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	r := &Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: &cosignFake{}}
	if _, err := r.Image(context.Background(), "lockssh", "v0.0.9"); err == nil || !strings.Contains(err.Error(), "v0.1.0 or later") {
		t.Errorf("lockssh v0.0.9 pinned: %v", err)
	}
	if _, err := r.Image(context.Background(), "lockssh", "v0.1.0"); err == nil || strings.Contains(err.Error(), "or later") {
		t.Errorf("lockssh v0.1.0: %v", err)
	}
}
