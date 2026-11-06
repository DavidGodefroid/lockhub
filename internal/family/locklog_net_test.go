package family

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A locklog lock with local sources only joins the hub's network alone:
// no locknet, no gateway, no LOCKLOG_NETWORK. With a remote source it is
// on its own network, locknet-<n>, behind its gateway, which no other
// lock joins, and LOCKLOG_NETWORK names it. The other locks keep theirs.
func TestComposeLocklogNetworks(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{
		"logs":     {Type: "locklog", Image: logImg},
		"crm-prod": {Type: "locksql", Image: sqlImg},
	}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	type svc struct {
		Networks    any               `yaml:"networks"`
		Environment map[string]string `yaml:"environment"`
		ExtraHosts  []string          `yaml:"extra_hosts"`
	}
	parse := func(out string) (map[string]svc, map[string]any) {
		t.Helper()
		var v struct {
			Services map[string]svc `yaml:"services"`
			Networks map[string]any `yaml:"networks"`
		}
		if err := yaml.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return v.Services, v.Networks
	}
	nets := func(s svc) []string {
		switch n := s.Networks.(type) {
		case []any:
			var a []string
			for _, x := range n {
				a = append(a, x.(string))
			}
			return a
		case map[string]any:
			var a []string
			for k := range n {
				a = append(a, k)
			}
			slices.Sort(a)
			return a
		}
		return nil
	}
	loki := Egress{Endpoints: []Endpoint{{Host: "loki.example.net", Port: 443, TLS: true, What: "loki source loki"}}}
	db := Egress{Endpoints: []Endpoint{{Host: "db.example.net", Port: 5432, What: "database"}}}
	base := Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0", Project: "lockfamily-0a1b2c3d",
		Egress: map[string]Egress{"logs": loki, "crm-prod": db}}
	for name, lp := range map[string]*LogPlan{
		"not planned yet": nil,
		"local":           {Profile: "app", Lines: []string{"journald"}},
	} {
		p := base
		p.Logs = map[string]*LogPlan{"logs": lp}
		svcs, ns := parse(Compose(c, p))
		l := svcs["lock-logs"]
		if !slices.Equal(nets(l), []string{"lockhub"}) || l.ExtraHosts != nil {
			t.Errorf("%s: lock-logs %+v", name, l)
		}
		if _, ok := l.Environment["LOCKLOG_NETWORK"]; ok {
			t.Errorf("%s: LOCKLOG_NETWORK set", name)
		}
		for _, n := range []string{"locknet-logs", "gwlink-logs", "out-logs"} {
			if _, ok := ns[n]; ok {
				t.Errorf("%s: %s defined", name, n)
			}
		}
		for _, n := range []string{"gw-logs", "gwout-logs"} {
			if _, ok := svcs[n]; ok {
				t.Errorf("%s: %s defined", name, n)
			}
		}
		if s := svcs["lock-crm-prod"]; !slices.Equal(nets(s), []string{"lockhub", "locknet-crm-prod"}) {
			t.Errorf("%s: crm-prod %+v", name, s)
		}
		if _, ok := svcs["gw-crm-prod"]; !ok {
			t.Errorf("%s: crm-prod lost its gateway", name)
		}
	}
	p := base
	p.Logs = map[string]*LogPlan{"logs": {Profile: "app", Lines: []string{"remote"}, Remote: true}}
	out := Compose(c, p)
	svcs, ns := parse(out)
	l := svcs["lock-logs"]
	if !slices.Equal(nets(l), []string{"lockhub", "locknet-logs"}) || l.Environment["LOCKLOG_NETWORK"] != "lockfamily-0a1b2c3d_locknet-logs" || l.ExtraHosts != nil {
		t.Errorf("remote: lock-logs %+v", l)
	}
	if _, ok := ns["locknet-logs"]; !ok {
		t.Errorf("remote: no locknet-logs network:\n%s", out)
	}
	if _, ok := svcs["gw-logs"]; !ok {
		t.Errorf("remote: no gateway:\n%s", out)
	}
	for n, s := range svcs {
		if n != "lock-logs" && n != "gw-logs" && slices.Contains(nets(s), "locknet-logs") {
			t.Errorf("%s joins locknet-logs", n)
		}
	}
	if LockNetwork("lockfamily-0a1b2c3d", "logs") != "lockfamily-0a1b2c3d_locknet-logs" {
		t.Error("LockNetwork")
	}
}

// The allowlist of a locklog lock: its remote sources' urls; file,
// journald and docker sources reach no host.
func TestLocklogEgress(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"logs": {Type: "locklog", Image: logImg, Profile: "app"}}}
	toml := `version = 1
[profiles.app.sources.syslog]
kind = "file"
paths = ["/var/log/syslog*"]
[profiles.app.sources.loki]
kind = "loki"
url = "https://loki.example.net:3101"
[profiles.app.sources.search]
kind = "elastic"
url = "HTTP://search.example.net"
[profiles.app.sources.bad]
kind = "opensearch"
url = "ftp://x.example.net"
[profiles.other.sources.os]
kind = "opensearch"
url = "https://other.example.net"
`
	e, err := lockEgress(c, "logs", profileOf(t, toml))
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{Host: "loki.example.net", Port: 3101, TLS: true, What: "loki source loki"}, {Host: "search.example.net", Port: 80, What: "elastic source search"}}
	if !slices.Equal(e.Endpoints, want) {
		t.Errorf("endpoints %+v", e.Endpoints)
	}
	if len(e.None) != 1 || !strings.Contains(e.None[0], "sources.bad.url") {
		t.Errorf("none %v", e.None)
	}
	if l := localLogEgress(); len(l.Endpoints) != 0 || !strings.Contains(strings.Join(l.Lines("logs"), "\n"), "lock logs egress none") {
		t.Errorf("local egress %+v", l)
	}
}

// lox run says which network a locklog lock gets, passes its network's
// engine name, and gives a remote source its gateway; local sources
// reach nothing, whatever the profile names.
func TestUpLocklogNetworkReviewed(t *testing.T) {
	h, _ := logHost(t)
	w := newWS(t, logConf("    profile: app\n"))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locklog", "config.toml"), []byte("version = 1\n[profiles.app.sources.loki]\nkind = \"loki\"\nurl = \"https://loki.example.net\"\n"), 0o644)
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nremote\n"
	out, err := upLog(w, h, "y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	project := Project(ws)
	net := project + "_locknet-logs"
	if !strings.Contains(out, "lock logs network lockhub and "+net+", its own, which no agent joins") {
		t.Errorf("review:\n%s", out)
	}
	if !strings.Contains(block(f.upCompose, "lock-logs"), `LOCKLOG_NETWORK: "`+net+`"`) {
		t.Errorf("compose:\n%s", block(f.upCompose, "lock-logs"))
	}
	if !strings.Contains(block(f.upCompose, "gw-logs"), "loki.example.net") {
		t.Errorf("no gateway for the remote source:\n%s", f.upCompose)
	}
	// Local sources only: a reviewed change, no route out.
	f.keys["plan/logs"] = "profile app false\njournald\n"
	f2 := &fake{keys: f.keys}
	out, err = upLog(w, h, "y\n", f2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "lock logs network lockhub only (local sources: no route out)") {
		t.Errorf("network change not reviewed:\n%s", out)
	}
	lb := block(f2.upCompose, "lock-logs")
	if strings.Contains(lb, "LOCKLOG_NETWORK") || strings.Contains(lb, "locknet-logs") || strings.Contains(f2.upCompose, "gw-logs") {
		t.Errorf("local sources: a route out:\n%s", f2.upCompose)
	}
}

// A locklog lock is never routed to a chat facade: hub.routing naming one
// is refused, and with no entry it is answered on tty, deck and mobile.
func TestLocklogRouting(t *testing.T) {
	load := func(conf string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "lockfamily.yaml")
		os.WriteFile(p, []byte(conf), 0o644)
		return Load(p)
	}
	for name, routing := range map[string]string{
		"slack":    slackHub + "  routing:\n    logs: [tty, slack]\n",
		"telegram": tgHub + "  routing:\n    logs: [telegram]\n",
	} {
		if _, err := load(strings.Replace(logConf(""), "locks:\n", routing+"locks:\n", 1)); err == nil || !strings.Contains(err.Error(), "locklog") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A chat facade stays fine for the other locks.
	c, err := load(strings.Replace(logConf(""), "locks:\n", slackHub+"  routing:\n    crm-prod: [slack]\n    logs: [deck]\nlocks:\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	if r := Routes(c); !slices.Equal(r.Only["logs"], []string{"deck"}) || !slices.Equal(r.Only["crm-prod"], []string{"slack"}) || r.Only["events"] != nil {
		t.Errorf("explicit routing: %v", r.Only)
	}
	if c, err = load(strings.Replace(logConf(""), "locks:\n", slackHub+"locks:\n", 1)); err != nil {
		t.Fatal(err)
	}
	if r := Routes(c); !slices.Equal(r.Only["logs"], LocklogFacades) || r.Only["crm-prod"] != nil {
		t.Errorf("default: %v", r.Only)
	}
	// The review line is what the hub applies: this hub runs tty, deck
	// and slack, so mobile is not in it, and slack never is.
	if s := strings.Join(Summary(c, "k", nil, nil), "\n"); !strings.Contains(s, "lock logs routed only to tty,deck (locklog's default: no chat facade)") {
		t.Errorf("review:\n%s", s)
	}
	// With mobile on and no device pinned: mobile narrowed away too.
	if c, err = load(strings.Replace(logConf(""), "locks:\n", plainMobile+"locks:\n", 1)); err != nil {
		t.Fatal(err)
	}
	if r := Routes(c); !slices.Equal(r.Only["logs"], []string{"tty", "deck"}) {
		t.Errorf("mobile, no device: %v", r.Only)
	}
	if s := strings.Join(Summary(c, "k", nil, nil), "\n"); !strings.Contains(s, "lock logs routed only to tty,deck (locklog's default: no chat facade)") {
		t.Errorf("mobile, no device: review:\n%s", s)
	}
	// Mobile on and the lock pins the devices: mobile is in it.
	if c, err = load(strings.Replace(logConf("    devices: true\n"), "locks:\n", plainMobile+"locks:\n", 1)); err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(Summary(c, "k", nil, nil), "\n"); !strings.Contains(s, "lock logs routed only to tty,deck,mobile (locklog's default: no chat facade)") {
		t.Errorf("mobile, devices: review:\n%s", s)
	}
	// An explicit entry, narrowed the same way: no device pinned.
	if c, err = load(strings.Replace(logConf(""), "locks:\n", plainMobile+"  routing:\n    logs: [deck, mobile]\nlocks:\n", 1)); err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(Summary(c, "k", nil, nil), "\n"); !strings.Contains(s, "lock logs routed only to deck (hub.routing)") {
		t.Errorf("explicit: review:\n%s", s)
	}
	if c, err = load(strings.Replace(logConf(""), "locks:\n", plainMobile+"  routing:\n    logs: [mobile]\nlocks:\n", 1)); err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(Summary(c, "k", nil, nil), "\n"); !strings.Contains(s, "lock logs routed only to no facade (hub.routing)") {
		t.Errorf("nothing left: review:\n%s", s)
	}
}

// plainMobile is the mobile facade with no device requirement.
const plainMobile = "  facades: [tty, deck, mobile]\n  mobile:\n    origin: https://hub.example.net\n"

// lox doctor checks routing.json against what lox run writes (Routes):
// the narrowed routing passes, a real difference still fails.
func TestDoctorRoutingIsRoutes(t *testing.T) {
	h, _ := logHost(t)
	conf := strings.Replace(logConf(""), "locks:\n", plainMobile+"locks:\n", 1)
	conf = strings.Replace(conf, "    image: "+sqlImg+"\n", "    image: "+sqlImg+"\n    devices: true\n", 1)
	w := newWS(t, conf)
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nremote\n"
	if out, err := upLog(w, h, "y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	d := &Doctor{State: filepath.Join(w.dir, "state")}
	var lines []string
	rec := func(p string) func(string, ...any) {
		return func(fm string, a ...any) { lines = append(lines, p+fmt.Sprintf(fm, a...)) }
	}
	d.routing(c, rec("ok "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "ok hub routing") {
		t.Errorf("routing lox up wrote (events and logs narrowed): %v", lines)
	}
	rj := filepath.Join(d.State, "hub", "routing.json")
	b, _ := os.ReadFile(rj)
	os.WriteFile(rj, []byte(strings.Replace(string(b), `"logs": [`, `"logs": ["mobile", `, 1)), 0o600)
	lines = nil
	d.routing(c, rec("ok "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "fail hub routing") {
		t.Errorf("a changed routing.json passes: %v\n%s", lines, b)
	}
}

// Local sources need an engine that keeps the binds non-recursive (19.03
// or later) and one that says it is rootful: fail closed otherwise. A
// remote source mounts nothing and asks neither.
func TestDeriveLogPlanEngine(t *testing.T) {
	h, logs := logHost(t)
	local := "profile a false\nfile " + logs + " " + logs + "/*.log\n"
	ver := "docker version --format {{.Server.Version}}"
	for v, ok := range map[string]bool{
		"27.3.1\n": true, "19.03.0\n": true, "20.10.24+dfsg1\n": true, "25.0\n": true,
		"19.02.9\n": false, "18.09.1-ce\n": false, "1.13.1\n": false, "\n": false, "dev\n": false,
	} {
		_, err := derive(t, h, &fake{keys: map[string]string{"docker/" + ver: v}}, local)
		if (err == nil) != ok {
			t.Errorf("engine %q: %v", strings.TrimSpace(v), err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "19.03")) {
			t.Errorf("engine %q: refusal %v", strings.TrimSpace(v), err)
		}
	}
	if _, err := derive(t, h, &fake{failing: "docker version"}, "profile a false\ndocker web-*\n"); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Errorf("no engine version: %v", err)
	}
	if _, err := derive(t, h, &fake{failing: "SecurityOptions"}, local); err == nil || !strings.Contains(err.Error(), "rootless") {
		t.Errorf("docker info failing: %v", err)
	}
	f := &fake{failing: "docker "}
	if p, err := derive(t, h, f, "profile a false\nremote\n"); err != nil || !p.Remote || len(f.calls) != 0 {
		t.Errorf("remote: %v %v", err, f.calls)
	}
}

// A locklog lock never applied with a mount plan (a workspace from before
// lox run derived them): lox doctor warns and says to run lox run; a plan
// it cannot read still fails.
func TestDoctorLocklogNoPlan(t *testing.T) {
	state := t.TempDir()
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"logs": {Type: "locklog", Image: logImg}}}
	d := &Doctor{State: state, Run: &fake{}}
	var lines []string
	rec := func(p string) func(string, ...any) {
		return func(fm string, a ...any) { lines = append(lines, p+fmt.Sprintf(fm, a...)) }
	}
	d.logMaps(context.Background(), c, rec("ok "), rec("warn "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "warn lock logs mount plan") || !strings.Contains(lines[0], "run lox run") {
		t.Errorf("no plan: %v", lines)
	}
	os.MkdirAll(logDir(state, "logs"), 0o700)
	os.Chmod(filepath.Join(state, "locklog"), 0o700)
	os.WriteFile(filepath.Join(logDir(state, "logs"), planFile), []byte("{"), 0o600)
	lines = nil
	d.logMaps(context.Background(), c, rec("ok "), rec("warn "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "fail lock logs") {
		t.Errorf("unreadable plan: %v", lines)
	}
}
