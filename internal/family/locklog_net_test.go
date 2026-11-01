package family

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A locklog lock with local sources only joins the hub's network alone;
// with a remote source, also its own egress network (LOCKLOG_NETWORK),
// which no other service joins. The other locks keep theirs.
func TestComposeLocklogNetworks(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{
		"logs":     {Type: "locklog", Image: logImg},
		"crm-prod": {Type: "locksql", Image: sqlImg},
	}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	type svc struct {
		Networks    []string          `yaml:"networks"`
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
	base := Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0", Project: "lockfamily-0a1b2c3d"}
	for name, lp := range map[string]*LogPlan{
		"not planned yet": nil,
		"local":           {Profile: "app", Lines: []string{"journald"}},
	} {
		p := base
		p.Logs = map[string]*LogPlan{"logs": lp}
		svcs, nets := parse(Compose(c, p))
		l := svcs["lock-logs"]
		if !slices.Equal(l.Networks, []string{"lockhub"}) || l.ExtraHosts != nil || l.Environment["LOCKLOG_NETWORK"] != "" {
			t.Errorf("%s: lock-logs %+v", name, l)
		}
		if _, ok := nets["egress-logs"]; ok {
			t.Errorf("%s: egress-logs defined", name)
		}
		if s := svcs["lock-crm-prod"]; !slices.Equal(s.Networks, []string{"lockhub", "egress-crm-prod"}) || s.ExtraHosts == nil {
			t.Errorf("%s: crm-prod %+v", name, s)
		}
	}
	p := base
	p.Logs = map[string]*LogPlan{"logs": {Profile: "app", Lines: []string{"remote"}, Remote: true}}
	out := Compose(c, p)
	svcs, nets := parse(out)
	l := svcs["lock-logs"]
	if !slices.Equal(l.Networks, []string{"lockhub", "egress-logs"}) || l.Environment["LOCKLOG_NETWORK"] != "lockfamily-0a1b2c3d_egress-logs" || l.ExtraHosts == nil {
		t.Errorf("remote: lock-logs %+v", l)
	}
	if _, ok := nets["egress-logs"]; !ok {
		t.Errorf("remote: no egress-logs network:\n%s", out)
	}
	for n, s := range svcs {
		if n != "lock-logs" && slices.Contains(s.Networks, "egress-logs") {
			t.Errorf("%s joins egress-logs", n)
		}
	}
	if EgressNetwork("lockfamily-0a1b2c3d", "logs") != "lockfamily-0a1b2c3d_egress-logs" {
		t.Error("EgressNetwork")
	}
}

// lox up says which network a locklog lock gets, and passes the egress
// network's engine name.
func TestUpLocklogNetworkReviewed(t *testing.T) {
	h, _ := logHost(t)
	w := newWS(t, logConf(""))
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nremote\n"
	out, err := upLog(w, h, "y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	project := Project(filepath.Dir(filepath.Dir(w.file)))
	net := project + "_egress-logs"
	if !strings.Contains(out, "lock logs network lockhub and "+net+", its own, which no agent joins") {
		t.Errorf("review:\n%s", out)
	}
	if !strings.Contains(block(f.upCompose, "lock-logs"), `LOCKLOG_NETWORK: "`+net+`"`) {
		t.Errorf("compose:\n%s", block(f.upCompose, "lock-logs"))
	}
	// Local sources only: a reviewed change, no route out.
	f.keys["plan/logs"] = "profile app false\njournald\n"
	out, _ = upLog(w, h, "", &fake{keys: f.keys})
	if !strings.Contains(out, "+ lock logs network lockhub only (local sources: no route out)") || !strings.Contains(out, "- lock logs network lockhub and") {
		t.Errorf("network change not reviewed:\n%s", out)
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
	if s := strings.Join(Summary(c, "k", nil, nil), "\n"); !strings.Contains(s, "lock logs routed only to tty,deck,mobile (locklog's default: no chat facade)") {
		t.Errorf("review:\n%s", s)
	}
	// With mobile on and no device pinned: mobile narrowed away too.
	if c, err = load(strings.Replace(logConf(""), "locks:\n", plainMobile+"locks:\n", 1)); err != nil {
		t.Fatal(err)
	}
	if r := Routes(c); !slices.Equal(r.Only["logs"], []string{"tty", "deck"}) {
		t.Errorf("mobile, no device: %v", r.Only)
	}
}

// plainMobile is the mobile facade with no device requirement.
const plainMobile = "  facades: [tty, deck, mobile]\n  mobile:\n    origin: https://hub.example.net\n"

// lox doctor checks routing.json against what lox up writes (Routes):
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
