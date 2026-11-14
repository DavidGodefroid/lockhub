package family

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A lock's gateway joining existing networks (lockhub#194).

func TestNetworksConfig(t *testing.T) {
	ok := lockConf(t, "locksql", "", "    networks: [shop, my_cache.net]\n")
	if got := ok.Locks["x"].Networks; !slices.Equal(got, []string{"shop", "my_cache.net"}) {
		t.Fatalf("networks %v", got)
	}
	for name, tc := range map[string]struct{ typ, lock, err string }{
		"host":          {"locksql", "    networks: [host]\n", "host is the engine's own network"},
		"none":          {"locksql", "    networks: [none]\n", "none is the engine's own network"},
		"bridge":        {"lockmq", "    networks: [bridge]\n", "bridge is the engine's own network"},
		"lock network":  {"locksql", "    networks: [lockfamily-ab12_locknet-x]\n", "named as a network of lox run's own"},
		"link network":  {"locksql", "    networks: [gwlink-x]\n", "named as a network of lox run's own"},
		"out network":   {"locksql", "    networks: [p_out-x]\n", "named as a network of lox run's own"},
		"hub network":   {"locksql", "    networks: [p_lockhub]\n", "named as a network of lox run's own"},
		"hub egress":    {"locksql", "    networks: [egress-hub]\n", "named as a network of lox run's own"},
		"twice":         {"locksql", "    networks: [shop, shop]\n", "shop is listed twice"},
		"not a name":    {"locksql", "    networks: [\"shop net\"]\n", "is not a Docker network name"},
		"lockhttp lock": {"lockhttp", "    networks: [shop]\n", "a lockhttp lock's egress is its own policy's"},
	} {
		t.Run(name, func(t *testing.T) {
			img := map[string]string{"locksql": sqlImg, "lockmq": mqImg, "lockhttp": httpImg}[tc.typ]
			y := strings.NewReplacer("%VAULT%", "", "%TYPE%", tc.typ, "%IMG%", img, "%LOCK%", tc.lock).Replace(oneLock)
			p := filepath.Join(t.TempDir(), "lockfamily.yaml")
			os.WriteFile(p, []byte(y), 0o644)
			_, err := Load(p)
			if err == nil || !strings.Contains(err.Error(), "locks.x.networks: ") || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err %v, want %q", err, tc.err)
			}
		})
	}
}

func TestCheckJoinNets(t *testing.T) {
	c := lockConf(t, "locksql", "", "    networks: [shop]\n")
	net := func(name, project, role string) EngineNet {
		n := EngineNet{Name: name, Labels: map[string]string{}}
		if project != "" {
			n.Labels["com.docker.compose.project"] = project
		}
		if role != "" {
			n.Labels[LabelRole] = role
		}
		return n
	}
	hub := net("lockfamily-1234_lockhub", "lockfamily-1234", RoleHub)
	for name, tc := range map[string]struct {
		nets []EngineNet
		err  string
	}{
		"exists":         {nets: []EngineNet{hub, net("shop", "shopstack", "")}},
		"missing":        {nets: []EngineNet{hub, net("shopping", "", "")}, err: "locks.x.networks: no network shop on the engine"},
		"labelled lox":   {nets: []EngineNet{net("shop", "", RoleHub)}, err: "shop is a network of a lox workspace"},
		"lox project's":  {nets: []EngineNet{hub, net("shop", "lockfamily-1234", "")}, err: "shop is a network of a lox workspace"},
		"none on engine": {err: "no network shop on the engine"},
	} {
		t.Run(name, func(t *testing.T) {
			err := CheckJoinNets(c, tc.nets)
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err %v, want %q", err, tc.err)
			}
		})
	}
}

// A dotless host is reached through the joined network by gwnet-<n>
// alone; a dotted one through out-<n> by gwout-<n>, which never joins it.
func TestJoinNetEgressAndCompose(t *testing.T) {
	c := lockConf(t, "locksql", "vault:\n  address: https://vault.example.com:8200\n", "    vault: true\n    networks: [shop]\n")
	es, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, "[profiles.p]\nengine = \"postgres\"\nhost = \"db\"\ncredentials = \"vault\"\nvault_path = \"db/creds/ro\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	e := es["x"]
	lines := strings.Join(e.Lines("x"), "\n")
	for _, s := range []string{"lock x egress db:5432 (database) via network shop", "lock x egress vault.example.com:8200 (vault)\n"} {
		if !strings.Contains(lines+"\n", s) {
			t.Errorf("lines lack %q:\n%s", s, lines)
		}
	}
	if got := e.Short(); got != "only db:5432 via network shop, vault.example.com:8200" {
		t.Errorf("short %q", got)
	}
	front, back, joined := e.forwards("x")
	if len(front) != 2 || front[0].Host != "gwnet-x" || front[1].Host != "gwout-x" {
		t.Errorf("front %v", front)
	}
	if len(joined) != 1 || joined[0].Host != "db" || len(back) != 1 || back[0].Host != "vault.example.com" {
		t.Errorf("joined %v back %v", joined, back)
	}

	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0", Egress: es})
	if s := service(out, q("join-shop")); !strings.Contains(s, "external: true\n") || !strings.Contains(s, `name: "shop"`) {
		t.Errorf("join-shop is not the existing network shop:\n%s", s)
	}
	gwnet := service(out, q("gwnet-x"))
	if !strings.Contains(gwnet, `networks: ["gwlink-x", "join-shop"]`) || !strings.Contains(gwnet, `command: ["egress-gateway", "--forward", "20000=db:5432"]`) {
		t.Errorf("gwnet-x:\n%s", gwnet)
	}
	// A container on shop reaches gwnet-x, which forwards only shop's own
	// endpoint: never the vault, never anything dotted.
	if strings.Contains(gwnet, "vault.example.com") || strings.Contains(gwnet, "out-x") || strings.Contains(gwnet, "host-gateway") {
		t.Errorf("gwnet-x reaches the route out:\n%s", gwnet)
	}
	// gwout-x and the console never join shop.
	gwout := service(out, q("gwout-x"))
	if !strings.Contains(gwout, `networks: ["gwlink-x", "out-x"]`) || strings.Contains(gwout, "join-shop") || strings.Contains(gwout, "db:5432") {
		t.Errorf("gwout-x:\n%s", gwout)
	}
	lock := service(out, "lock-x")
	if lock == "" || strings.Contains(lock, "join-shop") || strings.Contains(lock, "shop") {
		t.Errorf("the console joins shop:\n%s", lock)
	}
	if n := strings.Count(out, "join-shop"); n != 2 {
		t.Errorf("join-shop %d times, want 2 (gwnet-x and the network):\n%s", n, out)
	}
}

// A container on the joined network named like a dotted endpoint
// (an alias prod.example.com on shop) answers for nothing: dotted names
// are resolved by gwout-<n> alone, which is not on shop.
func TestJoinNetAliasHijackRefused(t *testing.T) {
	c := lockConf(t, "lockmq", "", "    networks: [shop]\n")
	es, err := Egresses(c, map[string]*Profile{"lockmq": profileOf(t, "[profiles.e]\nurl = \"https://prod.example.com\"\namqp_url = \"amqp://rabbit\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	_, back, joined := es["x"].forwards("x")
	for _, f := range joined {
		if strings.Contains(f.Host, ".") {
			t.Errorf("gwnet-x resolves %s on shop", f.Host)
		}
	}
	if len(joined) != 1 || joined[0].Host != "rabbit" || len(back) != 1 || back[0].Host != "prod.example.com" {
		t.Errorf("joined %v back %v", joined, back)
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0", Egress: es})
	if strings.Contains(service(out, q("gwout-x")), "join-shop") {
		t.Error("gwout-x joins shop")
	}
}

// Only endpoints on the joined network: no gwout-x and no route out.
func TestJoinNetOnlyNoRouteOut(t *testing.T) {
	c := lockConf(t, "locksql", "", "    networks: [shop]\n")
	es, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, "[profiles.p]\nengine = \"postgres\"\nhost = \"db\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0", Egress: es})
	if service(out, q("gwout-x")) != "" || service(out, q("out-x")) != "" {
		t.Errorf("a route out with no endpoint through it:\n%s", out)
	}
	if service(out, q("gwnet-x")) == "" || !strings.Contains(service(out, q("gw-x")), `"5432=gwnet-x:20000"`) {
		t.Errorf("gw-x does not forward to gwnet-x:\n%s", out)
	}
}

// Without networks, a dotless host is reached as before (out-<n>), and
// nothing joins any network.
func TestNoNetworksUnchanged(t *testing.T) {
	c := lockConf(t, "locksql", "", "")
	es, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, "[profiles.p]\nengine = \"postgres\"\nhost = \"db\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if l := es["x"].Lines("x"); !slices.Equal(l, []string{"lock x egress db:5432 (database)"}) {
		t.Errorf("lines %v", l)
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0", Egress: es})
	if strings.Contains(out, "gwnet-") || strings.Contains(out, "join-") || strings.Contains(out, "external:") {
		t.Errorf("joins a network:\n%s", out)
	}
	if !strings.Contains(service(out, q("gwout-x")), `"20000=db:5432"`) {
		t.Errorf("gwout-x:\n%s", out)
	}
}

// lox run reviews the joined networks, checks them on the engine before
// anything starts, and applies gwnet-<n>.
func TestJoinNetUp(t *testing.T) {
	conf := strings.Replace(yamlConf(""), "    type: locksql\n", "    type: locksql\n    networks: [shop]\n", 1)
	w := newWS(t, conf)
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db\"\n"), 0o644)

	t.Run("missing network", func(t *testing.T) {
		f := newFake()
		out, err := w.up("y\n", f)
		if err == nil || !strings.Contains(err.Error(), "locks.crm-prod.networks: no network shop on the engine") {
			t.Fatalf("err %v\n%s", err, out)
		}
		if f.upCompose != "" {
			t.Error("applied without the network")
		}
	})
	t.Run("applied", func(t *testing.T) {
		f := newFake()
		f.keys["networks"] = "n1\n"
		f.keys["docker/docker network inspect n1"] = `[{"Name":"shop","Labels":{"com.docker.compose.project":"shopstack"}}]`
		out, err := w.up("y\n", f)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, s := range []string{"  egress       only db:5432 via network shop\n", "  networks     shop (its gateway gwnet only, for dotless host names)\n"} {
			if !strings.Contains(out, s) {
				t.Errorf("review lacks %q:\n%s", s, out)
			}
		}
		if strings.Contains(out, "lock crm-prod joins networks") {
			t.Errorf("the networks line is listed besides the row:\n%s", out)
		}
		if !strings.Contains(service(f.upCompose, q("gwnet-crm-prod")), `networks: ["gwlink-crm-prod", "join-shop"]`) {
			t.Errorf("applied compose lacks gwnet-crm-prod:\n%s", f.upCompose)
		}
		b, _ := os.ReadFile(filepath.Join(w.dir, "state", "applied.json"))
		for _, s := range []string{"lock crm-prod egress db:5432 (database) via network shop", "lock crm-prod joins networks shop"} {
			if !strings.Contains(string(b), s) {
				t.Errorf("applied.json lacks %q", s)
			}
		}
	})
}

// lox doctor checks gwnet-<n> as it checks gwout-<n>: running, and
// forwarding the reviewed endpoints.
func TestDoctorJoinNet(t *testing.T) {
	setup := func(t *testing.T) (*Doctor, *answers) {
		d, a := healthy(t)
		b, _ := os.ReadFile(d.File)
		os.WriteFile(d.File, []byte(strings.Replace(string(b), "    type: locksql\n", "    type: locksql\n    networks: [shop]\n", 1)), 0o644)
		ws := filepath.Dir(filepath.Dir(d.File))
		os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db\"\n"), 0o644)
		f := newFake()
		f.keys["networks"] = "n1\n"
		f.keys["docker/docker network inspect n1"] = `[{"Name":"shop","Labels":{}}]`
		u := &Up{File: d.File, State: d.State, Runtime: d.Runtime, User: "1000:1000", Run: f, In: bufio.NewReader(strings.NewReader("y\n")), Out: &strings.Builder{}}
		if err := u.Do(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.out["ps --all --format json"] = `{"Service":"lockhub","State":"running"}
{"Service":"lock-crm-prod","State":"running"}
{"Service":"lock-events","State":"running"}
{"Service":"gw-crm-prod","State":"running"}
{"Service":"gwnet-crm-prod","State":"running"}
`
		a.out["{{json .Config.Cmd}}"] = `["egress-gateway","--forward","20000=db:5432"]`
		return d, a
	}
	t.Run("healthy", func(t *testing.T) {
		d, _ := setup(t)
		if out, n := doc(t, d); n != 0 || !strings.Contains(out, "ok   lock crm-prod egress: only db:5432 (internal networks, gateway running)") {
			t.Fatalf("%d:\n%s", n, out)
		}
	})
	t.Run("gwnet stopped", func(t *testing.T) {
		d, a := setup(t)
		a.out["ps --all --format json"] = strings.Replace(a.out["ps --all --format json"], `"gwnet-crm-prod","State":"running"`, `"gwnet-crm-prod","State":"exited"`, 1)
		if out, n := doc(t, d); n == 0 || !strings.Contains(out, "FAIL lock crm-prod egress: its gateway gwnet-crm-prod is exited") {
			t.Fatalf("%d:\n%s", n, out)
		}
	})
}
