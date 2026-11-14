package family

import (
	"bufio"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files of testdata")

// profileOf is a reviewed profile copy with one config.toml.
func profileOf(t *testing.T, toml string) *Profile {
	t.Helper()
	d := t.TempDir()
	os.Chmod(d, 0o755)
	if toml != "" {
		if err := os.WriteFile(filepath.Join(d, "config.toml"), []byte(toml), 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(d, "config.toml"), 0o644)
	}
	p, err := ReadProfile(d, 10001, 10000)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func confOf(t *testing.T, yaml string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	os.WriteFile(p, []byte(yaml), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func addrs(e Egress) []string {
	var a []string
	for _, x := range e.Endpoints {
		a = append(a, x.Addr())
	}
	return a
}

const oneLock = `version: 1
hub:
  image: ` + hubImg + `
%VAULT%locks:
  x:
    type: %TYPE%
    image: %IMG%
%LOCK%`

func lockConf(t *testing.T, typ, vault, lock string) *Config {
	img := map[string]string{"locksql": sqlImg, "lockmq": mqImg, "lockfile": fileImg, "lockhttp": httpImg}[typ]
	y := strings.NewReplacer("%VAULT%", vault, "%TYPE%", typ, "%IMG%", img, "%LOCK%", lock).Replace(oneLock)
	return confOf(t, y)
}

func TestEgressFromReviewedProfile(t *testing.T) {
	for name, tc := range map[string]struct {
		typ, vault, lock, toml string
		want                   []string
		none                   string
	}{
		"postgres": {typ: "locksql", toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"DB.example.com\"\nport = 6432\n", want: []string{"db.example.com:6432"}},
		"default port": {typ: "locksql", toml: "[profiles.p]\nengine = \"mariadb\"\nhost = \"host.docker.internal\"\n",
			want: []string{"host.docker.internal:3306"}},
		"sqlite":      {typ: "locksql", toml: "[profiles.p]\nengine = \"sqlite\"\npath = \"/data/x.db\"\n", none: "lock reaches no host"},
		"ssh":         {typ: "locksql", toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"10.0.0.5\"\n[profiles.p.ssh]\nhost = \"bastion.example.com\"\nuser = \"u\"\n", want: []string{"bastion.example.com:22"}},
		"loopback":    {typ: "locksql", toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"127.0.0.1\"\n", none: "lock reaches no host"},
		"loopback v6": {typ: "lockmq", toml: "[profiles.e]\nurl = \"http://[::1]:15672\"\n", none: "lock reaches no host"},
		"odd port":    {typ: "locksql", toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"db.example.com\"\nport = \"5432\"\n", none: "engine, host or port cannot be read"},
		"no file":     {typ: "locksql", none: "no config.toml"},
		"not toml":    {typ: "locksql", toml: "[profiles.p\n", none: "not TOML"},
		"named profile only": {typ: "locksql", lock: "    profile: b\n",
			toml: "[profiles.a]\nengine = \"postgres\"\nhost = \"a.example.com\"\n[profiles.b]\nengine = \"postgres\"\nhost = \"b.example.com\"\n", want: []string{"b.example.com:5432"}},
		"every profile when none named": {typ: "locksql",
			toml: "[profiles.a]\nengine = \"postgres\"\nhost = \"a.example.com\"\n[profiles.b]\nengine = \"mysql\"\nhost = \"b.example.com\"\n", want: []string{"a.example.com:5432", "b.example.com:3306"}},
		"lockmq": {typ: "lockmq", toml: "[profiles.e]\nurl = \"https://mq.example.com/api-prefix\"\namqp_url = \"amqps://mq.example.com\"\nstream_url = \"rabbitmq-stream://mq.example.com:5553\"\n",
			want: []string{"mq.example.com:443", "mq.example.com:5553", "mq.example.com:5671"}},
		"lockmq plain": {typ: "lockmq", toml: "[profiles.e]\nurl = \"http://host.docker.internal:15672\"\namqp_url = \"amqp://host.docker.internal\"\n",
			want: []string{"host.docker.internal:5672", "host.docker.internal:15672"}},
		"s3 aws":      {typ: "lockfile", toml: "[profiles.default]\nsource = \"s3\"\nbucket = \"docs\"\nregion = \"eu-west-1\"\n", want: []string{"docs.s3.eu-west-1.amazonaws.com:443"}},
		"s3 endpoint": {typ: "lockfile", toml: "[profiles.default]\nsource = \"s3\"\nbucket = \"docs\"\nendpoint = \"https://minio.example.com:9000\"\n", want: []string{"minio.example.com:9000"}},
		"sftp":        {typ: "lockfile", toml: "[profiles.default]\nsource = \"sftp\"\nhost = \"files.example.com\"\nport = 2222\n", want: []string{"files.example.com:2222"}},
		"local":       {typ: "lockfile", toml: "[profiles.default]\nsource = \"local\"\npath = \"/data\"\n", none: "lock reaches no host"},
		"vault lock": {typ: "locksql", vault: "vault:\n  address: https://vault.example.com:8200\n", lock: "    vault: true\n",
			toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"db.example.com\"\ncredentials = \"vault\"\nvault_path = \"db/creds/ro\"\n", want: []string{"db.example.com:5432", "vault.example.com:8200"}},
		"vault block, lock without vault": {typ: "locksql", vault: "vault:\n  address: https://vault.example.com:8200\n",
			toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"db.example.com\"\n", want: []string{"db.example.com:5432"}},
		"vault default port": {typ: "lockmq", vault: "vault:\n  address: https://vault.example.com\n", lock: "    vault: true\n",
			toml: "[profiles.e]\nurl = \"https://mq.example.com\"\n", want: []string{"mq.example.com:443", "vault.example.com:443"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := lockConf(t, tc.typ, tc.vault, tc.lock)
			es, err := Egresses(c, map[string]*Profile{tc.typ: profileOf(t, tc.toml)})
			if err != nil {
				t.Fatal(err)
			}
			e := es["x"]
			if got := addrs(e); !slices.Equal(got, tc.want) {
				t.Errorf("endpoints %v, want %v", got, tc.want)
			}
			lines := strings.Join(e.Lines("x"), "\n")
			if tc.none != "" && !strings.Contains(lines, tc.none) {
				t.Errorf("lines lack %q:\n%s", tc.none, lines)
			}
			if tc.none == "" && strings.Contains(lines, "unreachable") {
				t.Errorf("unexpected unreachable:\n%s", lines)
			}
		})
	}
}

func TestEgressLockhttpKeepsItsPolicy(t *testing.T) {
	c := lockConf(t, "lockhttp", "", "")
	es, err := Egresses(c, map[string]*Profile{"lockhttp": profileOf(t, "[profiles.default]\nmode = \"enforce\"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if !es["x"].Own || len(es["x"].Lines("x")) != 0 {
		t.Errorf("lockhttp: %+v", es["x"])
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0", Egress: es})
	if !strings.Contains(out, "  \"egress-x\": {}\n") || strings.Contains(out, "gw-x") {
		t.Errorf("lockhttp's egress network changed:\n%s", out)
	}
}

func TestEgressPortCollisions(t *testing.T) {
	vault := "vault:\n  address: %s\n"
	for name, tc := range map[string]struct {
		addr, toml string
		err        string
		sni        bool
	}{
		// Both TLS: one port, routed by server name.
		"tls shares": {addr: "https://vault.example.com", toml: "[profiles.e]\nurl = \"https://mq.example.com\"\n", sni: true},
		// The same endpoint twice is one endpoint.
		"same endpoint": {addr: "http://host.docker.internal:15672", toml: "[profiles.e]\nurl = \"http://host.docker.internal:15672\"\n"},
		"plain collides": {addr: "http://vault.example.com:15672", toml: "[profiles.e]\nurl = \"https://mq.example.com:15672\"\n",
			err: "share port 15672 on the lock's gateway, and vault.example.com:15672 does not start with TLS"},
	} {
		t.Run(name, func(t *testing.T) {
			c := lockConf(t, "lockmq", strings.Replace(vault, "%s", tc.addr, 1), "    vault: true\n")
			es, err := Egresses(c, map[string]*Profile{"lockmq": profileOf(t, tc.toml)})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			front, back := es["x"].forwards("x")
			sni := false
			for _, f := range front {
				sni = sni || f.SNI != ""
			}
			if sni != tc.sni || len(front) != len(back) {
				t.Errorf("front %v back %v", front, back)
			}
		})
	}
}

// An IP address is refused before anything starts (lockhub#145): the
// gateway answers by host name only, so the lock could never reach it.
// The refusal names the key and the fix.
func TestEgressRefusesIPAddresses(t *testing.T) {
	for name, tc := range map[string]struct{ typ, vault, lock, toml, key string }{
		"database host": {typ: "locksql", toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"10.1.2.3\"\n", key: "profiles.p.host in config.toml (database): 10.1.2.3"},
		"ssh bastion": {typ: "locksql", toml: "[profiles.shop-prod]\nengine = \"postgres\"\nhost = \"db.internal\"\n[profiles.shop-prod.ssh]\nhost = \"203.0.113.10\"\nuser = \"u\"\n",
			key: "profiles.shop-prod.ssh.host in config.toml (ssh): 203.0.113.10"},
		"ipv6":        {typ: "locksql", toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"2001:db8::5\"\n", key: "profiles.p.host in config.toml (database): 2001:db8::5"},
		"broker url":  {typ: "lockmq", toml: "[profiles.e]\nurl = \"http://[2001:db8::1]:15672\"\n", key: "profiles.e.url in config.toml (broker management API): 2001:db8::1"},
		"s3 endpoint": {typ: "lockfile", toml: "[profiles.default]\nsource = \"s3\"\nbucket = \"docs\"\nendpoint = \"http://192.0.2.7:9000\"\n", key: "profiles.default.endpoint in config.toml (s3): 192.0.2.7"},
		"sftp":        {typ: "lockfile", toml: "[profiles.default]\nsource = \"sftp\"\nhost = \"192.0.2.8\"\n", key: "profiles.default.host in config.toml (sftp): 192.0.2.8"},
		"vault": {typ: "locksql", vault: "vault:\n  address: https://192.0.2.9:8200\n", lock: "    vault: true\n",
			toml: "[profiles.p]\nengine = \"postgres\"\nhost = \"db.example.com\"\n", key: "vault.address in lockfamily.yaml (vault): 192.0.2.9"},
		"one of every profile": {typ: "locksql",
			toml: "[profiles.a]\nengine = \"postgres\"\nhost = \"a.example.com\"\n[profiles.b]\nengine = \"postgres\"\nhost = \"10.9.9.9\"\n", key: "profiles.b.host in config.toml (database): 10.9.9.9"},
	} {
		t.Run(name, func(t *testing.T) {
			c := lockConf(t, tc.typ, tc.vault, tc.lock)
			es, err := Egresses(c, map[string]*Profile{tc.typ: profileOf(t, tc.toml)})
			if err == nil {
				t.Fatalf("no refusal: %+v", es)
			}
			for _, w := range []string{"egress of lock x: ", tc.key + " is an IP address", "name the host instead", "host.docker.internal"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err lacks %q: %v", w, err)
				}
			}
		})
	}
	// A named profile that is not the IP's: only what the lock serves.
	c := lockConf(t, "locksql", "", "    profile: a\n")
	if _, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, "[profiles.a]\nengine = \"postgres\"\nhost = \"a.example.com\"\n[profiles.b]\nengine = \"postgres\"\nhost = \"10.9.9.9\"\n")}); err != nil {
		t.Errorf("profile a refused for b's IP: %v", err)
	}
}

// A proxy_command is refused before anything starts (lockhub#193): the
// gateway cannot follow the program it runs. The refusal names the
// profile and the built-in ssh bastion; a profile without one is served.
func TestEgressRefusesProxyCommand(t *testing.T) {
	const want = "egress of lock x: profile shop-prod: proxy_command is not supported under lox run; reach the database through the built-in ssh bastion ([profiles.shop-prod.ssh]) or publish its port (see docs/lox-run.md)"
	for name, tc := range map[string]struct{ lock, toml string }{
		"named profile": {lock: "    profile: shop-prod\n",
			toml: "[profiles.shop-prod]\nengine = \"postgres\"\nhost = \"db\"\nproxy_command = [\"ssh\", \"bastion\", \"socat\", \"-\", \"TCP:db:5432\"]\n"},
		"one of every profile": {
			toml: "[profiles.a]\nengine = \"postgres\"\nhost = \"a.example.com\"\n[profiles.shop-prod]\nengine = \"postgres\"\nhost = \"db\"\nproxy_command = [\"docker\", \"exec\", \"-i\", \"db\", \"socat\", \"-\", \"TCP:localhost:5432\"]\n"},
		"with an ssh bastion too": {
			toml: "[profiles.shop-prod]\nengine = \"postgres\"\nhost = \"db\"\nproxy_command = [\"nc\", \"db\", \"5432\"]\n[profiles.shop-prod.ssh]\nhost = \"bastion.example.com\"\nuser = \"u\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			c := lockConf(t, "locksql", "", tc.lock)
			es, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, tc.toml)})
			if err == nil || err.Error() != want {
				t.Fatalf("err %v, want %q (%+v)", err, want, es)
			}
		})
	}
	// A named profile without one: served as before, b's proxy_command
	// aside.
	c := lockConf(t, "locksql", "", "    profile: a\n")
	es, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, "[profiles.a]\nengine = \"postgres\"\nhost = \"a.example.com\"\n[profiles.b]\nengine = \"postgres\"\nhost = \"db\"\nproxy_command = [\"nc\", \"db\", \"5432\"]\n")})
	if err != nil {
		t.Fatalf("profile a refused for b's proxy_command: %v", err)
	}
	if got := addrs(es["x"]); !slices.Equal(got, []string{"a.example.com:5432"}) {
		t.Errorf("endpoints %v", got)
	}
}

func TestIPHost(t *testing.T) {
	for h, refused := range map[string]bool{"203.0.113.10": true, "[2001:db8::1]": true, "2001:db8::1": true, "127.0.0.1": false, "::1": false, "db.example.com": false, "host.docker.internal": false, "": false} {
		if got := IPHost(h) != ""; got != refused {
			t.Errorf("IPHost(%q) refused %v, want %v", h, got, refused)
		}
	}
}

func TestEgressRefusesReservedNames(t *testing.T) {
	c := lockConf(t, "locksql", "", "")
	_, err := Egresses(c, map[string]*Profile{"locksql": profileOf(t, "[profiles.p]\nengine = \"postgres\"\nhost = \"lockhub\"\nport = 8443\n")})
	if err == nil || !strings.Contains(err.Error(), "a name of lox run's own services") {
		t.Fatalf("err %v", err)
	}
}

// The golden compose of a workspace with a database lock (its DB and its
// Vault on this machine), a broker lock sharing port 443 by TLS name, a
// lockfile lock with no egress and a lockhttp lock (its own policy).
func TestEgressComposeGolden(t *testing.T) {
	y := `version: 1
hub:
  image: ` + hubImg + `
vault:
  address: http://host.docker.internal:8200
locks:
  db:
    type: locksql
    image: ` + sqlImg + `
    vault: true
  mq:
    type: lockmq
    image: ` + mqImg + `
  docs:
    type: lockfile
    image: ` + fileImg + `
  web:
    type: lockhttp
    image: ` + httpImg + `
`
	c := confOf(t, y)
	es, err := Egresses(c, map[string]*Profile{
		"locksql":  profileOf(t, "[profiles.p]\nengine = \"postgres\"\nhost = \"host.docker.internal\"\ncredentials = \"vault\"\nvault_path = \"db/creds/ro\"\n"),
		"lockmq":   profileOf(t, "[profiles.e]\nurl = \"https://mgmt.example.com\"\namqp_url = \"amqps://amqp.example.com:443\"\n"),
		"lockfile": profileOf(t, "[profiles.default]\nsource = \"local\"\npath = \"/data\"\n"),
		"lockhttp": profileOf(t, "[profiles.default]\nmode = \"enforce\"\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0", Egress: es})
	golden := filepath.Join("testdata", "egress-compose.golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (go test -run TestEgressComposeGolden -update)", err)
	}
	if out != string(want) {
		t.Errorf("compose differs from %s (go test -run TestEgressComposeGolden -update, then review the diff)", golden)
	}
	// What the golden file must say, whatever it is rewritten to.
	for _, s := range []string{
		"  \"locknet-db\":\n    internal: true\n",
		"  \"gwlink-db\":\n    internal: true\n",
		"  \"out-db\": {}\n",
		"  \"locknet-docs\":\n    internal: true\n",
		"  \"egress-web\": {}\n",
		`command: ["egress-gateway", "--forward", "5432=gwout-db:20000", "--forward", "8200=gwout-db:20001"]`,
		`command: ["egress-gateway", "--forward", "20000=host.docker.internal:5432", "--forward", "20001=host.docker.internal:8200"]`,
		`aliases: ["host.docker.internal"]`,
		`command: ["egress-gateway", "--forward", "443=gwout-mq:20000,sni=amqp.example.com", "--forward", "443=gwout-mq:20001,sni=mgmt.example.com"]`,
		`depends_on: [lockhub, "gw-db"]`,
	} {
		if !strings.Contains(out, s) {
			t.Errorf("compose lacks %q", s)
		}
	}
	for _, s := range []string{"gw-docs", "gw-web", "gwout-docs"} {
		if strings.Contains(out, s) {
			t.Errorf("compose has %q", s)
		}
	}
	// Only the back gateway of db resolves this machine; no lock does.
	if n := strings.Count(out, "host.docker.internal:host-gateway"); n != 1 {
		t.Errorf("%d host-gateway entries, want 1 (gwout-db's)", n)
	}
	if i := strings.Index(out, "  \"gwout-db\":"); i < 0 || !strings.Contains(out[i:i+800], "host.docker.internal:host-gateway") {
		t.Error("gwout-db does not resolve host.docker.internal")
	}
	if i := strings.Index(out, "  \"gwout-db\":"); !strings.Contains(out[i:i+900], `networks: ["gwlink-db", "out-db"]`) {
		t.Error("gwout-db is not on its link and out networks")
	}
}

// The allowlist is reviewed (short review row and summary lines), comes
// from the copy reviewed, and a workspace edit without a yes changes
// nothing applied.
func TestEgressReviewedAndAppliedFromCopy(t *testing.T) {
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"host.docker.internal\"\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".lockmq", "config.toml"), []byte("[profiles.e]\nurl = \"http://host.docker.internal:15672\"\n"), 0o644)
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, s := range []string{"  egress       only host.docker.internal:5432\n", "  egress       only host.docker.internal:15672\n"} {
		if !strings.Contains(out, s) {
			t.Errorf("review lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "lock crm-prod egress ") {
		t.Errorf("the egress lines are listed besides the row:\n%s", out)
	}
	if !strings.Contains(f.upCompose, `"--forward", "20000=host.docker.internal:5432"`) || !strings.Contains(f.upCompose, `"--forward", "20000=host.docker.internal:15672"`) {
		t.Fatalf("applied compose lacks the gateways:\n%s", f.upCompose)
	}
	state := filepath.Join(w.dir, "state")
	b, _ := os.ReadFile(filepath.Join(state, "applied.json"))
	if !strings.Contains(string(b), "lock crm-prod egress host.docker.internal:5432 (database)") {
		t.Errorf("applied.json lacks the allowlist:\n%s", b)
	}
	applied, _ := os.ReadFile(filepath.Join(state, "compose.yaml"))

	// An agent edits the workspace's profile: nothing applied changes, and
	// lox run shows the new allowlist, applied only on yes.
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"exfil.example.net\"\nport = 443\n"), 0o644)
	if now, _ := os.ReadFile(filepath.Join(state, "compose.yaml")); string(now) != string(applied) {
		t.Fatal("the applied compose changed without lox run")
	}
	f2 := newFake()
	f2.keys = f.keys
	out, err = w.up("n\n", f2)
	if err != ErrNotConfirmed {
		t.Fatalf("err %v\n%s", err, out)
	}
	if !strings.Contains(out, "  egress       only exfil.example.net:443\n") || !strings.Contains(out, "changed since the last lox run") {
		t.Errorf("the new allowlist is not reviewed:\n%s", out)
	}
	if f2.upCompose != "" {
		t.Error("compose up ran without a yes")
	}
	if now, _ := os.ReadFile(filepath.Join(state, "compose.yaml")); string(now) != string(applied) {
		t.Error("the applied compose changed without a yes")
	}
	// --review lists the allowlist lines themselves.
	f3 := newFake()
	f3.keys = f.keys
	var o strings.Builder
	u := &Up{File: w.file, State: state, Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: f3, In: nil, Out: &o, Review: true, DryRun: true}
	if err := u.Do(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.String(), "+ lock crm-prod egress exfil.example.net:443 (database)") || !strings.Contains(o.String(), "- lock crm-prod egress host.docker.internal:5432 (database)") {
		t.Errorf("--review does not diff the allowlist:\n%s", o.String())
	}
}

// A collision stops lox run before anything is reviewed or applied.
func TestEgressCollisionStopsUp(t *testing.T) {
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".lockmq", "config.toml"), []byte("[profiles.e]\nurl = \"http://a.example.com:5672\"\namqp_url = \"amqp://b.example.com\"\n"), 0o644)
	f := newFake()
	out, err := w.up("y\n", f)
	if err == nil || !strings.Contains(err.Error(), "egress of lock events: a.example.com:5672 (broker management API) and b.example.com:5672 (broker AMQP) share port 5672") {
		t.Fatalf("err %v\n%s", err, out)
	}
	if f.upCompose != "" {
		t.Error("applied despite the collision")
	}
}

// An SSH bastion named by its IP stops lox run before the review and
// before anything starts, naming the key and the fix (lockhub#145).
func TestEgressIPBastionStopsUp(t *testing.T) {
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db.internal\"\n[profiles.p.ssh]\nhost = \"203.0.113.10\"\nuser = \"u\"\n"), 0o644)
	f := newFake()
	out, err := w.up("y\n", f)
	if err == nil || !strings.Contains(err.Error(), "profiles.p.ssh.host in config.toml (ssh): 203.0.113.10 is an IP address") || !strings.Contains(err.Error(), "name the host instead") {
		t.Fatalf("err %v\n%s", err, out)
	}
	if strings.Contains(out, "Apply? [y/N]") || f.upCompose != "" {
		t.Errorf("asked or applied despite the IP:\n%s", out)
	}
}

// A proxy_command stops lox run before the review and before anything
// starts, naming the profile and the ssh bastion (lockhub#193).
func TestEgressProxyCommandStopsUp(t *testing.T) {
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db\"\nproxy_command = [\"nc\", \"db\", \"5432\"]\n"), 0o644)
	f := newFake()
	out, err := w.up("y\n", f)
	if err == nil || !strings.Contains(err.Error(), "profile p: proxy_command is not supported under lox run; reach the database through the built-in ssh bastion ([profiles.p.ssh])") {
		t.Fatalf("err %v\n%s", err, out)
	}
	if strings.Contains(out, "Apply? [y/N]") || f.upCompose != "" {
		t.Errorf("asked or applied despite the proxy_command:\n%s", out)
	}
}

func TestDoctorEgress(t *testing.T) {
	setup := func(t *testing.T) (*Doctor, *answers) {
		d, a := healthy(t)
		ws := filepath.Dir(filepath.Dir(d.File))
		os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db.example.com\"\n"), 0o644)
		f := newFake()
		u := &Up{File: d.File, State: d.State, Runtime: d.Runtime, User: "1000:1000", Run: f, In: bufio.NewReader(strings.NewReader("y\n")), Out: &strings.Builder{}}
		if err := u.Do(t.Context()); err != nil {
			t.Fatal(err)
		}
		a.out["ps --all --format json"] = `{"Service":"lockhub","State":"running"}
{"Service":"lock-crm-prod","State":"running"}
{"Service":"lock-events","State":"running"}
{"Service":"gw-crm-prod","State":"running"}
{"Service":"gwout-crm-prod","State":"running"}
`
		a.out["{{json .Config.Cmd}}"] = `["egress-gateway","--forward","20000=db.example.com:5432"]`
		return d, a
	}
	t.Run("healthy", func(t *testing.T) {
		d, _ := setup(t)
		out, n := doc(t, d)
		if n != 0 || !strings.Contains(out, "ok   lock crm-prod egress: only db.example.com:5432 (internal networks, gateway running)") ||
			!strings.Contains(out, "ok   lock events egress: none (internal networks, no gateway)") {
			t.Fatalf("%d:\n%s", n, out)
		}
	})
	for name, tc := range map[string]struct {
		break_ func(a *answers)
		want   string
	}{
		"gateway stopped": {func(a *answers) {
			a.out["ps --all --format json"] = strings.Replace(a.out["ps --all --format json"], `"gwout-crm-prod","State":"running"`, `"gwout-crm-prod","State":"restarting"`, 1)
		}, "FAIL lock crm-prod egress: its gateway gwout-crm-prod is restarting"},
		"gateway forwards elsewhere": {func(a *answers) {
			a.out["{{json .Config.Cmd}}"] = `["egress-gateway","--forward","20000=exfil.example.net:443"]`
		}, "FAIL lock crm-prod egress: the gateway forwards to exfil.example.net:443, the last lox run reviewed db.example.com:5432"},
		"lock network open": {func(a *answers) { a.out["network inspect"] = "false\n" }, "is not internal, it has a route out"},
	} {
		t.Run(name, func(t *testing.T) {
			d, a := setup(t)
			tc.break_(a)
			out, n := doc(t, d)
			if n == 0 || !strings.Contains(out, tc.want) {
				t.Errorf("want %q (%d):\n%s", tc.want, n, out)
			}
		})
	}
}

// The bridges the locks had before (egress-<n>, a route out) are removed
// once the locks run on their internal networks; lockhttp's stays.
func TestEgressRemovesFormerNetworks(t *testing.T) {
	w := newWS(t, yamlConf("")+"  web:\n    type: lockhttp\n    image: "+httpImg+"\n")
	f := newFake()
	f.keys["web"] = pubKey()
	f.keys["networks"] = "p_lockhub lockhub\np_egress-crm-prod egress-crm-prod\np_egress-web egress-web\np_locknet-events locknet-events\n"
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !f.ran("docker network rm p_egress-crm-prod") {
		t.Errorf("the former network of crm-prod was not removed: %q", f.calls)
	}
	for _, n := range []string{"p_egress-web", "p_lockhub", "p_locknet-events"} {
		if f.ran("docker network rm " + n) {
			t.Errorf("%s removed", n)
		}
	}
}
