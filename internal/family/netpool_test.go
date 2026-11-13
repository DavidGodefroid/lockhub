package family

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// tenLocks is a workspace of 10 locks of every kind with a network: three
// database locks and two broker locks with an allowlist, three lockfile
// locks with none and two lockhttp locks (their own policy).
func tenLocks(t *testing.T) (*Config, map[string]Egress) {
	t.Helper()
	y := "version: 1\nhub:\n  image: " + hubImg + "\nlocks:\n"
	for _, l := range []struct{ name, typ, img string }{
		{"db-a", "locksql", sqlImg}, {"db-b", "locksql", sqlImg}, {"db-c", "locksql", sqlImg},
		{"mq-a", "lockmq", mqImg}, {"mq-b", "lockmq", mqImg},
		{"files-a", "lockfile", fileImg}, {"files-b", "lockfile", fileImg}, {"files-c", "lockfile", fileImg},
		{"web-a", "lockhttp", httpImg}, {"web-b", "lockhttp", httpImg},
	} {
		y += "  " + l.name + ":\n    type: " + l.typ + "\n    image: " + l.img + "\n"
	}
	c := confOf(t, y)
	es, err := Egresses(c, map[string]*Profile{
		"locksql":  profileOf(t, "[profiles.p]\nengine = \"postgres\"\nhost = \"db.example.com\"\n"),
		"lockmq":   profileOf(t, "[profiles.e]\nurl = \"https://mgmt.example.com\"\n"),
		"lockfile": profileOf(t, "[profiles.default]\nsource = \"local\"\npath = \"/data\"\n"),
		"lockhttp": profileOf(t, "[profiles.default]\nmode = \"enforce\"\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, es
}

// composeNets are the networks of a compose file, with their subnets.
func composeNets(t *testing.T, out string) map[string][]string {
	t.Helper()
	var f struct {
		Networks map[string]struct {
			IPAM struct {
				Config []struct {
					Subnet string `yaml:"subnet"`
				} `yaml:"config"`
			} `yaml:"ipam"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal([]byte(out), &f); err != nil {
		t.Fatal(err)
	}
	nets := map[string][]string{}
	for k, n := range f.Networks {
		nets[k] = nil
		for _, c := range n.IPAM.Config {
			nets[k] = append(nets[k], c.Subnet)
		}
	}
	return nets
}

// engineNets are the networks compose makes from a compose file, as the
// engine lists them.
func engineNets(t *testing.T, project, out string) []EngineNet {
	var nets []EngineNet
	for k, subs := range composeNets(t, out) {
		n := EngineNet{Name: project + "_" + k, Labels: map[string]string{"com.docker.compose.project": project, "com.docker.compose.network": k}}
		for _, s := range subs {
			n.IPAM.Config = append(n.IPAM.Config, struct {
				Subnet string `json:"Subnet"`
			}{s})
		}
		nets = append(nets, n)
	}
	return nets
}

func subnets(m map[string]netip.Prefix) map[string]string {
	out := map[string]string{}
	for k, p := range m {
		out[k] = p.String()
	}
	return out
}

// lockhub#175: 10 locks in a workspace, a second workspace beside it and
// another compose project on the engine: every network has its own small
// subnet, set in the file, and none overlaps another.
func TestNetworkSubnetsGolden(t *testing.T) {
	c, es := tenLocks(t)
	// Another project took the pool's first /24 already.
	other := EngineNet{Name: "shop_default", Labels: map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.network": "default"}, Subnets: []struct {
		Subnet string `json:"subnet"`
	}{{"10.123.0.0/24"}}}
	engine := []EngineNet{other}
	var files []string
	for _, ws := range []string{"/w/one", "/w/two"} {
		project := Project(ws)
		subs, err := AllocSubnets(c.Pool(), project, NetKeys(c), engine)
		if err != nil {
			t.Fatal(err)
		}
		out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: ws, User: "0:0", Egress: es, Project: project, Subnets: subnets(subs)})
		files = append(files, out)
		engine = append(engine, engineNets(t, project, out)...)
	}
	golden := filepath.Join("testdata", "netpool-compose.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(files[0]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (go test -run TestNetworkSubnetsGolden -update)", err)
	}
	if files[0] != string(want) {
		t.Errorf("compose differs from %s (go test -run TestNetworkSubnetsGolden -update, then review the diff)", golden)
	}
	var all []netip.Prefix
	count := 0
	for i, out := range files {
		for k, subs := range composeNets(t, out) {
			count++
			if len(subs) != 1 {
				t.Fatalf("workspace %d: network %s has subnets %v, want one set in the file", i, k, subs)
			}
			p := netip.MustParsePrefix(subs[0])
			if want := netBits(k); p.Bits() != want {
				t.Errorf("workspace %d: network %s is a /%d, want /%d", i, k, p.Bits(), want)
			}
			if !c.Pool().Contains(p.Addr()) {
				t.Errorf("workspace %d: network %s %s outside the pool", i, k, p)
			}
			for _, q := range append(all, netip.MustParsePrefix("10.123.0.0/24")) {
				if p.Overlaps(q) {
					t.Errorf("workspace %d: network %s %s overlaps %s", i, k, p, q)
				}
			}
			all = append(all, p)
		}
	}
	// 1 hub network, 3 for each of the 5 locks with an allowlist, 1 for
	// each lockfile and lockhttp lock: 21 per workspace.
	if count != 42 {
		t.Errorf("%d networks in the two workspaces, want 42", count)
	}
	for _, s := range []string{
		"  lockhub:\n    internal: true\n    labels:\n",
		"  \"locknet-files-a\":\n    internal: true\n    ipam:\n      config:\n        - subnet: ",
		"  \"egress-web-a\":\n    ipam:\n",
		"  \"out-db-a\":\n    ipam:\n",
	} {
		if !strings.Contains(files[0], s) {
			t.Errorf("compose lacks %q", s)
		}
	}
}

func TestAllocSubnetsKeepsAndMoves(t *testing.T) {
	pool := netip.MustParsePrefix(DefaultNetworkPool)
	net := func(project, key string, subs ...string) EngineNet {
		n := EngineNet{Name: project + "_" + key, Labels: map[string]string{"com.docker.compose.project": project, "com.docker.compose.network": key}}
		for _, s := range subs {
			n.IPAM.Config = append(n.IPAM.Config, struct {
				Subnet string `json:"Subnet"`
			}{s})
		}
		return n
	}
	keys := []string{"lockhub", "locknet-a", "gwlink-a", "out-a"}
	got, err := AllocSubnets(pool, "p", keys, []EngineNet{
		// Kept: a free /28 of the pool, though an earlier one is free.
		net("p", "locknet-a", "10.123.9.32/28"),
		// Moved: made before lox set subnets, from the default pools.
		net("p", "lockhub", "172.18.0.0/16"),
		// Another workspace's network named like ours is not ours.
		net("q", "gwlink-a", "10.123.1.0/28"),
		// The bridge network, no labels.
		{Name: "bridge", IPAM: net("", "", "10.123.1.16/28").IPAM},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"lockhub": "10.123.0.0/24", "locknet-a": "10.123.9.32/28", "gwlink-a": "10.123.1.32/28", "out-a": "10.123.1.48/28"}
	for k, w := range want {
		if got[k].String() != w {
			t.Errorf("%s: %s, want %s", k, got[k], w)
		}
	}
	// A kept subnet another network overlaps now moves too.
	got, err = AllocSubnets(pool, "p", keys, []EngineNet{net("p", "locknet-a", "10.123.9.32/28"), net("x", "default", "10.123.9.0/24")})
	if err != nil || got["locknet-a"].String() == "10.123.9.32/28" {
		t.Errorf("overlapped subnet kept: %v %v", got, err)
	}
	// A full pool: say so, and how to fix it.
	_, err = AllocSubnets(netip.MustParsePrefix("10.9.0.0/24"), "p", keys, []EngineNet{net("x", "default", "10.9.0.0/25")})
	if !errors.Is(err, ErrPoolFull) || !strings.Contains(err.Error(), "network.pool") {
		t.Errorf("full pool: %v", err)
	}
}

func TestReadEngineNetsDockerAndPodman(t *testing.T) {
	a := &answers{out: map[string]string{
		"network ls -q": "aaa\nbbb\n",
		"network inspect aaa bbb": `[{"Name":"p_lockhub","Labels":{"com.docker.compose.project":"p","com.docker.compose.network":"lockhub"},"IPAM":{"Config":[{"Subnet":"10.123.0.0/24","Gateway":"10.123.0.1"},{"Subnet":"fd00::/64"}]}},` +
			`{"name":"lea-egress","labels":{},"subnets":[{"subnet":"10.89.0.0/24","gateway":"10.89.0.1"}]}]`,
	}}
	nets, err := ReadEngineNets(context.Background(), a)
	if err != nil || len(nets) != 2 {
		t.Fatalf("%v %v", nets, err)
	}
	if p := nets[0].Prefixes(); len(p) != 1 || p[0].String() != "10.123.0.0/24" || nets[0].Labels["com.docker.compose.network"] != "lockhub" {
		t.Errorf("docker's form: %v %v", p, nets[0].Labels)
	}
	if p := nets[1].Prefixes(); len(p) != 1 || p[0].String() != "10.89.0.0/24" || nets[1].Name != "lea-egress" {
		t.Errorf("podman's form: %v %q", p, nets[1].Name)
	}
}

func TestNetworkPoolSetting(t *testing.T) {
	base := "version: 1\nhub:\n  image: " + hubImg + "\n"
	for pool, ok := range map[string]bool{
		"10.200.0.0/16": true, "172.16.0.0/12": true, "192.168.128.0/20": true, "10.0.0.0/8": true,
		"10.200.0.0/25": false, "10.200.0.1/16": false, "8.8.0.0/16": false, "fd00::/48": false, "10.200.0.0": false, "172.15.0.0/16": false,
	} {
		_, err := decode([]byte(base+"network:\n  pool: "+pool+"\n"), "lockfamily.yaml")
		if (err == nil) != ok {
			t.Errorf("pool %s: %v", pool, err)
		}
	}
	c := confOf(t, base+"network:\n  pool: 10.200.0.0/16\n")
	if c.Pool().String() != "10.200.0.0/16" || confOf(t, base).Pool().String() != DefaultNetworkPool {
		t.Errorf("pools %s %s", c.Pool(), confOf(t, base).Pool())
	}
	// A pool set is reviewed: it moves the networks.
	if !strings.Contains(strings.Join(Summary(c, "k", nil, nil), "\n"), "network pool 10.200.0.0/16") {
		t.Errorf("pool not in the review")
	}
}

func TestFreeInPools(t *testing.T) {
	if free, total := FreeInPools(DockerDefaultPools, nil); free != 31 || total != 31 {
		t.Errorf("stock Docker: %d of %d", free, total)
	}
	used := []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("192.168.0.0/18"), netip.MustParsePrefix("10.1.0.0/16")}
	if free, total := FreeInPools(DockerDefaultPools, used); free != 26 || total != 31 {
		t.Errorf("used: %d of %d", free, total)
	}
}

func TestIsPoolError(t *testing.T) {
	re := &RunError{Cmd: "docker compose up -d", Err: errors.New("exit status 1"), Stderr: []byte("network x: Error response from daemon: all predefined address pools have been fully subnetted\n")}
	if !IsPoolError(re) || !IsPoolError(errors.Join(errors.New("hub key"), re)) {
		t.Error("pool error not seen")
	}
	if IsPoolError(errors.New("all predefined address pools have been fully subnetted")) || IsPoolError(&RunError{Err: errors.New("x"), Stderr: []byte("no such image")}) {
		t.Error("other error taken for a pool error")
	}
	if re.Error() != "docker compose up -d: exit status 1" {
		t.Errorf("message %q", re.Error())
	}
}

func TestUpExplainsPoolRefusal(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	// The engine refuses the compose up for its addresses.
	f.failing = " up -d --remove-orphans"
	f.failErr = &RunError{Cmd: "docker compose up", Err: errors.New("exit status 1"), Stderr: []byte("Error response from daemon: Pool overlaps with other one on this address space\n")}
	_, err := w.up("y\n", f)
	if err == nil || !strings.Contains(err.Error(), "refused a network of this workspace for its addresses") || !strings.Contains(err.Error(), "docs/networks.md") {
		t.Fatalf("err %v", err)
	}
	if !f.ran("docker network prune -f --filter label=com.docker.compose.project=lockfamily-") {
		t.Errorf("networks made before the refusal left: %v", f.calls)
	}
	// Nothing applied: the next lox run reviews it again.
	if _, err := os.Stat(filepath.Join(w.dir, "state", "applied.json")); err == nil {
		t.Error("applied.json written")
	}
}

func TestUpSetsSubnets(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	nets := composeNets(t, f.upCompose)
	if len(nets) == 0 {
		t.Fatal("no network")
	}
	for k, s := range nets {
		if len(s) != 1 || !strings.HasPrefix(s[0], "10.123.") {
			t.Errorf("network %s: subnets %v", k, s)
		}
	}
}

func TestDoctorNetworks(t *testing.T) {
	c := confOf(t, "version: 1\nhub:\n  image: "+hubImg+"\n")
	full := `[`
	// 172.17-29 and 192.168 taken: 172.30 and 172.31 left.
	for i := 0; i < 13; i++ {
		full += `{"Name":"n` + string(rune('a'+i)) + `","IPAM":{"Config":[{"Subnet":"172.` + strconv.Itoa(17+i) + `.0.0/16"}]}},`
	}
	full += `{"Name":"big","IPAM":{"Config":[{"Subnet":"192.168.0.0/16"}]}}]`
	for _, tc := range []struct {
		name, nets, pools, want string
	}{
		{"stock and free", `[]`, "null", "ok   networks: the engine's default address pools have 31 of 31 subnets free"},
		{"stock and nearly full", full, "null", "warn networks: the engine's default address pools have 2 of 31 subnets free"},
		{"daemon.json pools", full, `[{"Base":"10.200.0.0/16","Size":24}]`, "ok   networks: the engine's default address pools have 256 of 256"},
	} {
		var out bytes.Buffer
		d := &Doctor{File: "/w/lockfamily.yaml", Out: &out, Run: &answers{out: map[string]string{"network ls -q": "x\n", "network inspect x": tc.nets, "DefaultAddressPools": tc.pools}}}
		ok := func(f string, a ...any) { out.WriteString("ok   " + fmt.Sprintf(f, a...) + "\n") }
		warn := func(f string, a ...any) { out.WriteString("warn " + fmt.Sprintf(f, a...) + "\n") }
		d.networks(context.Background(), c, ok, warn)
		if !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "ok   networks: pool 10.123.0.0/16 holds a subnet") {
			t.Errorf("%s:\n%s", tc.name, out.String())
		}
		if strings.HasPrefix(tc.want, "warn") && !strings.Contains(out.String(), "default-address-pools") {
			t.Errorf("%s: no fix given:\n%s", tc.name, out.String())
		}
	}
	// Podman: no default pools to count, nothing said of them.
	var out bytes.Buffer
	d := &Doctor{File: "/w/lockfamily.yaml", Out: &out, Run: &answers{out: map[string]string{}, fail: []string{"DefaultAddressPools"}}}
	d.networks(context.Background(), c, func(f string, a ...any) { out.WriteString(fmt.Sprintf(f, a...) + "\n") }, func(f string, a ...any) { out.WriteString(fmt.Sprintf(f, a...) + "\n") })
	if strings.Contains(out.String(), "default address pools") {
		t.Errorf("podman:\n%s", out.String())
	}
}
