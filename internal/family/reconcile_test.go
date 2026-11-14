package family

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// engineNet is a network of project as docker network inspect prints it.
func engineNet(project, key string, internal bool, subnet string) EngineNet {
	n := EngineNet{Name: project + "_" + key, Internal: internal, Labels: map[string]string{
		"com.docker.compose.project": project, "com.docker.compose.network": key,
	}}
	if subnet != "" {
		n.IPAM.Config = append(n.IPAM.Config, struct {
			Subnet string `json:"Subnet"`
		}{subnet})
	}
	return n
}

// The reconcile decision: a network in place that the file declares
// otherwise is stale; one declared the same, one of another project, or
// none in place at all is not.
func TestStaleNets(t *testing.T) {
	const p = "lockfamily-0a0b0c0d"
	want := map[string]netSpec{
		"lockhub":        {internal: true, subnets: []string{"10.123.0.0/24"}},
		"locknet-db":     {internal: true, subnets: []string{"10.123.1.0/28"}},
		"egress-hub":     {},
		"out-db":         {subnets: []string{"10.123.1.16/28"}},
		"gwlink-db":      {internal: true, subnets: []string{"10.123.1.32/28"}},
		"mobile-hub":     {subnets: []string{"10.123.1.48/28"}},
		"egress-gateway": {subnets: []string{"10.123.1.64/28"}},
	}
	identical := []EngineNet{
		engineNet(p, "lockhub", true, "10.123.0.0/24"),
		engineNet(p, "locknet-db", true, "10.123.1.0/28"),
		engineNet(p, "egress-hub", false, "172.20.0.0/16"), // no subnet declared: the engine's
		engineNet(p, "out-db", false, "10.123.1.16/28"),
	}
	for name, tc := range map[string]struct {
		nets []EngineNet
		want []string
	}{
		"no previous stack": {nil, nil},
		"identical":         {identical, nil},
		// lox 0.10: the engine's subnets, none declared.
		"diverging subnets": {[]EngineNet{
			engineNet(p, "lockhub", true, "172.18.0.0/16"),
			engineNet(p, "locknet-db", true, "172.19.0.0/16"),
			engineNet(p, "egress-hub", false, "172.20.0.0/16"),
		}, []string{"lockhub", "locknet-db"}},
		"diverging internal": {[]EngineNet{engineNet(p, "out-db", true, "10.123.1.16/28")}, []string{"out-db"}},
		"another project":    {[]EngineNet{engineNet("lockfamily-ffffffff", "lockhub", true, "172.18.0.0/16")}, nil},
		"not declared":       {[]EngineNet{engineNet(p, "locknet-gone", true, "172.18.0.0/16")}, nil},
		"not compose's name": {[]EngineNet{func() EngineNet {
			n := engineNet(p, "lockhub", true, "172.18.0.0/16")
			n.Name = "lockhub"
			return n
		}()}, nil},
	} {
		if got := staleNets(p, want, tc.nets); !slices.Equal(got, tc.want) {
			t.Errorf("%s: stale %v, want %v", name, got, tc.want)
		}
	}
}

func TestDeclaredNets(t *testing.T) {
	c, err := Load(writeConf(t, yamlConf("")))
	if err != nil {
		t.Fatal(err)
	}
	paths := Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "1000:1000", Subnets: map[string]string{"lockhub": "10.123.0.0/24", "locknet-crm-prod": "10.123.1.0/28"}}
	got, err := declaredNets([]byte(Compose(c, paths)))
	if err != nil {
		t.Fatal(err)
	}
	if s := got["lockhub"]; !s.internal || !slices.Equal(s.subnets, []string{"10.123.0.0/24"}) {
		t.Errorf("lockhub: %+v", s)
	}
	if s := got["locknet-crm-prod"]; !s.internal || !slices.Equal(s.subnets, []string{"10.123.1.0/28"}) {
		t.Errorf("locknet-crm-prod: %+v (%v)", s, got)
	}
}

func writeConf(t *testing.T, conf string) string {
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	if err := os.WriteFile(p, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A stack an earlier lox made (its networks without the subnets this
// file declares) still up: lox run takes it down before reading any key,
// says so in one line, asks nothing more and keeps the volumes and the
// state; then applies.
func TestUpgradeOverRunningStack(t *testing.T) {
	for _, hubExited := range []bool{false, true} {
		w := newWS(t, yamlConf(""))
		f := newFake()
		if _, err := w.up("y\n", f); err != nil {
			t.Fatal(err)
		}
		project := Project(filepath.Join(w.dir, "projects"))
		state := filepath.Join(w.dir, "state")
		before := stateFiles(t, state)

		// The networks as lox 0.10 made them: the engine's subnets. The
		// locks run; the hub too, or not (the state after a reboot): the
		// containers are there either way.
		f2 := &fake{keys: f.keys}
		var old []EngineNet
		for _, k := range []string{"lockhub", "locknet-crm-prod", "locknet-events"} {
			old = append(old, engineNet(project, k, true, "172.18.0.0/16"))
		}
		b, _ := json.Marshal(old)
		ctrs := "c-lock-crm-prod\nc-lock-events\n"
		if !hubExited {
			ctrs += "c-lockhub\n"
		}
		setNets(f2, project, b, ctrs)
		out, err := w.up("", f2)
		if err != nil {
			t.Fatalf("hub exited %v: %v\n%s", hubExited, err, out)
		}
		if !strings.Contains(out, "previous stack stopped (its networks changed)\n") || strings.Contains(out, "Apply?") {
			t.Errorf("hub exited %v: output:\n%s", hubExited, out)
		}
		stop, key := index(f2.calls, "docker stop c-lock-crm-prod c-lock-events"), index(f2.calls, "hub-key --instance")
		if stop < 0 || key < 0 || stop > key || index(f2.calls, "docker rm c-lock-crm-prod") < 0 {
			t.Errorf("hub exited %v: not taken down before the keys: %q", hubExited, f2.calls)
		}
		if !f2.ran("up -d --remove-orphans") {
			t.Errorf("hub exited %v: not applied: %q", hubExited, f2.calls)
		}
		for _, c := range f2.calls {
			if strings.Contains(c, "volume rm") || strings.Contains(c, " down ") || strings.Contains(c, " -v") {
				t.Errorf("hub exited %v: volumes not kept: %s", hubExited, c)
			}
		}
		if f2.ran("keygen") {
			t.Errorf("hub exited %v: hub key made again", hubExited)
		}
		after := stateFiles(t, state)
		for _, p := range []string{"hub.pub", "hub/locks.json", "hub/routing.json"} {
			if before[p] == "" || before[p] != after[p] {
				t.Errorf("hub exited %v: %s changed: %q → %q", hubExited, p, before[p], after[p])
			}
		}

		// The same networks as the file: nothing taken down.
		f3 := &fake{keys: f.keys}
		var same []EngineNet
		for k, s := range mustDeclared(t, f2.upCompose) {
			n := engineNet(project, k, s.internal, "")
			if len(s.subnets) > 0 {
				n = engineNet(project, k, s.internal, s.subnets[0])
			}
			same = append(same, n)
		}
		b, _ = json.Marshal(same)
		setNets(f3, project, b, ctrs)
		if out, err := w.up("", f3); err != nil || strings.Contains(out, "previous stack stopped") || f3.ran("docker stop") {
			t.Errorf("hub exited %v: identical networks: %v %q\n%s", hubExited, err, f3.calls, out)
		}
	}
}

// A dry run never takes the stack down: it says why it cannot go on.
func TestUpgradeOverRunningStackDryRun(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	project := Project(filepath.Join(w.dir, "projects"))
	f2 := &fake{keys: f.keys}
	b, _ := json.Marshal([]EngineNet{engineNet(project, "lockhub", true, "172.18.0.0/16")})
	setNets(f2, project, b, "c-lockhub\n")
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: f2, In: nil, Out: &out, DryRun: true}
	err := u.Do(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dry run: the stack in place") || f2.ran("docker stop") || f2.ran("docker rm") {
		t.Errorf("dry run: %v %q\n%s", err, f2.calls, out.String())
	}
}

// A compose call refused on a network still in use takes the stack down
// and runs once more; refused again, it says what is in the way.
func TestActiveEndpointsRetry(t *testing.T) {
	const p = "lockfamily-0a0b0c0d"
	refusal := &RunError{Cmd: "docker compose", Err: errors.New("exit status 1"),
		Stderr: []byte(` network:lockhub Error response from daemon: error while removing network: network ` + p + `_lockhub has active endpoints (name:"lea-agent-1" id:"0123")` + "\n")}
	for name, tc := range map[string]struct {
		fails   int
		apply   bool
		wantErr string
		stopped bool
	}{
		"retried":         {fails: 1, apply: true, stopped: true},
		"refused twice":   {fails: 2, apply: true, stopped: true, wantErr: "still used by the container lea-agent-1, which lox down did not stop: stop it (docker stop lea-agent-1) or disconnect it (docker network disconnect " + p + "_lockhub lea-agent-1)"},
		"probe: no retry": {fails: 1, apply: false, wantErr: "still used by the container lea-agent-1"},
	} {
		r := &scripted{fails: tc.fails, err: refusal, out: map[string]string{
			"docker ps -a -q --no-trunc --filter label=com.docker.compose.project=" + p: "c1\n",
			"docker network ls -q --filter label=com.docker.compose.project=" + p:       "n1\n",
		}}
		var out strings.Builder
		e := endpointRetry{Runner: r, project: p, out: &out, apply: tc.apply}
		_, err := e.Run(context.Background(), []byte("services: {}\n"), "docker", "compose", "-p", p, "run", "--rm", "lock-db", "hub-key")
		if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: %v", name, err)
		}
		if got := slices.Contains(r.calls, "docker stop c1") && slices.Contains(r.calls, "docker rm c1") && slices.Contains(r.calls, "docker network rm n1"); got != tc.stopped {
			t.Errorf("%s: stack stopped %v: %q", name, got, r.calls)
		}
		if tc.stopped != strings.Contains(out.String(), "previous stack stopped (volumes kept), trying again") {
			t.Errorf("%s: output %q", name, out.String())
		}
	}
	// Any other error, or not a compose call: as it is.
	r := &scripted{fails: 1, err: errors.New("refused")}
	if _, err := (endpointRetry{Runner: r, project: p, out: &strings.Builder{}, apply: true}).Run(context.Background(), nil, "docker", "compose", "up"); err == nil || err.Error() != "refused" || len(r.calls) != 1 {
		t.Errorf("other error: %v %q", err, r.calls)
	}
}

// StopStack removes containers and networks, never a volume; with
// nothing there it does nothing and is no error.
func TestStopStack(t *testing.T) {
	const p = "lockfamily-0a0b0c0d"
	r := &scripted{out: map[string]string{
		"docker ps -a -q --no-trunc --filter label=com.docker.compose.project=" + p: "c1\nc2\n",
		"docker network ls -q --filter label=com.docker.compose.project=" + p:       "n1\nn2\n",
	}}
	n, nn, err := StopStack(context.Background(), r, p)
	if err != nil || n != 2 || nn != 2 {
		t.Fatalf("%d %d %v", n, nn, err)
	}
	for _, want := range []string{"docker stop c1 c2", "docker rm c1 c2", "docker network rm n1 n2"} {
		if !slices.Contains(r.calls, want) {
			t.Errorf("no %q: %q", want, r.calls)
		}
	}
	for _, c := range r.calls {
		if strings.Contains(c, "volume") || strings.Contains(c, " -v") {
			t.Errorf("a volume touched: %s", c)
		}
	}
	empty := &scripted{}
	if n, nn, err := StopStack(context.Background(), empty, p); err != nil || n != 0 || nn != 0 || len(empty.calls) != 2 {
		t.Errorf("nothing to stop: %d %v %q", n, err, empty.calls)
	}
	// A network some other container still uses: said, with the way out.
	busy := &scripted{out: map[string]string{"docker network ls -q --filter label=com.docker.compose.project=" + p: "n1\n"},
		failOn: "docker network rm", err: &RunError{Err: errors.New("exit status 1"), Stderr: []byte(`Error response from daemon: error while removing network: network ` + p + `_lockhub has active endpoints (name:"other" id:"1")`)}}
	if _, _, err := StopStack(context.Background(), busy, p); err == nil || !strings.Contains(err.Error(), "docker network disconnect "+p+"_lockhub other") {
		t.Errorf("busy network: %v", err)
	}
}

// scripted answers out[line], and fails its first fails compose calls
// (or every call containing failOn) with err.
type scripted struct {
	calls  []string
	out    map[string]string
	fails  int
	failOn string
	err    error
}

func (s *scripted) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, line)
	if s.failOn != "" && strings.Contains(line, s.failOn) {
		return nil, s.err
	}
	if s.failOn == "" && len(args) > 0 && args[0] == "compose" && s.fails > 0 {
		s.fails--
		return nil, s.err
	}
	return []byte(s.out[line]), nil
}

// setNets makes f's engine show nets (docker network inspect's JSON) and
// the containers ctrs for project.
func setNets(f *fake, project string, nets []byte, ctrs string) {
	f.keys["docker/docker network ls -q --no-trunc"] = "n1\n"
	f.keys["docker/docker network inspect n1"] = string(nets)
	f.keys["docker/docker ps -a -q --no-trunc --filter label=com.docker.compose.project="+project] = ctrs
}

func mustDeclared(t *testing.T, composeYAML string) map[string]netSpec {
	t.Helper()
	d, err := declaredNets([]byte(composeYAML))
	if err != nil || len(d) == 0 {
		t.Fatalf("%v %v", d, err)
	}
	return d
}

func index(calls []string, s string) int {
	return slices.IndexFunc(calls, func(c string) bool { return strings.Contains(c, s) })
}

// stateFiles are the files of the state directory, by relative path.
func stateFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			r, _ := filepath.Rel(dir, p)
			out[r] = string(b)
		}
		return nil
	})
	return out
}
