package family

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The shared root check: lox add never declares a locklog lock that lox
// run refuses. A directory outside the default roots is refused unless
// LOCKLOG_EXTRA_ROOTS lets it in; then it becomes the lock's log_roots,
// and lox run's plan check takes it (lockhub#177).
func TestAddLogRootsMatchesLoxRun(t *testing.T) {
	h, _ := logHost(t)
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	d := filepath.Join(outside, "app")
	os.Mkdir(d, 0o755)
	plan := "profile app false\nfile " + d + " " + d + "/*.log\n"

	// Without an extra root: refused at add time, with lox run's message.
	_, addErr := AddLogRoots([]string{d}, nil)
	_, runErr := derive(t, &LogHost{Roots: DefaultLogRoots, Journals: h.Journals, GroupName: h.GroupName, GOOS: "linux"}, nil, plan)
	if addErr == nil || runErr == nil {
		t.Fatalf("outside the roots: add %v, run %v", addErr, runErr)
	}
	if want := d + " is not under an allowed log root (/var/log /run/log/journal)"; !strings.Contains(addErr.Error(), want) || !strings.Contains(runErr.Error(), want) {
		t.Errorf("not the same message:\nadd %v\nrun %v", addErr, runErr)
	}

	// With LOCKLOG_EXTRA_ROOTS covering it: the directory itself is the
	// lock's log_roots, and lox run takes the plan.
	roots, err := AddLogRoots([]string{d, "/var/log/nginx", d}, []string{outside})
	if err != nil || !slices.Equal(roots, []string{d}) {
		t.Fatalf("log_roots: %v %v", roots, err)
	}
	l := Lock{Type: "locklog", LogRoots: roots}
	if p, err := derive(t, (&LogHost{Roots: DefaultLogRoots, Journals: h.Journals, GroupName: h.GroupName, GOOS: "linux"}).forLock(l), nil, plan); err != nil || !slices.Equal(p.Binds, []string{d}) {
		t.Errorf("lox run refuses what lox add declared: %+v %v", p, err)
	}
	for _, r := range LockLogRoots(l) {
		if UnderLogRoot(r, DefaultLogRoots) != nil && r != d {
			t.Errorf("a root wider than the directory: %s", r)
		}
	}
	// Under the default roots: no log_roots.
	if roots, err := AddLogRoots([]string{"/var/log/app", "/run/log/journal"}, nil); err != nil || roots != nil {
		t.Errorf("default roots: %v %v", roots, err)
	}
	// A bad extra root or directory is refused, as the launcher does.
	for _, extra := range []string{"/", "rel", "/a b", "/a*", "/a/../b"} {
		if _, err := AddLogRoots([]string{"/var/log"}, []string{extra}); err == nil {
			t.Errorf("extra root %q accepted", extra)
		}
	}
}

// log_roots is a locklog lock's, valid roots only, and reviewed.
func TestLogRootsConfig(t *testing.T) {
	load := func(conf string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "lockfamily.yaml")
		os.WriteFile(p, []byte(conf), 0o644)
		return Load(p)
	}
	c, err := load(logConf("    log_roots: [/srv/app/logs]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Locks["logs"].LogRoots, []string{"/srv/app/logs"}) {
		t.Errorf("log_roots: %v", c.Locks["logs"].LogRoots)
	}
	if s := Summary(c, "", nil, nil); !slices.Contains(s, "lock logs log roots /srv/app/logs besides /var/log /run/log/journal (log_roots)") {
		t.Errorf("not reviewed: %v", s)
	}
	for name, conf := range map[string]string{
		"root":     logConf("    log_roots: [/]\n"),
		"relative": logConf("    log_roots: [srv]\n"),
		"twice":    logConf("    log_roots: [/srv, /srv]\n"),
		"glob":     logConf("    log_roots: [/srv/*]\n"),
		"locksql":  strings.Replace(yamlConf(""), "type: locksql\n", "type: locksql\n    log_roots: [/srv]\n", 1),
	} {
		if _, err := load(conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A lock whose mount plan lox run refuses is not started: the other
// locks are, its reason is said and kept for lox run's header and lox
// doctor; once fixed, it starts at the next lox run (lockhub#177).
func TestUpSkipsLockWithRefusedPlan(t *testing.T) {
	h, logs := logHost(t)
	w := newWS(t, logConf("    profile: app\n"))
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nfile /etc /etc/*.conf\n"
	out, err := upLog(w, h, "y\n", f)
	if err != nil {
		t.Fatalf("lox run stopped on one bad lock: %v\n%s", err, out)
	}
	why := "mount plan: /etc is not under an allowed log root (" + logs + ")"
	for _, want := range []string{"lock logs: not started: " + why, "lock crm-prod: started", "lock events: started", "lock logs not started: " + why} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "lock logs: started") {
		t.Errorf("logs said started:\n%s", out)
	}
	if block(f.upCompose, "lock-logs") != "" || block(f.upCompose, "lock-crm-prod") == "" || strings.Contains(f.upCompose, "/etc") {
		t.Errorf("compose:\n%s", f.upCompose)
	}
	state := filepath.Join(w.dir, "state")
	var lj struct {
		Locks map[string]any `json:"locks"`
	}
	b, _ := os.ReadFile(filepath.Join(state, "hub", "locks.json"))
	if json.Unmarshal(b, &lj); lj.Locks["logs"] != nil || lj.Locks["crm-prod"] == nil {
		t.Errorf("locks.json: %s", b)
	}
	ns, err := ReadNotStarted(state)
	if err != nil || ns["logs"] != why || len(ns) != 1 {
		t.Errorf("not started: %v %v", ns, err)
	}
	var st UpState
	b, _ = os.ReadFile(filepath.Join(state, UpFile))
	if json.Unmarshal(b, &st); st.Locks["logs"].Type != "" || st.Locks["crm-prod"].Type == "" {
		t.Errorf("up.json: %s", b)
	}

	// Fixed: a change to review, then it starts and the file goes.
	d := filepath.Join(logs, "nginx")
	os.Mkdir(d, 0o755)
	f.keys["plan/logs"] = "profile app false\nfile " + d + " " + d + "/*.log\n"
	f2 := &fake{keys: f.keys}
	out, err = upLog(w, h, "y\n", f2)
	if err != nil || !strings.Contains(out, "lock logs: started") || !strings.Contains(out, "- lock logs not started: ") {
		t.Fatalf("fixed lock: %v\n%s", err, out)
	}
	if block(f2.upCompose, "lock-logs") == "" {
		t.Errorf("lock-logs not in compose:\n%s", f2.upCompose)
	}
	if ns, err := ReadNotStarted(state); err != nil || ns != nil {
		t.Errorf("not started after the fix: %v %v", ns, err)
	}
}

// lox add of the bad lock itself still stops on it: nothing to serve.
func TestUpFocusOnRefusedPlanStops(t *testing.T) {
	h, _ := logHost(t)
	w := newWS(t, logConf(""))
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nfile /etc /etc/*.conf\n"
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: f,
		In: nil, Out: &out, LogHost: h, Focus: "logs"}
	if err := u.Do(t.Context()); err == nil || !strings.Contains(err.Error(), "/etc is not under an allowed log root") {
		t.Errorf("lox add of a refused lock: %v\n%s", err, out.String())
	}
}

// A lock's log_roots reach lox run's check and the console's environment.
func TestUpLogRootsBindAndEnv(t *testing.T) {
	h, _ := logHost(t)
	extra, _ := filepath.EvalSymlinks(t.TempDir())
	d := filepath.Join(extra, "app")
	os.Mkdir(d, 0o755)
	w := newWS(t, logConf("    log_roots: ["+d+"]\n"))
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nfile " + d + " " + d + "/*.log\n"
	out, err := upLog(w, h, "y\n", f)
	if err != nil || !strings.Contains(out, "lock logs: started") || !strings.Contains(out, "lock logs log roots "+d) {
		t.Fatalf("%v\n%s", err, out)
	}
	if svc := block(f.upCompose, "lock-logs"); !strings.Contains(svc, "      LOCKLOG_EXTRA_ROOTS: \""+d+"\"\n") || !strings.Contains(svc, "source: \""+d+"\"") {
		t.Errorf("lock-logs:\n%s", svc)
	}
}

// lox doctor says a lock not started, and checks the others as applied.
func TestDoctorNotStarted(t *testing.T) {
	d, _ := healthy(t)
	b, _ := os.ReadFile(d.File)
	os.WriteFile(d.File, append(b, []byte("  logs:\n    type: locklog\n    image: "+logImg+"\n")...), 0o644)
	if err := writeNotStarted(d.State, map[string]string{"logs": "mount plan: /x is not under an allowed log root (/var/log /run/log/journal)"}); err != nil {
		t.Fatal(err)
	}
	out, n := doc(t, d)
	if n != 1 || !strings.Contains(out, "FAIL lock logs: not started: mount plan: /x is not under an allowed log root") {
		t.Errorf("%d problems:\n%s", n, out)
	}
	if strings.Contains(out, "changed since") || strings.Contains(out, "lock-logs") {
		t.Errorf("the lock not started is checked as applied:\n%s", out)
	}
}
