package family

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// logHost is a host whose log roots and journal live under a temp dir;
// the group of gid adm is "adm" (the host user's own group stands in).
func logHost(t *testing.T) (*LogHost, string) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	logs := filepath.Join(root, "log")
	os.MkdirAll(logs, 0o755)
	adm := uint32(os.Getgid())
	return &LogHost{Roots: []string{logs}, Journals: []string{filepath.Join(logs, "journal"), filepath.Join(root, "run-journal")}, GOOS: "linux",
		GroupName: func(g uint32) string {
			if g == adm {
				return "adm"
			}
			return "other"
		}}, logs
}

func derive(t *testing.T, h *LogHost, f *fake, plan string) (*LogPlan, error) {
	t.Helper()
	if f == nil {
		f = &fake{}
	}
	return DeriveLogPlan(context.Background(), f, h, []byte(plan), "/s/locklog/logs/map")
}

// The plan's file and journald lines are bound and checked as the
// launcher's plan_line: under an allowed root, real paths, the groups the
// files grant (only adm and systemd-journal), dev:inode of each root.
func TestDeriveLogPlanLocal(t *testing.T) {
	h, logs := logHost(t)
	open := filepath.Join(logs, "nginx")
	os.Mkdir(open, 0o755)
	os.WriteFile(filepath.Join(open, "access.log"), []byte("x\n"), 0o644)
	grp := filepath.Join(logs, "app")
	os.Mkdir(grp, 0o750)
	os.WriteFile(filepath.Join(grp, "app.log"), []byte("x\n"), 0o640)
	os.Chmod(grp, 0o750)
	jn := filepath.Join(logs, "journal")
	os.Mkdir(jn, 0o755)
	p, err := derive(t, h, nil, "profile app false\nfile "+grp+" "+grp+"/*.log\nfile "+open+" "+open+"/access.log*\njournald\n")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Binds, []string{grp, open, jn}) || p.Profile != "app" || p.Production || p.Remote || p.DockerRoot != "" || p.MapDir != "" {
		t.Errorf("plan %+v", p)
	}
	if !slices.Equal(p.GIDs, []uint32{uint32(os.Getgid())}) {
		t.Errorf("gids %v (the adm group grants app/)", p.GIDs)
	}
	for _, d := range p.Binds {
		di, _ := devIno(d)
		if !strings.Contains(p.Expect, di+" "+d+";") {
			t.Errorf("expect %q lacks %s", p.Expect, d)
		}
	}
	rev := strings.Join(p.Review("logs"), "\n")
	for _, want := range []string{
		"lock logs mount plan of profile app (production false), from locklog mounts on the reviewed copy",
		"lock logs plan file " + grp + " " + grp + "/*.log", "lock logs plan journald",
		"lock logs bind " + open + " (read-only, non-recursive)", "lock logs bind " + jn + " (read-only, non-recursive)",
		fmt.Sprintf("lock logs groups %d", os.Getgid()),
	} {
		if !strings.Contains(rev, want) {
			t.Errorf("review lacks %q:\n%s", want, rev)
		}
	}
	// Every file is readable, and one of the two journal directories
	// exists: no warning.
	if len(p.Warnings) != 0 {
		t.Errorf("warnings %v", p.Warnings)
	}

	// A group the console may not join: a warning, no gid.
	h.GroupName = func(uint32) string { return "staff" }
	p, err = derive(t, h, nil, "profile app true\nfile "+grp+" "+grp+"/*.log\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.GIDs) != 0 || len(p.Warnings) != 2 || !p.Production {
		t.Errorf("not an allowed group: gids %v, warnings %v", p.GIDs, p.Warnings)
	}
	// No journal directory: a warning.
	os.Remove(jn)
	if p, err = derive(t, h, nil, "profile app false\njournald\n"); err != nil || len(p.Binds) != 0 || len(p.Warnings) != 1 {
		t.Errorf("no journal: %+v %v", p, err)
	}
}

func TestDeriveLogPlanRefusals(t *testing.T) {
	h, logs := logHost(t)
	d := filepath.Join(logs, "nginx")
	os.Mkdir(d, 0o755)
	os.Symlink(d, filepath.Join(logs, "link"))
	outside, _ := filepath.EvalSymlinks(t.TempDir())
	for name, plan := range map[string]string{
		"no header":       "file " + d + " " + d + "/*.log\n",
		"bad header":      "profile a b\n",
		"outside roots":   "profile a false\nfile " + outside + " " + outside + "/*.log\n",
		"link":            "profile a false\nfile " + logs + "/link " + logs + "/link/*.log\n",
		"root":            "profile a false\nfile / /*.log\n",
		"relative":        "profile a false\nfile var/log var/log/*.log\n",
		"glob elsewhere":  "profile a false\nfile " + d + " /etc/*.log\n",
		"not clean":       "profile a false\nfile " + d + " " + d + "/../x.log\n",
		"unsafe":          "profile a false\nfile " + d + " " + d + "/a=b.log\n",
		"extra field":     "profile a false\nfile " + d + " " + d + "/x.log y\n",
		"unknown":         "profile a false\nsocket /run/x\n",
		"bad glob":        "profile a false\ndocker -web\n",
		"docker beside":   "profile a false\nfile " + d + " " + d + "/*.log\ndocker web-*\n",
		"journald beside": "profile a false\njournald\ndocker web-*\n",
		"remote field":    "profile a false\nremote loki\n",
	} {
		if _, err := derive(t, h, nil, plan); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Docker Desktop on macOS, rootless Docker: no local source.
	mac := *h
	mac.GOOS = "darwin"
	if _, err := derive(t, &mac, nil, "profile a false\nfile "+d+" "+d+"/*.log\n"); err == nil {
		t.Error("macOS: local source accepted")
	}
	if p, err := derive(t, &mac, nil, "profile a false\nremote\n"); err != nil || !p.Remote {
		t.Errorf("macOS: remote source refused: %v", err)
	}
	rl := &fake{keys: map[string]string{"docker/docker info --format {{.SecurityOptions}}": "[name=seccomp name=rootless]\n"}}
	if _, err := derive(t, h, rl, "profile a false\ndocker web-*\n"); err == nil || !strings.Contains(err.Error(), "rootless") {
		t.Errorf("rootless: %v", err)
	}
}

// A docker source binds the containers root (docker info) with gid 0, and
// the containers map directory.
func TestDeriveLogPlanDocker(t *testing.T) {
	h, _ := logHost(t)
	dr, _ := filepath.EvalSymlinks(t.TempDir())
	os.Mkdir(filepath.Join(dr, "containers"), 0o710)
	f := &fake{keys: map[string]string{"docker/docker info --format {{.DockerRootDir}}": dr + "\n"}}
	p, err := derive(t, h, f, "profile ctr false\ndocker shop-*\ndocker web\ndocker shop-*\nremote\n")
	if err != nil {
		t.Fatal(err)
	}
	r := dr + "/containers"
	if p.DockerRoot != r || !slices.Equal(p.Binds, []string{r}) || !slices.Equal(p.GIDs, []uint32{0}) || !slices.Equal(p.DockerGlobs, []string{"shop-*", "web"}) || p.MapDir != "/s/locklog/logs/map" || !p.Remote {
		t.Errorf("plan %+v", p)
	}
	rev := strings.Join(p.Review("ctr"), "\n")
	if !strings.Contains(rev, "lock ctr bind "+r+" (read-only, non-recursive; the Docker containers root, group 0 for it only)") ||
		!strings.Contains(rev, "lock ctr groups 0") || !strings.Contains(rev, "lock ctr containers map /s/locklog/logs/map at /run/locklog-map (read-only)") {
		t.Errorf("review:\n%s", rev)
	}
	// The root lox run cannot stat (/var/lib/docker is 0710 root): bound,
	// said so, no expected device and inode.
	p, err = derive(t, h, &fake{}, "profile ctr false\ndocker web\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, can := devIno("/var/lib/docker/containers"); !can && (p.Expect != "" || !strings.Contains(strings.Join(p.Review("c"), "\n"), "not checked from the host")) {
		t.Errorf("unstat-able root: %+v", p)
	}
	for _, bad := range []string{"relative", "/a b", "/x/../y", "/"} {
		f := &fake{keys: map[string]string{"docker/docker info --format {{.DockerRootDir}}": bad + "\n"}}
		if _, err := derive(t, h, f, "profile ctr false\ndocker web\n"); err == nil {
			t.Errorf("docker root %q accepted", bad)
		}
	}
}

func inspectJSON(id, name, driver string, cfg map[string]string, labels map[string]string) string {
	var c []string
	for k, v := range cfg {
		c = append(c, fmt.Sprintf("%q:%q", k, v))
	}
	var l []string
	for k, v := range labels {
		l = append(l, fmt.Sprintf("%q:%q", k, v))
	}
	return fmt.Sprintf(`{"Id":%q,"Name":"/%s","Config":{"Labels":{%s}},"HostConfig":{"LogConfig":{"Type":%q,"Config":{%s}}}}`, id, name, strings.Join(l, ","), driver, strings.Join(c, ","))
}

func cid(c byte) string { return strings.Repeat(string(c), 64) }

// mapFake is a Docker host with these containers.
func mapFake(recs map[string]string) *fake {
	f := &fake{keys: map[string]string{}}
	var ids []string
	for id, rec := range recs {
		ids = append(ids, id)
		f.keys["docker/docker inspect --type container --format {{json .}} "+id] = rec
	}
	slices.Sort(ids)
	f.keys["docker/docker ps -a -q --no-trunc"] = strings.Join(ids, "\n") + "\n"
	return f
}

// The map is the launcher's: json-file containers the approved globs
// name, console containers and unparsable records excluded.
func TestBuildLogMap(t *testing.T) {
	f := mapFake(map[string]string{
		cid('a'): inspectJSON(cid('a'), "shop-api-1", "json-file", map[string]string{"max-file": "3", "compress": "true"}, nil),
		cid('b'): inspectJSON(cid('b'), "shop-worker-1", "json-file", map[string]string{"max-file": "500"}, nil),
		cid('c'): inspectJSON(cid('c'), "shop-local", "local", nil, nil),
		cid('d'): inspectJSON(cid('d'), "lockfamily-1-lock-logs-1", "json-file", nil, map[string]string{"locklog.console": "1"}),
		cid('e'): inspectJSON(cid('e'), "locklog-console-42", "json-file", nil, nil),
		cid('f'): inspectJSON(cid('f'), "other", "json-file", nil, nil),
		cid('0'): inspectJSON(cid('0'), "shop-bad", "json-file", map[string]string{"max-file": "x"}, nil),
		cid('1'): inspectJSON(cid('1'), "-bad name", "json-file", nil, nil),
	})
	m, err := BuildLogMap(context.Background(), f, []string{"shop-*"})
	if err != nil {
		t.Fatal(err)
	}
	want := "locklog-map 1\n" +
		"c " + cid('a') + " shop-api-1 3 1\n" +
		"c " + cid('b') + " shop-worker-1 100 0\n" +
		"x " + cid('1') + "\nx " + cid('d') + "\nx " + cid('e') + "\n"
	if m.Content != want || m.Mapped != 2 || m.Excluded != 3 || m.Skips != 3 {
		t.Errorf("map %d/%d/%d:\n%s\nwant:\n%s", m.Mapped, m.Excluded, m.Skips, m.Content, want)
	}
	if _, err := BuildLogMap(context.Background(), &fake{failing: "docker ps"}, []string{"x"}); err == nil {
		t.Error("docker ps failing: no error")
	}
}

// Each write is a new version, atomically; the last two are kept.
func TestWriteLogMapVersions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "map")
	for i := 1; i <= 3; i++ {
		v, err := WriteLogMap(dir, LogMap{Content: fmt.Sprintf("locklog-map 1\n# %d\n", i)})
		if err != nil || v != i {
			t.Fatalf("write %d: v%d %v", i, v, err)
		}
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"map.v2", "map.v3"}) {
		t.Errorf("versions %v", names)
	}
	fi, _ := os.Stat(filepath.Join(dir, "map.v3"))
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o644 || di.Mode().Perm() != 0o755 {
		t.Errorf("modes %v %v", fi.Mode().Perm(), di.Mode().Perm())
	}
}

// afterUp is f until compose up ran, then answers the docker commands of
// after (the containers compose created).
type afterUp struct {
	*fake
	after map[string]string
	up    bool
}

func (a *afterUp) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	out, err := a.fake.Run(ctx, stdin, name, args...)
	if strings.Contains(line, " up -d") {
		a.up = true
	}
	if v, ok := a.after["docker/"+line]; ok && a.up {
		return []byte(v), nil
	}
	return out, err
}

// upLog is w.up with a log host.
func upLog(w ws, h *LogHost, input string, f Runner) (string, error) {
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: f,
		In: bufio.NewReader(strings.NewReader(input)), Out: &out, LogHost: h}
	err := u.Do(context.Background())
	return out.String(), err
}

// lox run derives the plan on the reviewed copy, shows every line of it,
// and mounts exactly that: binds, groups, the device and inode the
// console checks, its PII dir.
func TestUpMountsLocklogPlan(t *testing.T) {
	h, logs := logHost(t)
	d := filepath.Join(logs, "nginx")
	os.Mkdir(d, 0o755)
	w := newWS(t, logConf("    profile: app\n"))
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nfile " + d + " " + d + "/*.log\n"
	out, err := upLog(w, h, "y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// locklog mounts ran on the reviewed copy, with its profile, before
	// the review.
	var mounts string
	for _, c := range f.calls {
		if strings.HasSuffix(c, "--no-deps mounts-logs") {
			mounts = c
		}
	}
	if mounts == "" || string(f.stdins[mounts]) == "" {
		t.Fatalf("locklog mounts did not run on the copy: %v", f.calls)
	}
	for _, want := range []string{"lock logs plan file " + d + " " + d + "/*.log", "lock logs bind " + d + " (read-only, non-recursive)", "lock logs mount plan of profile app (production false)"} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	svc := block(f.upCompose, "lock-logs")
	di, _ := devIno(d)
	for _, want := range []string{
		"      LOCKLOG_EXPECT_DIR: \"2049:131074\"\n", "      LOCKLOG_EXPECT_ROOTS: \"" + di + " " + d + ";\"\n", "      LOCKLOG_PII_DIR: \"/home/locklog/pii-rules\"\n",
		"      - type: bind\n        source: \"" + d + "\"\n        target: \"" + d + "\"\n        read_only: true\n        bind:\n          recursive: disabled\n",
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("lock-logs lacks %q:\n%s", want, svc)
		}
	}
	if strings.Contains(svc, "group_add") || strings.Contains(svc, "locklog-map") {
		t.Errorf("no group, no map:\n%s", svc)
	}
	state := filepath.Join(w.dir, "state")
	if p, err := ReadLogPlan(state, "logs"); err != nil || !slices.Equal(p.Binds, []string{d}) {
		t.Errorf("applied plan: %+v %v", p, err)
	}
	// A new line in the plan is a change to review.
	d2 := filepath.Join(logs, "app")
	os.Mkdir(d2, 0o755)
	f.keys["plan/logs"] += "file " + d2 + " " + d2 + "/*.log\n"
	out, err = upLog(w, h, "", &fake{keys: f.keys})
	if err == nil || !strings.Contains(out, "+ lock logs bind "+d2+" (read-only, non-recursive)") {
		t.Errorf("a new bind is not reviewed: %v\n%s", err, out)
	}
	// A plan the host check refuses stops lox run before the review.
	f.keys["plan/logs"] = "profile app false\nfile /etc /etc/*.conf\n"
	if out, err := upLog(w, h, "y\n", &fake{keys: f.keys}); err == nil || strings.Contains(out, "Apply?") {
		t.Errorf("/etc mounted: %v\n%s", err, out)
	}
}

// A docker source: the containers root with gid 0, the map lox run writes
// in its state, lox refresh rewrites, and lox doctor checks.
func TestUpLocklogDockerMapRefreshDoctor(t *testing.T) {
	h, _ := logHost(t)
	w := newWS(t, logConf(""))
	f := mapFake(map[string]string{cid('a'): inspectJSON(cid('a'), "shop-api-1", "json-file", nil, nil)})
	for k, v := range newFake().keys {
		f.keys[k] = v
	}
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile ctr false\ndocker shop-*\n"
	// compose up creates the console: from then on, docker ps lists it.
	console := mapFake(map[string]string{
		cid('a'): inspectJSON(cid('a'), "shop-api-1", "json-file", nil, nil),
		cid('c'): inspectJSON(cid('c'), "lockfamily-x-lock-logs-1", "json-file", nil, map[string]string{LocklogConsoleLabel: "1"}),
	})
	out, err := upLog(w, h, "y\n", &afterUp{fake: f, after: console.keys})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	state := filepath.Join(w.dir, "state")
	dir := LogMapDir(state, "logs")
	// v1 before the consoles start (the console reads one at its start),
	// v2 once they exist: their ids excluded.
	b, err := os.ReadFile(filepath.Join(dir, "map.v1"))
	if err != nil || string(b) != "locklog-map 1\nc "+cid('a')+" shop-api-1 1 0\n" {
		t.Fatalf("map.v1: %v\n%s", err, b)
	}
	b, err = os.ReadFile(filepath.Join(dir, "map.v2"))
	if err != nil || string(b) != "locklog-map 1\nc "+cid('a')+" shop-api-1 1 0\nx "+cid('c')+"\n" {
		t.Fatalf("map.v2: %v\n%s", err, b)
	}
	svc := block(f.upCompose, "lock-logs")
	for _, want := range []string{`group_add: ["0"]`, "LOCKLOG_DOCKER_ROOT: \"/var/lib/docker/containers\"", "        source: \"" + dir + "\"\n        target: \"/run/locklog-map\"\n        read_only: true\n", "        source: \"/var/lib/docker/containers\""} {
		if !strings.Contains(svc, want) {
			t.Errorf("lock-logs lacks %q:\n%s", want, svc)
		}
	}
	if !strings.Contains(out, "lock logs containers map "+dir) {
		t.Errorf("review:\n%s", out)
	}
	c, _ := Load(w.file)
	d := &Doctor{State: state, Run: console}
	var lines []string
	rec := func(p string) func(string, ...any) {
		return func(fm string, a ...any) { lines = append(lines, p+fmt.Sprintf(fm, a...)) }
	}
	d.logMaps(context.Background(), c, rec("ok "), rec("warn "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "ok lock logs containers map: map.v2 current") {
		t.Errorf("doctor: %v", lines)
	}
	// The mount plan derives from the profile: not a change of
	// lockfamily.yaml for the doctor.
	lines = nil
	d.applied(c, rec("warn "))
	if slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "changed since") }) {
		t.Errorf("doctor, applied: %v", lines)
	}
	// A container created since: stale until lox refresh.
	g := mapFake(map[string]string{cid('a'): inspectJSON(cid('a'), "shop-api-1", "json-file", nil, nil), cid('b'): inspectJSON(cid('b'), "shop-api-2", "json-file", nil, nil),
		cid('c'): inspectJSON(cid('c'), "lockfamily-x-lock-logs-1", "json-file", nil, map[string]string{LocklogConsoleLabel: "1"})})
	d.Run, lines = g, nil
	d.logMaps(context.Background(), c, rec("ok "), rec("warn "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "warn lock logs containers map: map.v2 is stale") || !strings.Contains(lines[0], "lox refresh logs") {
		t.Errorf("doctor, stale: %v", lines)
	}
	msg, err := Refresh(context.Background(), g, state, c, "logs")
	if err != nil || !strings.Contains(msg, "containers map v3 of logs") || !strings.Contains(msg, "2 mapped") {
		t.Errorf("refresh: %q %v", msg, err)
	}
	lines = nil
	d.logMaps(context.Background(), c, rec("ok "), rec("warn "), rec("fail "))
	if len(lines) != 1 || !strings.Contains(lines[0], "map.v3 current: 2 mapped") {
		t.Errorf("doctor after refresh: %v", lines)
	}
	// Nothing changed: updateLogMap writes no new version.
	p, _ := ReadLogPlan(state, "logs")
	if v, wrote, err := updateLogMap(context.Background(), g, p); v != 3 || wrote || err != nil {
		t.Errorf("update, unchanged: v%d %v %v", v, wrote, err)
	}
	// No map at all: a failure.
	os.RemoveAll(dir)
	lines = nil
	d.logMaps(context.Background(), c, rec("ok "), rec("warn "), rec("fail "))
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "fail ") {
		t.Errorf("doctor, no map: %v", lines)
	}
	// lox refresh refuses a lock with no map.
	if _, err := Refresh(context.Background(), g, state, c, "crm-prod"); err == nil {
		t.Error("refresh of a locksql lock")
	}
	if _, err := Refresh(context.Background(), g, state, c, "nope"); err == nil {
		t.Error("refresh of an unknown lock")
	}
	if _, err := Refresh(context.Background(), g, t.TempDir(), c, "logs"); err == nil {
		t.Error("refresh before lox run")
	}
}

// mounts-<instance>: locklog mounts on the copy, as the image's agent,
// no network, the copy unpacked in a tmpfs at the workspace's path.
func TestComposeMountsService(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"logs": {Type: "locklog", Image: logImg, Profile: "app"}}}
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"})
	want := `  "mounts-logs":
    image: "` + logImg + `"
    profiles: [setup]
    user: "10052:10050"
    environment:
      HOME: "/tmp"
    entrypoint: ["/bin/sh", "-c", "mkdir -p \"$0/.locklog\" && head -c 526336 | tar -x -C \"$0/.locklog\" && cd \"$0\" && exec locklog mounts \"$@\"", "/w", "--profile", "app"]
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m", "/w:size=2m,uid=10052,gid=10050,mode=0700"]
    pids_limit: 64
    mem_limit: 256m
`
	if got := block(out, "mounts-logs"); got != want {
		t.Errorf("mounts-logs:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(block(out, "profile-locklog"), "&& stat -c %d:%i /p") || strings.Contains(out, "mounts-crm") {
		t.Errorf("profile-locklog:\n%s", block(out, "profile-locklog"))
	}
	// No other type prints its copy's inode or gets a plan service.
	c.Locks["crm-prod"] = Lock{Type: "locksql", Image: sqlImg}
	out = Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"})
	if strings.Contains(block(out, "profile-locksql"), "stat -c") || strings.Count(out, "mounts-") != 1 {
		t.Errorf("other kinds:\n%s", out)
	}
}

// The writer lock: a live writer's is waited for, then refused; a killed
// writer's (older than mapLockStale) is taken over, with its temporary
// files.
func TestWriteLogMapLock(t *testing.T) {
	tries, wait := mapLockTries, mapLockWait
	mapLockTries, mapLockWait = 2, time.Millisecond
	t.Cleanup(func() { mapLockTries, mapLockWait = tries, wait })
	dir := filepath.Join(t.TempDir(), "map")
	if _, err := WriteLogMap(dir, LogMap{Content: "locklog-map 1\n"}); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ".lock")
	os.Mkdir(lock, 0o700)
	if _, err := WriteLogMap(dir, LogMap{Content: "locklog-map 1\n"}); err == nil || !strings.Contains(err.Error(), "another writer holds the map") {
		t.Errorf("a held lock: %v", err)
	}
	old := time.Now().Add(-2 * time.Minute)
	tmp := filepath.Join(dir, ".map.tmp.123")
	os.WriteFile(tmp, []byte("partial"), 0o600)
	os.Chtimes(tmp, old, old)
	os.Chtimes(lock, old, old)
	if v, err := WriteLogMap(dir, LogMap{Content: "locklog-map 1\n"}); err != nil || v != 2 {
		t.Errorf("a stale lock: v%d %v", v, err)
	}
	for _, p := range []string{lock, tmp} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s left behind: %v", p, err)
		}
	}
	// The map directory is never a link.
	link := filepath.Join(t.TempDir(), "map")
	os.Symlink(dir, link)
	if _, err := WriteLogMap(link, LogMap{Content: "locklog-map 1\n"}); err == nil {
		t.Error("a link as the map directory")
	}
}

// The map's own rules, as the console parses it: a name given to two ids
// maps neither; an id listed twice is excluded; a compress the launcher
// does not know skips the container; no max-file is 1.
func TestBuildLogMapDuplicates(t *testing.T) {
	f := mapFake(map[string]string{
		cid('a'): inspectJSON(cid('a'), "web", "json-file", nil, nil),
		cid('b'): inspectJSON(cid('b'), "web", "json-file", nil, nil),
		cid('c'): inspectJSON(cid('c'), "web-2", "json-file", map[string]string{"compress": "yes"}, nil),
		cid('d'): inspectJSON(cid('d'), "web-3", "json-file", map[string]string{"max-file": "0"}, nil),
	})
	f.keys["docker/docker ps -a -q --no-trunc"] += cid('d') + "\nnot-an-id\n"
	m, err := BuildLogMap(context.Background(), f, []string{"web*"})
	if err != nil {
		t.Fatal(err)
	}
	want := "locklog-map 1\nx " + cid('a') + "\nx " + cid('b') + "\nx " + cid('d') + "\n"
	if m.Content != want || m.Mapped != 0 || m.Skips != 1 {
		t.Errorf("map %d/%d/%d:\n%s\nwant:\n%s", m.Mapped, m.Excluded, m.Skips, m.Content, want)
	}
	// max-file 0 is clamped to 1.
	g := mapFake(map[string]string{cid('d'): inspectJSON(cid('d'), "web-3", "json-file", map[string]string{"max-file": "0"}, nil)})
	if m, _ := BuildLogMap(context.Background(), g, []string{"web*"}); m.Content != "locklog-map 1\nc "+cid('d')+" web-3 1 0\n" {
		t.Errorf("max-file 0:\n%s", m.Content)
	}
}

// The applied plan and the map live in the persistent state directory,
// host only: 0700 parents, a 0755 map directory the console reads
// through its read-only bind.
func TestLogStateModes(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	os.Mkdir(state, 0o700)
	p := &LogPlan{Profile: "ctr", DockerGlobs: []string{"web"}, MapDir: LogMapDir(state, "logs")}
	if err := writeLogPlan(state, "logs", p); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteLogMap(p.MapDir, LogMap{Content: "locklog-map 1\n"}); err != nil {
		t.Fatal(err)
	}
	for d, want := range map[string]os.FileMode{
		filepath.Join(state, "locklog"):                   0o700,
		filepath.Join(state, "locklog", "logs"):           0o700,
		filepath.Join(state, "locklog", "logs", "map"):    0o755,
		filepath.Join(state, "locklog", "logs", planFile): 0o600,
	} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", d, fi.Mode().Perm(), err, want)
		}
	}
	got, err := ReadLogPlan(state, "logs")
	if err != nil || got.Profile != "ctr" || !slices.Equal(got.DockerGlobs, []string{"web"}) {
		t.Errorf("read back: %+v %v", got, err)
	}
	// A plan directory others can read is refused.
	os.Chmod(filepath.Join(state, "locklog", "logs"), 0o755)
	if _, err := ReadLogPlan(state, "logs"); err == nil {
		t.Error("a 0755 plan directory read")
	}
}

// lox doctor: a renamed or removed container is a stale map too.
func TestLogMapStaleRenamedRemoved(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	os.Mkdir(state, 0o700)
	p := &LogPlan{Profile: "ctr", DockerGlobs: []string{"web*"}, MapDir: LogMapDir(state, "logs")}
	writeLogPlan(state, "logs", p)
	f := mapFake(map[string]string{cid('a'): inspectJSON(cid('a'), "web-1", "json-file", nil, nil), cid('b'): inspectJSON(cid('b'), "web-2", "json-file", nil, nil)})
	m, _ := BuildLogMap(context.Background(), f, p.DockerGlobs)
	WriteLogMap(p.MapDir, m)
	if _, stale, err := logMapStale(context.Background(), f, state, "logs"); stale || err != nil {
		t.Fatalf("current: %v %v", stale, err)
	}
	for name, g := range map[string]*fake{
		"renamed": mapFake(map[string]string{cid('a'): inspectJSON(cid('a'), "web-one", "json-file", nil, nil), cid('b'): inspectJSON(cid('b'), "web-2", "json-file", nil, nil)}),
		"removed": mapFake(map[string]string{cid('a'): inspectJSON(cid('a'), "web-1", "json-file", nil, nil)}),
	} {
		if msg, stale, err := logMapStale(context.Background(), g, state, "logs"); !stale || err != nil || !strings.Contains(msg, "run lox refresh logs") {
			t.Errorf("%s: %q %v %v", name, msg, stale, err)
		}
	}
	// No docker source: nothing to say.
	writeLogPlan(state, "files", &LogPlan{Profile: "app"})
	if msg, stale, err := logMapStale(context.Background(), f, state, "files"); msg != "" || stale || err != nil {
		t.Errorf("no docker source: %q %v %v", msg, stale, err)
	}
}
