package family

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// locklog profile rules --json is read strictly: the profile's three
// actions, each auto, ask or deny; a pending review takes the stricter
// of the approved and the file value; anything else is unknown (every
// ticket asked), never an error.
func TestDeriveLogRules(t *testing.T) {
	r := DeriveLogRules([]byte("noise\n"+rulesJSON("auto", "ask", "deny", "other", "app")), "app")
	if r.Unknown != "" || r.Profile != "app" || r.Get("read") != "auto" || r.Get("unmask") != "ask" || r.Get("lookup") != "deny" {
		t.Fatalf("rules %+v", r)
	}
	if got := r.Line("logs"); got != "lock logs auto rules of profile app: read auto · unmask ask · lookup deny (locklog profile rules, on the reviewed copy)" {
		t.Errorf("line %q", got)
	}
	pending := `{"lock":"locklog","profiles":[{"profile":"app","rules":{"read":"auto","unmask":"auto","lookup":"ask"},"source":"approved",` +
		`"pending_review":true,"file_rules":{"read":"ask","unmask":"auto","lookup":"auto"}}]}`
	if r := DeriveLogRules([]byte(pending), "app"); r.Get("read") != "ask" || r.Get("unmask") != "auto" || r.Get("lookup") != "ask" {
		t.Errorf("pending review: %+v", r)
	}
	for name, out := range map[string]string{
		"empty":         "",
		"not json":      "locklog: no .locklog/ here\n",
		"error":         `{"lock":"locklog","code":"usage","error":"no such profile"}`,
		"another lock":  strings.Replace(rulesJSON("auto", "auto", "auto", "app"), `"locklog"`, `"locksql"`, 1),
		"other profile": rulesJSON("auto", "auto", "auto", "staging"),
		"bad value":     rulesJSON("yes", "auto", "auto", "app"),
		"missing":       `{"lock":"locklog","profiles":[{"profile":"app","rules":{"read":"auto"}}]}`,
		"too long":      rulesJSON("auto", "auto", "auto", "app") + strings.Repeat(" ", maxRules),
	} {
		r := DeriveLogRules([]byte(out), "app")
		if r.Unknown == "" {
			t.Errorf("%s: read as %+v", name, r)
		}
		for _, a := range LogRuleActions {
			if r.Get(a) != "ask" {
				t.Errorf("%s: %s is %s, want ask", name, a, r.Get(a))
			}
		}
		if !strings.HasSuffix(r.Line("logs"), "): lox run asks every ticket") {
			t.Errorf("%s: line %q", name, r.Line("logs"))
		}
	}
	var none *LogRules
	if none.Get("read") != "ask" || !strings.Contains(none.Line("x"), "unknown (none read)") {
		t.Error("nil rules")
	}
}

// rules-<instance>: locklog profile rules on the reviewed copy, as the
// mount plan: the image's agent, no network, no volume.
func TestComposeRulesService(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"logs": {Type: "locklog", Image: logImg, Profile: "app"}}}
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"})
	want := `  "rules-logs":
    image: "` + logImg + `"
    profiles: [setup]
    user: "10052:10050"
    environment:
      HOME: "/tmp"
    entrypoint: ["/bin/sh", "-c", "mkdir -p \"$0/.locklog\" && head -c 526336 | tar -x -C \"$0/.locklog\" && cd \"$0\" && exec locklog profile rules --json \"$@\"", "/w", "--profile", "app"]
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:size=16m", "/w:size=2m,uid=10052,gid=10050,mode=0700"]
    pids_limit: 64
    mem_limit: 256m
`
	if got := block(out, "rules-logs"); got != want {
		t.Errorf("rules-logs:\n%s\nwant:\n%s", got, want)
	}
	// locksql and lockmq have profile rules too (locksql#185, lockmq#49),
	// read as their image's agent; lockfile and lockhttp have none.
	c.Locks["crm-prod"] = Lock{Type: "locksql", Image: sqlImg, Profile: "prod"}
	c.Locks["files"] = Lock{Type: "lockfile", Image: "ghcr.io/davidgodefroid/lockfile@sha256:" + strings.Repeat("4", 64)}
	out = Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"})
	if strings.Count(out, `"rules-`) != 2 {
		t.Errorf("want a rules service for the locklog and the locksql locks only:\n%s", out)
	}
	got := block(out, "rules-crm-prod")
	for _, want := range []string{`user: "10002:10000"`, `exec locksql profile rules --json \"$@\"", "/w", "--profile", "prod"]`, "network_mode: none", `uid=10002,gid=10000`} {
		if !strings.Contains(got, want) {
			t.Errorf("rules-crm-prod lacks %s:\n%s", want, got)
		}
	}
}

// lox run reads a locksql and a lockmq lock's rules from their reviewed
// copy, shows them in the review and keeps them for its engine; rules it
// cannot read (an image before `profile rules`) leave the engine's
// defaults, as before, and the stack starts.
func TestUpSQLAndMQRules(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	f.keys["rules/crm-prod"] = `{"lock":"locksql","profiles":[{"profile":"prod","production":true,"rules":{"connect":"auto","read":"auto","write":"deny","ddl":"deny","unmask":"ask"}}]}` + "\n"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	st := filepath.Join(w.dir, "state")
	m := AppliedProfileRules(st, c)
	if r := m["crm-prod"]["prod"]; r == nil || r.Get("connect") != "auto" || r.Get("write") != "deny" || r.Unknown != "" {
		t.Errorf("locksql rules applied as %+v", m["crm-prod"])
	}
	if r := m["events"]["default"]; r == nil || r.Get("list") != "auto" || r.Get("peek") != "ask" || r.Get("connect") != "ask" {
		t.Errorf("lockmq rules applied as %+v", m["events"])
	}
	ab, _ := os.ReadFile(filepath.Join(st, "applied.json"))
	for _, want := range []string{
		"lock crm-prod auto rules of profile prod: connect auto · read auto · write deny · ddl deny · unmask ask (locksql profile rules, on the reviewed copy)",
		"lock events auto rules of profile default: connect ask · list auto · read auto · peek ask · get ask · publish ask · purge ask · delete ask (lockmq profile rules, on the reviewed copy)",
	} {
		if !strings.Contains(string(ab), want) {
			t.Errorf("the applied summary lacks %q:\n%s", want, ab)
		}
	}
	// A change of rules is a change to confirm.
	f2 := &fake{keys: maps.Clone(f.keys)}
	f2.keys["rules/crm-prod"] = strings.Replace(f.keys["rules/crm-prod"], `"write":"deny"`, `"write":"auto"`, 1)
	if out, err := w.up("n\n", f2); !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "write auto") {
		t.Errorf("loosened rules: %v\n%s", err, out)
	}
	// Unreadable: said, the defaults kept, nothing asked more than before.
	f3 := &fake{keys: maps.Clone(f.keys)}
	f3.keys["rules/crm-prod"] = "unknown command: profile rules\n"
	out, err = w.up("y\n", f3)
	if err != nil || !strings.Contains(out, "warning: lock crm-prod: auto rules unknown") || !strings.Contains(out, "lox run keeps its defaults for this lock") {
		t.Errorf("unknown rules: %v\n%s", err, out)
	}
	if r := AppliedProfileRules(st, c)["crm-prod"][""]; r == nil || r.Unknown == "" {
		t.Errorf("unknown rules applied as %+v", r)
	}
}

// lox run reads the rules on the reviewed copy before the review, shows
// them, keeps them with the applied plan (lox run --no-start reads them
// there), and a change of rules is a change to confirm; rules it cannot
// read are shown unknown, with a warning, and every ticket is asked.
func TestUpLocklogRules(t *testing.T) {
	h, _ := logHost(t)
	w := newWS(t, logConf("    profile: app\n"))
	f := newFake()
	f.keys["logs"] = pubKey()
	f.keys["plan/logs"] = "profile app false\nremote\n"
	f.keys["rules/logs"] = rulesJSON("auto", "ask", "deny", "app")
	out, err := upLog(w, h, "y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var rules string
	for _, c := range f.calls {
		if strings.HasSuffix(c, "--no-deps rules-logs") {
			rules = c
		}
	}
	if rules == "" || string(f.stdins[rules]) == "" || strings.Index(out, "Apply?") < 0 {
		t.Fatalf("locklog profile rules did not run on the copy before the review: %v\n%s", f.calls, out)
	}
	line := "lock logs auto rules of profile app: read auto · unmask ask · lookup deny (locklog profile rules, on the reviewed copy)"
	if !strings.Contains(out, line) {
		t.Errorf("review lacks %q:\n%s", line, out)
	}
	state := filepath.Join(w.dir, "state")
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if r := AppliedLogRules(state, c)["logs"]; r == nil || r.Profile != "app" || r.Get("read") != "auto" || r.Get("lookup") != "deny" {
		t.Errorf("applied rules %+v", r)
	}
	if _, ok := AppliedLogRules(state, c)["crm-prod"]; ok {
		t.Error("rules for a locksql lock")
	}
	// The same rules: nothing to review.
	if out, err := upLog(w, h, "", &fake{keys: f.keys}); err != nil || !strings.Contains(out, "configuration unchanged") {
		t.Errorf("unchanged: %v\n%s", err, out)
	}
	// A loosening is a change to confirm.
	f.keys["rules/logs"] = rulesJSON("auto", "auto", "deny", "app")
	out, err = upLog(w, h, "", &fake{keys: f.keys})
	if err == nil || !strings.Contains(out, "+ lock logs auto rules of profile app: read auto · unmask auto · lookup deny") {
		t.Errorf("a rules change is not reviewed: %v\n%s", err, out)
	}
	// lox doctor takes them for the profile's, not for a yaml change.
	d := &Doctor{State: state, Run: f}
	var lines []string
	d.applied(c, func(fm string, a ...any) { lines = append(lines, "warn "+strings.TrimSpace(fm)) })
	if strings.Contains(strings.Join(lines, "\n"), "changed since") {
		t.Errorf("doctor: %v", lines)
	}
	// Rules that cannot be read: unknown, a warning, every ticket asked.
	f.keys["rules/logs"] = "locklog: profile rules: unknown subcommand\n"
	out, err = upLog(w, h, "y\n", &fake{keys: f.keys})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "warning: lock logs: auto rules unknown (locklog profile rules gave no answer lox run reads): lox run asks every ticket of this lock") ||
		!strings.Contains(out, "lock logs auto rules of profile app: unknown (") {
		t.Errorf("unknown rules:\n%s", out)
	}
	if r := AppliedLogRules(state, c)["logs"]; r.Unknown == "" || r.Get("read") != "ask" {
		t.Errorf("applied unknown rules %+v", r)
	}
	// A plan from before the rules: unknown.
	os.Remove(filepath.Join(state, "locklog", "logs", planFile))
	if r := AppliedLogRules(state, c)["logs"]; r.Unknown == "" || r.Get("read") != "ask" {
		t.Errorf("no plan: %+v", r)
	}
}
