package loxrun

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

var update = flag.Bool("update", false, "rewrite the golden files (and docs/lox-run.svg)")

var t0 = time.Date(2026, 11, 6, 14, 2, 0, 0, time.UTC)

// sampleView is a busy session: two connected profiles (one production),
// a write question on production, auto reads folded, a denial, an error.
func sampleView() View {
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	return View{
		Workspace: "~/Documents/shop",
		Mode:      Auto,
		HubOK:     true,
		Locks:     3,
		Now:       at(300),
		Loc:       time.UTC,
		Profiles: []ProfileConn{
			{Name: "shop/prod", Since: at(12), Production: true},
			{Name: "shop/dev", Since: at(250)},
		},
		Cards: []Card{{
			ID: "01K", Instance: "shop", Lock: "locksql", Agent: "dev-1", Profile: "prod", Kind: ticket.KindWrite,
			Risk: "prod-write", Production: true, Header: "shop / prod · write",
			Body:     []string{"UPDATE customers SET email = j***(20) WHERE id = 4***(3)", "-- 1 row (estimated)"},
			Warnings: []string{"production"}, Touched: []string{"email"},
			Why: "write is always asked", Expires: at(300 + 540),
		}, {ID: "01L", Instance: "shop", Lock: "locksql", Agent: "dev-2", Kind: ticket.KindDDL}},
		Feed: []Entry{
			{At: at(12), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindConnect,
				Summary: "shop/prod · connect db.internal:5432/shop", Status: Approved, Result: ResRan},
			{At: at(14), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindRead,
				Summary: "SELECT id, total FROM orders WHERE customer = c***(8)", Target: "orders", Status: AutoApproved, Rule: "default:read", Result: ResRan, Count: 12},
			{At: at(61), Agent: "web-agent", Instance: "mq", Lock: "lockmq", Profile: "local", Kind: ticket.KindAction,
				Summary: "PEEK orders.created (10 messages)", Status: AutoApproved, Rule: "default:action", Result: ResRan},
			{At: at(90), Agent: "web-agent", Instance: "api", Lock: "lockhttp", Profile: "stripe", Kind: ticket.KindEndpoint,
				Summary: "GET api.stripe.com/v1/charges", Status: Approved, Result: ResRan},
			{At: at(150), Agent: "dev-2", Instance: "shop", Lock: "locksql", Profile: "dev", Kind: ticket.KindDDL,
				Summary: "DROP TABLE sessions", Status: Denied},
			{At: at(200), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindWrite,
				Summary: "INSERT INTO audit_notes (note) VALUES (<redacted>)", Status: Failed, Note: "hub refused"},
			{At: at(299), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindWrite,
				Summary: "UPDATE customers SET email = j***(20) WHERE id = 4***(3)", Status: Waiting, Tag: "ask:write"},
		},
	}
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func visible(s string) string { return ansi.ReplaceAllString(s, "") }

type variant struct {
	name string
	st   Style
	w, h int
	mod  func(*View)
}

var variants = []variant{
	{"dark-120", Style{Color: true, Unicode: true}, 120, 28, nil},
	{"light-120", Style{Color: true, Unicode: true, Light: true}, 120, 28, nil},
	{"nocolor-80", Style{Unicode: true}, 80, 24, nil},
	{"dark-80", Style{Color: true, Unicode: true}, 80, 24, nil},
	{"ascii-80", Style{}, 80, 24, nil},
	{"narrow-60", Style{Unicode: true}, 60, 20, nil},
	{"manual-details-100", Style{Unicode: true}, 100, 30, func(v *View) {
		v.Mode = Manual
		v.Cards[0].Details = true
		v.Cards[0].Note = "fix the customer's address"
	}},
	{"secret-prompt-80", Style{Unicode: true}, 80, 24, func(v *View) {
		v.Cards = []Card{{ID: "01M", Instance: "shop", Lock: "locksql", Agent: "dev-1", Profile: "prod", Kind: ticket.KindConnect,
			Production: true, Header: "prod · connect", Body: []string{"endpoint: db.internal:5432/shop", "credentials: ask"},
			Why: "first connection to this profile in this session", Prompt: &Prompt{Label: "password for shop/prod:", Secret: true, Typed: []rune("hunter2")}}}
	}},
	{"idle-80", Style{Unicode: true}, 80, 12, func(v *View) {
		v.Cards, v.Feed, v.Profiles, v.HubOK, v.HubErr = nil, nil, nil, false, "connection refused"
	}},
	{"help-80", Style{Unicode: true}, 80, 24, func(v *View) { v.Overlay = "help" }},
	{"audit-80", Style{Unicode: true}, 80, 24, func(v *View) { v.Overlay, v.Cards = "audit", nil }},
	{"lock-tab-120", Style{Color: true, Unicode: true}, 120, 34, withLockTab(false)},
	{"lock-tab-ascii-80", Style{}, 80, 30, withLockTab(false)},
	{"lock-tab-clear-100", Style{Unicode: true}, 100, 34, withLockTab(true)},
}

// The frame, golden: the layout, the colour code, the question card, on
// dark and light terminals, without colour, at 80 columns and below,
// without Unicode. Run with -update to rewrite.
func TestFrameGolden(t *testing.T) {
	for _, vr := range variants {
		v := sampleView()
		if vr.mod != nil {
			vr.mod(&v)
		}
		lines := Frame(v, vr.w, vr.h, vr.st)
		if len(lines) != vr.h {
			t.Errorf("%s: %d lines, want %d", vr.name, len(lines), vr.h)
		}
		for i, l := range lines {
			if n := strWidth(visible(l)); n > vr.w {
				t.Errorf("%s: line %d is %d columns wide (max %d): %q", vr.name, i, n, vr.w, visible(l))
			}
			if !vr.st.Color && strings.Contains(l, "\x1b") {
				t.Errorf("%s: escape without colour: %q", vr.name, l)
			}
			if !vr.st.Unicode && !isASCII(l) {
				t.Errorf("%s: non-ASCII without Unicode: %q", vr.name, l)
			}
		}
		got := strings.Join(lines, "\n") + "\n"
		path := filepath.Join("testdata", vr.name+".golden")
		if *update {
			os.MkdirAll("testdata", 0o755)
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s (run go test -update): %v", vr.name, err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s (go test ./internal/loxrun -update to accept):\n%s", vr.name, path, visible(got))
		}
	}
}

// Every width from 40 to 200 and short heights: never wider than the
// terminal, never a missing or extra line (a resize never breaks it).
func TestFrameAnySize(t *testing.T) {
	for _, st := range []Style{{Color: true, Unicode: true}, {}} {
		for w := 40; w <= 200; w += 7 {
			for _, h := range []int{6, 9, 15, 40} {
				lines := Frame(sampleView(), w, h, st)
				if len(lines) != h {
					t.Fatalf("%dx%d: %d lines", w, h, len(lines))
				}
				for i, l := range lines {
					if n := strWidth(visible(l)); n > w {
						t.Fatalf("%dx%d line %d: %d columns: %q", w, h, i, n, visible(l))
					}
				}
			}
		}
	}
}

func TestMaskedValuesStandOut(t *testing.T) {
	st := Style{Color: true, Unicode: true}
	l := st.highlight("UPDATE t SET a = j***(20), b = <redacted>, c = <masked bytes:3>, d = <redacted:r1.c2> WHERE id = 7", "")
	got := l.render(true)
	for _, want := range []string{"\x1b[2;3m‹j***(20)›", "\x1b[2;3m‹redacted›", "\x1b[2;3m‹masked bytes:3›", "\x1b[2;3m‹redacted:r1.c2›", "\x1b[1;33mUPDATE"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q not in %q", want, got)
		}
	}
	if p := l.render(false); !strings.Contains(p, "‹j***(20)›") || strings.Contains(p, "\x1b") {
		t.Errorf("plain: %q", p)
	}
}

func TestDetectStyle(t *testing.T) {
	env := func(kv ...string) func(string) (string, bool) {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	cases := []struct {
		name  string
		env   func(string) (string, bool)
		theme string
		want  Style
	}{
		{"default", env("LANG", "en_US.UTF-8"), "", Style{Color: true, Unicode: true}},
		{"NO_COLOR empty", env("NO_COLOR", "", "LANG", "fr_BE.UTF-8"), "", Style{Unicode: true}},
		{"dumb", env("TERM", "dumb"), "", Style{Unicode: true}},
		{"latin1", env("LC_ALL", "fr_BE.ISO-8859-1"), "", Style{Color: true}},
		{"console", env("TERM", "linux"), "", Style{Color: true}},
		{"COLORFGBG light", env("COLORFGBG", "0;15"), "", Style{Color: true, Unicode: true, Light: true}},
		{"COLORFGBG dark", env("COLORFGBG", "15;0"), "", Style{Color: true, Unicode: true}},
		{"theme flag", env("COLORFGBG", "15;0"), "light", Style{Color: true, Unicode: true, Light: true}},
	}
	for _, c := range cases {
		if got := DetectStyle(c.env, c.theme); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestTrunc(t *testing.T) {
	l := line{{"abc", "1"}, {"défgh", "2"}}
	if got := l.trunc(5, "…").text(); got != "abcd…" {
		t.Errorf("trunc 5: %q", got)
	}
	if got := l.trunc(8, "…").text(); got != "abcdéfgh" {
		t.Errorf("trunc 8: %q", got)
	}
	if got := (line{{"日本語", ""}}).trunc(4, "…").text(); got != "日…" {
		t.Errorf("wide: %q", got)
	}
	if got := l.pad(10, "…").width(); got != 10 {
		t.Errorf("pad: %d", got)
	}
}

// The decision column names the rule of each line (#149): auto:read,
// ask:<why>; the entries of lox audit (no tag) fall back on their rule.
func TestStatusCellTag(t *testing.T) {
	st := Style{Unicode: true}
	cases := []struct {
		e    Entry
		want string
	}{
		{Entry{Status: AutoApproved, Rule: "default:read", Tag: "auto:read", Result: ResRan}, "auto:read ✓"},
		{Entry{Status: AutoApproved, Rule: "profile:read-pii"}, "auto:read-pii"},
		{Entry{Status: AutoApproved, Rule: "session:connect"}, "auto:session"},
		{Entry{Status: AutoApproved}, "auto"},
		{Entry{Status: Waiting, Tag: "ask:lock"}, "◆ ask:lock"},
		{Entry{Status: Waiting}, "◆ asked"},
		{Entry{Status: Approved, Tag: "ask:write"}, "✔ you"},
	}
	for _, c := range cases {
		if got := statusCell(c.e, st).text(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.e, got, c.want)
		}
	}
	if got := statusCell(Entry{Status: Waiting, Tag: "ask:lock"}, Style{}).text(); got != "? ask:lock" {
		t.Errorf("ascii: %q", got)
	}
}

// A profile whose lock asks its reads (its auto rule for reads is ask)
// says so in the header's connected line (#149), never implicitly.
func TestHeaderReadsAsked(t *testing.T) {
	v := sampleView()
	v.Profiles[0].ReadsAsked = true
	got := ""
	for _, l := range header(v, 120, Style{Color: true, Unicode: true}) {
		got += l.text() + "\n"
	}
	if !strings.Contains(got, "shop/prod reads asked") {
		t.Errorf("header without the reads asked mark:\n%s", got)
	}
	if strings.Contains(got, "shop/dev reads asked") {
		t.Errorf("header marks shop/dev:\n%s", got)
	}
}
