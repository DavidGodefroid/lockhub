package loxrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// sampleAudit is a day and a half of exchanges: a lox run session with a
// mode switch, auto reads, a human-approved write on production, a rule
// denial, a human denial, a ticket that expired undecided, one waiting.
func sampleAudit() ([]Exchange, []RunEvent) {
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	x := func(s int, e Entry, mod func(*Exchange)) Exchange {
		e.At = at(s)
		if e.ID == "" {
			e.ID = "01K" + strings.Repeat("0", 3) + string(rune('A'+s%26))
		}
		ex := Exchange{Entry: e, State: "consumed", Decided: e.At.Add(40 * time.Millisecond), Ended: e.At.Add(900 * time.Millisecond),
			Sig: SigOK, SigNote: "ticket signed by its lock's pinned key; decision signed by the hub key"}
		if mod != nil {
			mod(&ex)
		}
		return ex
	}
	xs := []Exchange{
		x(-86000, Entry{Agent: "dev-2", Instance: "shop", Lock: "locksql", Profile: "dev", Kind: ticket.KindRead,
			Summary: "SELECT count(*) FROM orders", Status: AutoApproved, Rule: "default:read", Result: ResRan}, nil),
		x(12, Entry{Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindConnect,
			Summary: "connect db.internal:5432/shop (credentials: ask)", Status: Approved, By: "human", Result: ResRan},
			func(e *Exchange) {
				e.Facade, e.Approver, e.Risk, e.Decided = "tty", "david", "read", e.At.Add(3200*time.Millisecond)
			}),
		x(14, Entry{Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindRead,
			Summary: "SELECT id, total FROM orders WHERE customer = c***(8)", Target: "orders", Status: AutoApproved, Rule: "default:read", Result: ResRan},
			func(e *Exchange) { e.Risk = "read_pii" }),
		x(61, Entry{Agent: "web-agent", Instance: "mq", Lock: "lockmq", Profile: "local", Kind: ticket.KindAction,
			Summary: "PEEK orders.created (10 messages)", Status: AutoApproved, Rule: "default:action", Result: ResRan}, nil),
		x(150, Entry{Agent: "dev-2", Instance: "shop", Lock: "locksql", Profile: "dev", Kind: ticket.KindDDL,
			Summary: "DROP TABLE sessions", Status: Denied, Rule: "deny:ddl"}, func(e *Exchange) { e.State, e.Ended, e.Risk = "denied", time.Time{}, "write" }),
		x(200, Entry{ID: "01KWRITE", Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindWrite,
			Summary: "UPDATE customers SET email = j***(20) WHERE id = 4***(3)", Target: "customers", Status: Approved, By: "human", Result: ResRan},
			func(e *Exchange) {
				e.Facade, e.Approver, e.Risk = "telegram", "alice", "prod_write"
				e.Decided = e.At.Add(12 * time.Second)
				e.Ended = e.Decided.Add(300 * time.Millisecond)
				e.Header = "shop / prod · write"
				e.Body = []string{"UPDATE customers SET email = j***(20) WHERE id = 4***(3)", "-- 1 row (estimated)"}
				e.Warnings, e.Touched = []string{"production"}, []string{"email"}
			}),
		x(230, Entry{Agent: "web-agent", Instance: "api", Lock: "lockhttp", Profile: "stripe", Kind: ticket.KindEndpoint,
			Summary: "POST api.stripe.com/v1/refunds", Status: Denied}, func(e *Exchange) { e.State, e.Facade, e.Approver, e.Ended = "denied", "tty", "david", time.Time{} }),
		x(260, Entry{Agent: "dev-2", Instance: "shop", Lock: "locksql", Profile: "dev", Kind: ticket.KindWrite,
			Summary: "DELETE FROM carts WHERE created < <redacted>", Status: Undecided, Result: ResExpired},
			func(e *Exchange) {
				e.State, e.Decided, e.Sig, e.SigNote = "expired", time.Time{}, SigUnchecked, "ticket not checked (no pinned key for shop)"
			}),
		x(299, Entry{Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindWrite,
			Summary: "UPDATE orders SET status = <redacted> WHERE id = 4***(3)", Status: Waiting},
			func(e *Exchange) { e.State, e.Decided, e.Ended = "pending", time.Time{}, time.Time{} }),
	}
	runs := []RunEvent{
		{At: at(5), Event: RunStart, User: "david", Mode: "AUTO"},
		{At: at(220), Event: RunMode, Mode: "MANUAL"},
		{At: at(280), Event: RunMode, Mode: "AUTO"},
	}
	return xs, runs
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s (run go test -update): %v", name, err)
	}
	if got != string(want) {
		t.Errorf("%s differs from %s (go test ./internal/loxrun -update to accept):\n%s", name, path, visible(got))
	}
}

func checkLines(t *testing.T, name string, lines []string, w int, st Style) {
	t.Helper()
	for i, l := range lines {
		if n := strWidth(visible(l)); n > w {
			t.Errorf("%s: line %d is %d columns wide (max %d): %q", name, i, n, w, visible(l))
		}
		if !st.Color && strings.Contains(l, "\x1b") {
			t.Errorf("%s: escape without colour: %q", name, l)
		}
		if !st.Unicode && !isASCII(l) {
			t.Errorf("%s: non-ASCII without Unicode: %q", name, l)
		}
	}
}

var auditStyles = []struct {
	name string
	st   Style
	w    int
}{
	{"dark-120", Style{Color: true, Unicode: true}, 120},
	{"light-120", Style{Color: true, Unicode: true, Light: true}, 120},
	{"dark-80", Style{Color: true, Unicode: true}, 80},
	{"nocolor-80", Style{Unicode: true}, 80},
	{"ascii-80", Style{}, 80},
}

// The listing (summary, day separators, session headers and mode
// switches, lox run's columns and colours) and the detail panel, golden,
// in colour on dark and light, with NO_COLOR, at 80 columns, in ASCII.
func TestAuditGolden(t *testing.T) {
	xs, runs := sampleAudit()
	for _, v := range auditStyles {
		ls := AuditListing(xs, runs, time.UTC, v.w, v.st)
		checkLines(t, "audit-list-"+v.name, ls, v.w, v.st)
		golden(t, "audit-list-"+v.name, strings.Join(ls, "\n")+"\n")
		d := AuditDetail(xs[5], time.UTC, v.w, v.st)
		checkLines(t, "audit-detail-"+v.name, d, v.w, v.st)
		golden(t, "audit-detail-"+v.name, strings.Join(d, "\n")+"\n")
	}
	// The summary alone, and the detail of an auto-decided one.
	golden(t, "audit-summary-nocolor-80", AuditSummary(xs, 80, Style{Unicode: true})+"\n"+
		strings.Join(AuditDetail(xs[2], time.UTC, 80, Style{Unicode: true}), "\n")+"\n")
}

func TestAuditListingContent(t *testing.T) {
	xs, runs := sampleAudit()
	got := visible(strings.Join(AuditListing(xs, runs, time.UTC, 120, Style{Unicode: true}), "\n"))
	for _, want := range []string{
		"9 exchanges · 3 auto · 2 human · 2 denied · 1 waiting · 4 writes · 1 connection opened",
		"── Thursday 5 November 2026 ──", "── Friday 6 November 2026 ──",
		"── lox run started by david at 14:02:05 in AUTO ─", "── switched to MANUAL at 14:05:40 ──",
		"✔ human", "✘ rule", "✘ denied", "– none ⌛", "◆ asked", "auto ✓", "‹j***(20)›",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("listing lacks %q:\n%s", want, got)
		}
	}
	// Oldest first: the session header comes before its first exchange.
	if strings.Index(got, "started by david") > strings.Index(got, "connect db.internal") {
		t.Error("session header after its exchanges")
	}
	if strings.Index(got, "Thursday") > strings.Index(got, "count(*)") || strings.Index(got, "Friday") > strings.Index(got, "started by") {
		t.Error("day separators out of place")
	}
	empty := visible(strings.Join(AuditListing(nil, nil, time.UTC, 80, Style{Unicode: true}), "\n"))
	if !strings.Contains(empty, "0 exchanges") || !strings.Contains(empty, "no exchange") {
		t.Errorf("empty listing:\n%s", empty)
	}
}

func TestAuditDetailContent(t *testing.T) {
	xs, _ := sampleAudit()
	st := Style{Unicode: true}
	cases := []struct {
		x    Exchange
		want []string
	}{
		{xs[5], []string{"by alice on the telegram facade", "decided +12.0s", "consumed +300ms", "✓ ticket signed", "‹j***(20)›",
			"personal data touched: email (masked)", "! production", "PRODUCTION", "lox audit verify"}},
		{xs[2], []string{"by the auto rule default:read", "decided +40ms"}},
		{xs[4], []string{"✘ rule", "by the auto rule deny:ddl"}},
		{xs[7], []string{"never decided", "? ticket not checked", "expired +900ms"}},
		{xs[8], []string{"waiting for an answer", "state      pending"}},
	}
	for _, c := range cases {
		got := visible(strings.Join(AuditDetail(c.x, time.UTC, 100, st), "\n"))
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("detail of %s lacks %q:\n%s", c.x.Summary, w, got)
			}
		}
	}
	bad := xs[1]
	bad.Sig, bad.SigNote = SigBad, "the decision does not verify under the hub's pinned keys"
	if got := visible(strings.Join(AuditDetail(bad, time.UTC, 100, st), "\n")); !strings.Contains(got, "✗ the decision does not verify") {
		t.Errorf("bad signature not shown:\n%s", got)
	}
}

func TestAuditCounts(t *testing.T) {
	xs, _ := sampleAudit()
	c := CountAudit(xs)
	want := AuditCounts{Total: 9, Auto: 3, Human: 2, Denied: 2, Pending: 1, Writes: 4, Connections: 1}
	// AutoApproved: 3 (the deny:ddl one is a rule's denial).
	if c != want {
		t.Errorf("counts %+v, want %+v", c, want)
	}
	if xs[4].Decision() != "denied" || xs[4].ByHuman() || xs[6].Decision() != "denied" || !xs[6].ByHuman() ||
		xs[7].Decision() != "none" || xs[8].Decision() != "pending" || xs[1].Decision() != "human" || xs[2].Decision() != "auto" {
		t.Error("decision categories")
	}
}

// lox run's a key shows the hub's audit, its newest lines in the room
// the frame leaves, the summary kept on top.
func TestFrameHubAudit(t *testing.T) {
	xs, runs := sampleAudit()
	v := sampleView()
	v.Cards, v.Overlay, v.Audit = nil, "audit", &auditView{xs: xs, runs: runs}
	lines := Frame(v, 80, 16, Style{Unicode: true})
	got := visible(strings.Join(lines, "\n"))
	if !strings.Contains(got, "the hub's audit") || !strings.Contains(got, "9 exchanges") || !strings.Contains(got, "UPDATE orders SET") {
		t.Errorf("audit overlay:\n%s", got)
	}
	if strings.Contains(got, "count(*)") {
		t.Errorf("oldest line shown in a short frame:\n%s", got)
	}
	golden(t, "audit-hub-80", strings.Join(Frame(v, 80, 24, Style{Unicode: true}), "\n")+"\n")
	v.Audit = &auditView{err: "no such file"}
	if got := visible(strings.Join(Frame(v, 80, 16, Style{Unicode: true}), "\n")); !strings.Contains(got, "cannot read it: no such file") {
		t.Errorf("error not shown:\n%s", got)
	}
}
