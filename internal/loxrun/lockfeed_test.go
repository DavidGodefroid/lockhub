package loxrun

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

var f0 = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// planBox is a locksql plan as its console frames it (lockconsoles hands
// the lines cleaned: no escape sequence).
func planBox(sql, verdict string, reasons ...string) []string {
	ls := []string{
		"",
		"╭─ SHOP-PROD · 10.0.0.5 / appdb · user app_ro · tier read ─────",
		"│ requested by uid 1000",
		"│ agent: Q3: editions of supplier 'ACME' books",
		"│",
		"│   " + sql,
		"│",
		"│ class READ · EXPLAIN: book full ~1 943 473 · est. 1 943 473 rows examined · verdict " + verdict,
	}
	for _, r := range reasons {
		ls = append(ls, "│   - "+r)
	}
	return append(ls,
		"│ reads: appdb.book",
		"│ returns at most 100 rows",
		"│ k-anonymity count (k=5): SELECT COUNT(*) FROM book WHERE isbn = '9782070360024'",
		"│ PII: masked (40 column rules; detectors: card, email, iban, phone)",
		"│ some line a lock adds, with 'a value'",
		"╰─ pending: ticket 01M",
	)
}

func TestLockFeedPlan(t *testing.T) {
	f := &LockFeed{Instance: "shop"}
	sql := "SELECT title FROM book WHERE supplier = 'ACME' AND price > 12.5 LIMIT 100"
	f.take(planBox(sql, "OK", "a policy change in the config files was refused by the human; the last approved policy applies"), f0, RefusalLoop)
	f.take([]string{"✓ done: 93 rows in 3946 ms"}, f0.Add(4*time.Second), RefusalLoop)
	if len(f.Items) != 2 || f.Items[0].Kind != ItemPlan {
		t.Fatalf("items: %+v", f.Items)
	}
	p := f.Items[0]
	if p.Head != "SHOP-PROD · 10.0.0.5 / appdb · user app_ro · tier read" || p.Agent != "uid 1000" {
		t.Errorf("head %q agent %q", p.Head, p.Agent)
	}
	if want := "SELECT title FROM book WHERE supplier = ‹?› AND price > ‹?› LIMIT 100"; !slices.Equal(p.Statement, []string{want}) {
		t.Errorf("statement %q, want %q", p.Statement, want)
	}
	if !slices.Equal(p.clear, []string{sql}) {
		t.Errorf("clear %q", p.clear)
	}
	if p.Intent != "Q3: editions of supplier ‹?› books" {
		t.Errorf("intent %q", p.Intent)
	}
	if !strings.HasPrefix(p.Class, "class READ") || !strings.HasSuffix(p.Class, "verdict OK") {
		t.Errorf("class %q", p.Class)
	}
	if p.Decision != "pending: ticket 01M" || p.Outcome != "done: 93 rows in 3946 ms" || p.Failed {
		t.Errorf("decision %q outcome %q failed %v", p.Decision, p.Outcome, p.Failed)
	}
	all := strings.Join(append(append(p.Details, p.Reasons...), append(p.Statement, p.Intent)...), "\n")
	for _, v := range []string{"ACME", "9782070360024", "12.5", "a value"} {
		if strings.Contains(all, v) {
			t.Errorf("%q in clear in the feed:\n%s", v, all)
		}
	}
	if f.Policy != PolicyRefused {
		t.Errorf("policy %v, want refused (from the plan's reason)", f.Policy)
	}
	if f.Items[1].Kind != ItemPolicy {
		t.Errorf("no policy line: %+v", f.Items[1])
	}
}

// Identical refusals from one agent fold into one line with a counter;
// the loop count raises one alert; another refusal starts a new line.
func TestLockFeedRefusalCollapse(t *testing.T) {
	f := &LockFeed{Instance: "shop"}
	f.take(planBox("SELECT * FROM book", "REFUSE"), f0, RefusalLoop)
	cost := "✗ refused [E_COST]: weight check: estimated rows examined 1 943 473 > 200 000; full scan of book (~1 943 473 rows) > 200 000"
	var alerts []*LockItem
	for i := range 11 {
		alerts = append(alerts, f.take([]string{cost}, f0.Add(time.Duration(i)*time.Second), RefusalLoop)...)
	}
	var refusals []*LockItem
	for _, it := range f.Items {
		if it.Kind == ItemRefusal {
			refusals = append(refusals, it)
		}
	}
	if len(refusals) != 1 || refusals[0].Count != 11 || refusals[0].Code != "E_COST" || refusals[0].Agent != "uid 1000" {
		t.Fatalf("refusals: %+v", refusals)
	}
	if !strings.HasPrefix(refusals[0].Reason, "weight check: estimated rows examined 1 943 473 > 200 000") {
		t.Errorf("reason %q", refusals[0].Reason)
	}
	if len(alerts) != 1 || alerts[0] != refusals[0] {
		t.Errorf("alerts: %d, want one at the %dth", len(alerts), RefusalLoop)
	}
	if got := f.Attention(RefusalLoop); got != "refusal loop" {
		t.Errorf("attention %q", got)
	}
	f.take([]string{"✗ refused [E_CONSTRUCT]: INTO OUTFILE is refused"}, f0.Add(time.Minute), RefusalLoop)
	f.take([]string{cost}, f0.Add(2*time.Minute), RefusalLoop)
	n := 0
	for _, it := range f.Items {
		if it.Kind == ItemRefusal {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d refusal lines after another refusal in between, want 3", n)
	}
}

func TestLockFeedThrottled(t *testing.T) {
	f := &LockFeed{}
	f.take(planBox("SELECT 1", "OK"), f0, RefusalLoop)
	f.take([]string{"✗ not submitted: hubclient: too many tickets: 20 tickets already pending (limit 20, raised by limits.max_pending); retry once one is decided"}, f0, RefusalLoop)
	it := f.Items[len(f.Items)-1]
	if it.Kind != ItemRefusal || it.Code != "THROTTLED" || !strings.HasPrefix(it.Reason, "too many tickets: 20 tickets already pending") {
		t.Errorf("throttled: %+v", it)
	}
	if !f.Items[0].Failed {
		t.Errorf("the plan is not marked as not submitted: %+v", f.Items[0])
	}
}

func TestLockFeedPolicy(t *testing.T) {
	f := &LockFeed{}
	// At start: the files loosen the approved policy, the human refused.
	f.take([]string{
		"The policy of profile shop-prod changed since it was approved:",
		"  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)",
		"Apply these changes? [y/N] ",
		"changes refused: the last approved policy applies",
	}, f0, RefusalLoop)
	if f.Policy != PolicyRefused || !slices.Equal(f.PolicyDiff, []string{"~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)"}) {
		t.Fatalf("policy %v diff %q", f.Policy, f.PolicyDiff)
	}
	if f.Attention(RefusalLoop) != "policy refused" {
		t.Errorf("attention %q", f.Attention(RefusalLoop))
	}
	f.take([]string{"nothing to review"}, f0, RefusalLoop)
	if !strings.Contains(f.PolicyNote, "once the config files change") {
		t.Errorf("note %q", f.PolicyNote)
	}
	// The files change again: pending, reviewed, applied.
	f.take([]string{"pending policy change (loosening) — type :review to see it"}, f0, RefusalLoop)
	if f.Policy != PolicyPending {
		t.Fatalf("policy %v, want pending", f.Policy)
	}
	f.take([]string{
		"pending policy change for profile shop-prod:",
		"  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)",
	}, f0, RefusalLoop)
	if len(f.PolicyDiff) != 1 {
		t.Errorf("diff %q", f.PolicyDiff)
	}
	f.take([]string{"policy change applied"}, f0, RefusalLoop)
	if f.Policy != PolicyApproved || f.Attention(RefusalLoop) != "" {
		t.Errorf("policy %v attention %q", f.Policy, f.Attention(RefusalLoop))
	}
	f.status("SHOP-PROD tier read · results masked ^O · policy change pending :review", f0)
	if f.Policy != PolicyPending {
		t.Errorf("status row: policy %v", f.Policy)
	}
}

func TestLockFeedSession(t *testing.T) {
	f := &LockFeed{}
	f.take([]string{
		"▸ Requests are decided on lockhub at https://hub:8443 as shop",
		"  profile        shop-prod · mysql 10.0.0.5 · tier read · production true",
		"  session        ends in 52 min (max_session 1h0m0s) · idle_timeout 10m0s",
		"  policy change  none",
	}, f0, RefusalLoop)
	if f.Limits.IdleTimeout != 10*time.Minute || f.Limits.MaxSession != time.Hour || f.Limits.EndsIn != 52*time.Minute {
		t.Fatalf("limits %+v", f.Limits)
	}
	if f.Started != f0 || f.Policy != PolicyApproved {
		t.Errorf("started %v policy %v", f.Started, f.Policy)
	}
	f.take(planBox("SELECT 1", "OK"), f0.Add(time.Minute), RefusalLoop)
	now := f0.Add(4 * time.Minute)
	if got := f.IdleFor(now); got != 3*time.Minute {
		t.Errorf("idle %v", got)
	}
	if left, ok := f.SessionLeft(now); !ok || left != 48*time.Minute {
		t.Errorf("session left %v %v", left, ok)
	}
	f.take([]string{"▸ session ended: idle timeout"}, now, RefusalLoop)
	if f.EndReason != "idle timeout" || f.Ended != now {
		t.Errorf("ended %v %q", f.Ended, f.EndReason)
	}
}

func TestMaskLiterals(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"SELECT a FROM t WHERE b = 'x''y' AND c = 42 LIMIT 10 OFFSET 5", "SELECT a FROM t WHERE b = ‹?› AND c = ‹?› LIMIT 10 OFFSET 5"},
		{`WHERE email = "a@b.c"`, `WHERE email = ‹?›`},
		{"SELECT col1, t2.x FROM t2", "SELECT col1, t2.x FROM t2"},
		// A backslash escapes under MySQL, not under PostgreSQL or SQLite:
		// both readings are masked, so all from the quote on.
		{"WHERE a = 'it\\'s SECRET' AND b = 1", "WHERE a = ‹?›"},
		{`WHERE a = 'x\' AND b = 'SECRET'`, "WHERE a = ‹?›"},
		{`WHERE a = "a\" , "SECRET"`, "WHERE a = ‹?›"},
		{"SELECT `it's` FROM t WHERE x='SECRET'", "SELECT `it‹?›"},
		{"SELECT [it's] FROM t WHERE x='SECRET'", "SELECT [it‹?›"},
		{"SELECT `a` FROM t WHERE x = 'SECRET' AND [b] = 1", "SELECT `a` FROM t WHERE x = ‹?› AND [b] = ‹?›"},
		{"WHERE a = $é$ SECRET $é$ AND b = 1", "WHERE a = ‹?› AND b = ‹?›"},
		{"SELECT /* a /* b */ SECRET */ a FROM t", "SELECT ‹?› a FROM t"},
		{"WHERE a = $1 AND b = $2", "WHERE a = $‹?› AND b = $‹?›"},
		{"WHERE a = $$SECRET$$ AND b = $tag$x$$SECRET$tag$ LIMIT 5", "WHERE a = ‹?› AND b = ‹?› LIMIT 5"},
		{"SELECT a -- SECRET\nFROM t", "SELECT a ‹?›\nFROM t"},
		{"SELECT a # SECRET\nFROM t", "SELECT a ‹?›\nFROM t"},
		{"SELECT /* SECRET\n SECRET */ a FROM t", "SELECT ‹?› a FROM t"},
		{"WHERE a = 'line one SECRET\nSECRET end' LIMIT\n10", "WHERE a = ‹?› LIMIT\n10"},
		{"WHERE a = 'open SECRET\nSECRET", "WHERE a = ‹?›"},
		{"WHERE a = $q$open SECRET", "WHERE a = ‹?›"},
		{"SELECT a /* open SECRET", "SELECT a ‹?›"},
		{"SELECT `col` FROM t WHERE x = $1", "SELECT `col` FROM t WHERE x = $‹?›"},
	} {
		if got := maskLiterals(c.in, true); got != c.want {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

// A random statement of a dialect, with a SECRET in each of its literals
// and comments: no SECRET shows once masked.
func TestMaskLiteralsProperty(t *testing.T) {
	for seed := range int64(20000) {
		checkMasked(t, seed)
	}
}

// A 200-line statement, masked anew as each of its lines comes in.
func BenchmarkMaskLongStatement(b *testing.B) {
	line := "AND t.x = 'it''s' /* c */ AND y IN (\"a\", `b`, [c], $1) -- d"
	for b.Loop() {
		var clear []string
		for range 200 {
			clear = append(clear, line)
			maskLiterals(strings.Join(clear, "\n"), true)
		}
	}
}

func FuzzMaskLiterals(f *testing.F) {
	for seed := range int64(64) {
		f.Add(seed)
	}
	f.Fuzz(checkMasked)
}

func checkMasked(t *testing.T, seed int64) {
	d := sqlDialects[uint64(seed)%uint64(len(sqlDialects))]
	stmt := d.statement(rand.New(rand.NewPCG(uint64(seed), 1)))
	if got := maskLiterals(stmt, true); strings.Contains(got, "SECRET") {
		t.Fatalf("seed %d, %s: %q masked to %q", seed, d.name, stmt, got)
	}
}

// sqlDialect is how a database lexes literals, comments and quoted
// identifiers: statement writes a random statement it reads that way.
type sqlDialect struct {
	name                    string
	sqBackslash, eStrings   bool // \ escapes in '…'; E'…' strings (\ escapes)
	dq                      byte // '"' : "…" is a string; 'i': an identifier
	dqBackslash             bool
	backtick, bracket, hash bool
	dashSpace, nest, dollar bool
}

var sqlDialects = []sqlDialect{
	{name: "postgres", eStrings: true, dq: 'i', nest: true, dollar: true},
	{name: "mysql", sqBackslash: true, dq: '"', dqBackslash: true, backtick: true, hash: true, dashSpace: true},
	{name: "mysql ansi", sqBackslash: true, dq: 'i', backtick: true, hash: true, dashSpace: true},
	{name: "mysql no backslash", dq: '"', backtick: true, hash: true, dashSpace: true},
	{name: "sqlite", dq: 'i', backtick: true, bracket: true},
}

// tricky are the bytes that open or close something in some dialect.
var tricky = []string{"'", `"`, "`", "[", "]", `\`, "$", "$$", "$é$", "/*", "*/", "--", "#", "\n", " ", "é", "x", "1", "E"}

func (d sqlDialect) statement(r *rand.Rand) string {
	var b strings.Builder
	for range 1 + r.IntN(8) {
		b.WriteString(d.token(r))
		b.WriteByte(' ')
	}
	return b.String()
}

// body is random content holding a SECRET, none of whose bytes is in
// banned; closing ends it but for a byte doubled or escaped by the caller.
func body(r *rand.Rand, ok func(string) bool) string {
	var b strings.Builder
	n := 1 + r.IntN(6)
	at := r.IntN(n)
	for i := range n {
		if i == at {
			b.WriteString("SECRET")
		}
		if p := tricky[r.IntN(len(tricky))]; ok(b.String() + p) {
			b.WriteString(p)
		}
	}
	return b.String()
}

func quoted(r *rand.Rand, q string, backslash bool) string {
	s := body(r, func(string) bool { return true })
	esc := strings.ReplaceAll(s, q, q+q)
	if backslash {
		esc = strings.ReplaceAll(s, `\`, `\\`)
		esc = strings.ReplaceAll(esc, q, `\`+q)
		if r.IntN(2) == 0 {
			esc = strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), q, q+q)
		}
	}
	return q + esc + q
}

func (d sqlDialect) token(r *rand.Rand) string {
	for {
		switch r.IntN(12) {
		case 0, 1:
			return []string{"SELECT", "a", "t.x", "=", ",", "(", ")", "1", "é", "AND"}[r.IntN(10)]
		case 2:
			return quoted(r, "'", d.sqBackslash)
		case 3:
			if d.eStrings {
				return "E" + quoted(r, "'", true)
			}
		case 4:
			if d.dq == '"' {
				return quoted(r, `"`, d.dqBackslash)
			}
			// A quoted identifier: masked all the same.
			return quoted(r, `"`, false)
		case 5:
			if d.backtick {
				s := body(r, func(string) bool { return true })
				return "`" + strings.ReplaceAll(strings.ReplaceAll(s, "SECRET", "ident"), "`", "``") + "`"
			}
		case 6:
			if d.bracket {
				s := body(r, func(s string) bool { return !strings.Contains(s, "]") })
				return "[" + strings.ReplaceAll(s, "SECRET", "ident") + "]"
			}
		case 7:
			s := body(r, func(s string) bool { return !strings.Contains(s, "\n") })
			return "-- " + s + "\n"
		case 8:
			if d.hash {
				s := body(r, func(s string) bool { return !strings.Contains(s, "\n") })
				return "#" + s + "\n"
			}
		case 9:
			if d.nest {
				s := body(r, func(s string) bool {
					return !strings.Contains(s, "/*") && !strings.Contains(s, "*/") && !strings.HasSuffix(s, "/") && !strings.HasSuffix(s, "*")
				})
				return "/* /* " + s + " */ SECRET */"
			}
			s := body(r, func(s string) bool { return !strings.Contains(s, "*/") && !strings.HasSuffix(s, "*") })
			return "/*" + s + "*/"
		case 10:
			if d.dollar {
				tag := []string{"", "q", "é", "tag_1"}[r.IntN(4)]
				s := body(r, func(s string) bool { return !strings.Contains(s, "$"+tag+"$") && !strings.HasSuffix(s, "$") })
				return "$" + tag + "$" + s + "$" + tag + "$"
			}
		case 11:
			if d.dollar {
				return "$1"
			}
		}
	}
}

// A statement the console prints over several lines is masked as a
// whole: a literal spanning lines and a comment never show in clear.
func TestLockFeedMultiLineStatement(t *testing.T) {
	f := &LockFeed{Instance: "shop"}
	box := planBox("SELECT title FROM book -- SECRETD", "OK")
	i := slices.Index(box, "│   SELECT title FROM book -- SECRETD")
	box = slices.Insert(box, i+1,
		"│   WHERE note = 'line one SECRETA",
		"│   SECRETB end' /* SECRETC",
		"│   SECRETE */ AND id = 'open SECRETF",
		"│   SECRETG")
	f.take(box, f0, RefusalLoop)
	p := f.Items[0]
	all := strings.Join(p.Statement, "\n")
	for _, v := range []string{"SECRETA", "SECRETB", "SECRETC", "SECRETD", "SECRETE", "SECRETF", "SECRETG"} {
		if strings.Contains(all, v) {
			t.Errorf("%q in clear in the statement:\n%s", v, all)
		}
	}
	if !strings.HasPrefix(all, "SELECT title FROM book ‹?›\nWHERE note = ‹?›") {
		t.Errorf("statement:\n%s", all)
	}
	if len(p.clear) != 5 || !strings.Contains(strings.Join(p.clear, "\n"), "SECRETA") {
		t.Errorf("clear %q", p.clear)
	}
}

// A loop of a refusal alerts again once a plan went through and the
// agent loops on it anew.
func TestLockFeedLoopAlertsAgain(t *testing.T) {
	f := &LockFeed{Instance: "shop"}
	f.take(planBox("SELECT * FROM book", "REFUSE"), f0, RefusalLoop)
	cost := "✗ refused [E_COST]: weight check"
	loop := func(from time.Duration) (alerts int) {
		for i := range RefusalLoop {
			alerts += len(f.take([]string{cost}, f0.Add(from+time.Duration(i)*time.Second), RefusalLoop))
		}
		return alerts
	}
	if n := loop(0); n != 1 {
		t.Fatalf("first loop: %d alerts", n)
	}
	f.take(planBox("SELECT 1", "OK"), f0.Add(time.Minute), RefusalLoop)
	f.take([]string{"✓ done: 1 rows in 3 ms"}, f0.Add(time.Minute), RefusalLoop)
	if n := loop(2 * time.Minute); n != 1 {
		t.Errorf("second loop after a plan went through: %d alerts, want 1", n)
	}
}
