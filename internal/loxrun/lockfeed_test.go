package loxrun

import (
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
	} {
		if got := maskLiterals(c.in, true); got != c.want {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}
