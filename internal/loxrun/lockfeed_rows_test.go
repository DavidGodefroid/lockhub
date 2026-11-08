package loxrun

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// feedText is every text of f that lox run may show, the statement in
// clear (o) included.
func feedText(f *LockFeed) string {
	var b []string
	for _, it := range f.Items {
		b = append(b, it.Agent, it.Intent, it.Head, it.Class, it.Decision, it.Outcome, it.Code, it.Reason, it.Text)
		b = append(b, it.Statement...)
		b = append(b, it.Reasons...)
		b = append(b, it.Details...)
		b = append(b, it.clear...)
	}
	b = append(b, f.PolicyDiff...)
	b = append(b, f.PolicyNote, f.EndReason, f.StatusRow)
	return strings.Join(b, "\n")
}

// resultTable is a result as locksql's console prints it (showTable):
// its title, then "  " and the aligned cells, each row.
func resultTable(title string, header []string, rows [][]string) []string {
	widths := make([]int, len(header))
	for j, h := range header {
		widths[j] = len([]rune(h))
	}
	for _, r := range rows {
		for j, c := range r {
			widths[j] = max(widths[j], len([]rune(c)))
		}
	}
	pad := func(cells []string) string {
		out := make([]string, len(cells))
		for j, c := range cells {
			out[j] = c + strings.Repeat(" ", widths[j]-len([]rune(c)))
		}
		return strings.TrimRight(strings.Join(out, " │ "), " ")
	}
	ls := []string{title, "  " + pad(header)}
	rules := make([]string, len(widths))
	for j, w := range widths {
		rules[j] = strings.Repeat("─", w)
	}
	ls = append(ls, "  "+strings.Join(rules, "─┼─"))
	for _, r := range rows {
		ls = append(ls, "  "+pad(r))
	}
	return ls
}

const (
	clearTitle    = "result in clear (shown here only; the agent got it masked)"
	unmaskedTitle = "PII: UNMASKED result"
)

// TestLockFeedResultRows: rows of a result printed in clear are never read
// as console lines, whatever their first cell looks like.
func TestLockFeedResultRows(t *testing.T) {
	cases := []struct {
		name string
		rows [][]string
	}{
		{"session ended", [][]string{{"session ended: jane@x.be 0471123456"}}},
		{"done", [][]string{{"done: 3 rows in 4 ms 4111111111111111"}}},
		{"box", [][]string{{"╭─ BE68539007547034"}, {"│ requested by jane@x.be"}, {"╰─ refused: 4111111111111111"}}},
		{"policy diff", [][]string{{"pending policy change for profile x"}, {"  + 4111111111111111"}}},
		{"status", [][]string{{"session  ends in 1 min (max_session 1h0m0s) · idle_timeout 1m0s"}, {"policy change  awaits 4111111111111111"}}},
		{"refused", [][]string{{"refused [E_X]: 4111111111111111"}, {"not submitted: 4111111111111111"}}},
	}
	for _, title := range []string{clearTitle, unmaskedTitle} {
		for _, c := range cases {
			t.Run(title[:6]+"/"+c.name, func(t *testing.T) {
				f := &LockFeed{Instance: "shop"}
				f.take([]string{"▸ Requests are decided on lockhub at https://hub:8443 as shop"}, f0, RefusalLoop)
				f.take(planBox("SELECT email FROM users", "OK"), f0, RefusalLoop)
				f.take([]string{"✓ done: 1 rows in 3 ms"}, f0, RefusalLoop)
				before := len(f.Items)
				f.take(resultTable(title, []string{"email"}, c.rows), f0.Add(time.Second), RefusalLoop)
				all := feedText(f)
				for _, v := range []string{"jane", "0471", "4111", "BE68"} {
					if strings.Contains(all, v) {
						t.Errorf("%q in the feed:\n%s", v, all)
					}
				}
				if len(f.Items) != before || f.Policy != PolicyUnknown || f.Limits.IdleTimeout != 0 || !f.Ended.IsZero() {
					t.Errorf("a result row was read: items %d (was %d), policy %v, limits %+v, ended %v",
						len(f.Items), before, f.Policy, f.Limits, f.Ended)
				}
				// The console's next own line is read again.
				f.take([]string{"✓ session ended: quit"}, f0.Add(2*time.Second), RefusalLoop)
				if f.EndReason != "quit" {
					t.Errorf("end reason %q after the result", f.EndReason)
				}
			})
		}
	}
}

// TestLockFeedIndentedOutsideBlock: an indented line no unindented console
// line opened is left out (a result whose title was not read: before the
// backlog's first line).
func TestLockFeedIndentedOutsideBlock(t *testing.T) {
	f := &LockFeed{Instance: "shop"}
	f.take([]string{
		"  session ended: jane@x.be",
		"  done: 4111111111111111",
		"  ╭─ BE68539007547034",
		"  pending policy change for profile x",
		"  + 4111111111111111",
		"  session  ends in 1 min (max_session 1h0m0s) · idle_timeout 1m0s",
	}, f0, RefusalLoop)
	if len(f.Items) != 0 || f.PolicyDiff != nil || f.Limits.IdleTimeout != 0 || !f.Ended.IsZero() {
		t.Fatalf("indented lines read: %q limits %+v", feedText(f), f.Limits)
	}
}

// TestLockFeedUnknownAndFailures: an unknown line is left out; a failure's
// text and a reason have their digits masked, the row bound too.
func TestLockFeedUnknownAndFailures(t *testing.T) {
	f := &LockFeed{Instance: "shop"}
	f.take(planBox("SELECT 1", "OK", "rows 4111111111111111 seen"), f0, RefusalLoop)
	f.take([]string{
		"jane@x.be 0471123456",
		"✗ failed: Duplicate entry 4111111111111111 for key email",
		"✗ error: value 0471123456 out of range",
	}, f0, RefusalLoop)
	all := feedText(f)
	for _, v := range []string{"jane", "0471", "4111", "100 rows"} {
		if strings.Contains(all, v) {
			t.Errorf("%q in the feed:\n%s", v, all)
		}
	}
	p := f.Items[0]
	if !p.Failed || !strings.HasPrefix(p.Outcome, "failed: Duplicate entry ‹?›") {
		t.Errorf("outcome %q failed %v", p.Outcome, p.Failed)
	}
	if !slices.Contains(p.Details, "returns at most ‹?› rows") {
		t.Errorf("details %q", p.Details)
	}
}

// TestLockFeedNoResultCell is a property: whatever the cells of a result
// the console prints in clear, with whatever lines around it, none shows
// in the feed, nor moves its state.
func TestLockFeedNoResultCell(t *testing.T) {
	heads := []string{"", "session ended: ", "done: 1 rows in 2 ms ", "failed: ", "error: ", "denied: ",
		"╭─ ", "│ ", "╰─ ", "╰─ refused: ", "refused [E_X]: ", "not submitted: ", "pending policy change for profile ",
		"The policy of profile x changed since it was approved:", "policy tightened", "policy change applied",
		"nothing to review", "Requests are decided on lockhub ", "Policy only: ", "+ ", "~ ", "- ", "  + ", "  - ",
		"session  ends in 1 min (max_session 1h0m0s) · idle_timeout 1m0s", "profile  ", "policy change  awaits",
		"session: idle_timeout 1m0s · max_session 1h0m0s", "First start of profile x: review its policy.",
		"result in clear", "PII: UNMASKED result", "✓ ", "▸ ", "│", "requested by ", "agent: ", "class ", "  ", "─┼─"}
	cell := func(r *rand.Rand) string {
		s := heads[r.IntN(len(heads))]
		if r.IntN(3) == 0 {
			s += heads[r.IntN(len(heads))]
		}
		return s + "SECRET" + strings.Repeat("9", r.IntN(3))
	}
	around := [][]string{
		{"▸ Requests are decided on lockhub at https://hub:8443 as shop"},
		planBox("SELECT a FROM t", "OK"),
		{"✓ done: 2 rows in 3 ms"},
		{"pending policy change for profile shop:", "  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)"},
		{"  profile        shop-prod · mysql 10.0.0.5 · tier read · production true"},
		{""},
		{"Apply these changes? [y/N] "},
	}
	r := rand.New(rand.NewPCG(146, 6))
	for n := range 3000 {
		f := &LockFeed{Instance: "shop"}
		var ls []string
		for range r.IntN(4) {
			ls = append(ls, around[r.IntN(len(around))]...)
		}
		f.take(ls, f0, RefusalLoop)
		before := feedText(f)
		state := [3]any{f.Policy, f.Limits, f.Ended}
		cols := 1 + r.IntN(3)
		header := make([]string, cols)
		for j := range header {
			header[j] = []string{"email", "id", "x"}[r.IntN(3)]
		}
		rows := make([][]string, 1+r.IntN(4))
		for i := range rows {
			rows[i] = make([]string, cols)
			for j := range rows[i] {
				rows[i][j] = cell(r)
			}
		}
		title := []string{clearTitle, unmaskedTitle}[r.IntN(2)]
		table := resultTable(title, header, rows)
		if r.IntN(4) == 0 {
			table = table[1+r.IntN(len(table)-1):] // the title not read (backlog cut)
			f = &LockFeed{Instance: "shop"}
			before, state = feedText(f), [3]any{f.Policy, f.Limits, f.Ended}
		}
		f.take(table, f0.Add(time.Second), RefusalLoop)
		if all := feedText(f); strings.Contains(all, "SECRET") {
			t.Fatalf("case %d: a cell shows:\n%s\nfrom:\n%s", n, all, strings.Join(table, "\n"))
		}
		if got := feedText(f); got != before {
			t.Fatalf("case %d: the feed changed:\n%s\nwas:\n%s\nfrom:\n%s", n, got, before, strings.Join(table, "\n"))
		}
		if got := [3]any{f.Policy, f.Limits, f.Ended}; got != state {
			t.Fatalf("case %d: state %v, was %v, from:\n%s", n, got, state, strings.Join(table, "\n"))
		}
	}
}

// FuzzLockFeedResultCell: no cell of a result printed in clear shows in
// the feed, whatever the cell.
func FuzzLockFeedResultCell(f *testing.F) {
	for _, s := range []string{"session ended: x", "╭─ x", "pending policy change for profile x", "done: 1 rows in 2 ms"} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if strings.ContainsAny(a+b, "\n\r") {
			return
		}
		fd := &LockFeed{Instance: "shop"}
		fd.take([]string{"▸ Requests are decided on lockhub at https://hub:8443 as shop", "✓ done: 2 rows in 3 ms"}, f0, RefusalLoop)
		before := feedText(fd)
		fd.take(resultTable(clearTitle, []string{"a", "b"}, [][]string{{a + "SECRET", b}, {b, a + "SECRET"}}), f0, RefusalLoop)
		if got := feedText(fd); got != before {
			t.Fatalf("the feed changed:\n%s\nwas:\n%s", got, before)
		}
	})
}
