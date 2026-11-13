package loxrun

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// SigStatus is what checking an exchange's signatures found: the
// ticket's under the pinned lock key, the decision's under the hub keys.
type SigStatus int

const (
	// SigUnchecked: no key to check with (or nothing signed yet).
	SigUnchecked SigStatus = iota
	// SigOK: every signature there is verifies.
	SigOK
	// SigBad: a signature does not verify (SigNote says which).
	SigBad
)

// Exchange is one ticket of the hub's audit and its answer, as lox audit
// and lox run's audit view show it: only what the hub keeps, masked by
// the lock (its screen), the signed decision's rule and human, and the
// ticket's state. Never a value in clear, a credential or a result row:
// the hub has none of them.
type Exchange struct {
	// Entry is its feed line: At is when it was asked; Rule the auto rule
	// that decided, By the human ("human") when one did.
	Entry
	Risk string
	// State is the ticket's state at the hub (pending, approved,
	// consumed, denied, expired, withdrawn, lock_removed).
	State string
	// Decided is when the decision was signed, Ended when the ticket
	// reached its final state (zero: not yet).
	Decided, Ended time.Time
	// Facade and Approver are who signed a human decision: the facade
	// (tty for lox run, telegram, mobile…) and the human's display name.
	Facade, Approver string
	// Reason is the signed decision's reason (a denial's; a human's
	// withdrawal names the human and where: "withdrawn by …").
	Reason string
	// The lock's masked screen.
	Header                  string
	Body, Warnings, Touched []string
	Sig                     SigStatus
	SigNote                 string
}

// RunEvent is one line of lox run's session journal: a session started
// (by User, in Mode), switched mode, or stopped. It holds no ticket.
type RunEvent struct {
	At        time.Time `json:"at"`
	Event     string    `json:"event"`
	User      string    `json:"user,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Workspace string    `json:"workspace,omitempty"`
	// Instance and Vault (RunVaultToken): the lock a Vault token went to,
	// and how (VaultFromCLI, VaultTyped). Never the token.
	Instance string `json:"instance,omitempty"`
	Vault    string `json:"vault,omitempty"`
}

// Run events.
const (
	RunStart = "start"
	RunMode  = "mode"
	RunStop  = "stop"
	// RunVaultToken: a vault_token: cli lock got a Vault token.
	RunVaultToken = "vault-token"
)

// Decision is how the exchange was decided: auto (a rule approved it),
// human (a human approved it), denied (a human or a rule refused it),
// pending (it waits), none (it ended undecided: expired, withdrawn).
func (x Exchange) Decision() string {
	switch x.Status {
	case AutoApproved:
		return "auto"
	case Approved:
		return "human"
	case Denied:
		return "denied"
	}
	if x.State == "pending" {
		return "pending"
	}
	return "none"
}

// ByHuman reports whether a human (not a rule) decided it.
func (x Exchange) ByHuman() bool {
	return (x.Status == Approved || x.Status == Denied) && x.Rule == ""
}

// Write reports whether it changes data: a write or DDL kind, or a write
// risk (an MQ or file action that writes).
func (x Exchange) Write() bool {
	return x.Kind == ticket.KindWrite || x.Kind == ticket.KindDDL || x.Risk == string(ticket.RiskWrite) || x.Risk == string(ticket.RiskProdWrite)
}

// Connected reports whether it opened a connection (a connect ticket the
// lock consumed).
func (x Exchange) Connected() bool { return x.Kind == ticket.KindConnect && x.Result == ResRan }

// AuditCounts is the summary on top of a listing.
type AuditCounts struct {
	Total, Auto, Human, Denied, Pending, Writes, Connections int
}

// CountAudit counts xs.
func CountAudit(xs []Exchange) AuditCounts {
	var c AuditCounts
	for _, x := range xs {
		c.Total++
		switch x.Decision() {
		case "auto":
			c.Auto++
		case "human":
			c.Human++
		case "denied":
			c.Denied++
		case "pending":
			c.Pending++
		}
		if x.Write() {
			c.Writes++
		}
		if x.Connected() {
			c.Connections++
		}
	}
	return c
}

func summaryLine(c AuditCounts, st Style) line {
	sep := " " + st.g("·", "-") + " "
	l := line{{" ", ""}, {fmt.Sprintf("%d exchange%s", c.Total, plural(c.Total)), sgrBold}}
	part := func(n int, label, sgr string) {
		l = l.add(sep, sgrDim).add(fmt.Sprintf("%d %s", n, label), sgr)
	}
	part(c.Auto, "auto", st.auto())
	part(c.Human, "human", st.approved())
	part(c.Denied, "denied", st.denied())
	if c.Pending > 0 {
		part(c.Pending, "waiting", st.asked())
	}
	part(c.Writes, "write"+plural(c.Writes), st.writeKind())
	part(c.Connections, "connection"+plural(c.Connections)+" opened", st.keyword())
	return l
}

// sepLine is "── text ───…" over w columns.
func sepLine(text, sgr string, w int, st Style) line {
	hz := st.g("─", "-")
	l := line{{" " + hz + hz + " ", sgrDim}, {text, sgr}, {" ", ""}}
	if n := w - l.width(); n > 0 {
		l = l.add(strings.Repeat(hz, n), sgrDim)
	}
	return l
}

func (st Style) modeStyle(mode string) string {
	if mode == Manual.String() {
		return st.asked()
	}
	return st.auto()
}

// auditListing is the listing before drawing: the summary, then the
// exchanges oldest first, with a separator at each new day and the
// lox run sessions (who started one, when, its mode switches) inline.
func auditListing(xs []Exchange, runs []RunEvent, loc *time.Location, w int, st Style) []line {
	w = max(w, 40)
	v := View{Loc: loc}
	c := layout(w)
	out := []line{summaryLine(CountAudit(xs), st), rule(w, st, sgrDim)}
	runs = slices.Clone(runs)
	slices.SortStableFunc(runs, func(a, b RunEvent) int { return a.At.Compare(b.At) })
	day := ""
	newDay := func(t time.Time) {
		if d := t.In(v.loc()).Format("2006-01-02"); d != day {
			day = d
			out = append(out, sepLine(t.In(v.loc()).Format("Monday 2 January 2006"), sgrBold, w, st))
		}
	}
	ri := 0
	flushRuns := func(until time.Time, all bool) {
		for ; ri < len(runs) && (all || !runs[ri].At.After(until)); ri++ {
			newDay(runs[ri].At)
			out = append(out, runLine(runs[ri], v.loc(), w, st))
		}
	}
	if len(xs) == 0 {
		flushRuns(time.Time{}, true)
		return append(out, line{{"   no exchange: every ticket the hub keeps, and its answer, shows here, masked by its lock", sgrDim}})
	}
	for _, x := range xs {
		flushRuns(x.At, false)
		newDay(x.At)
		out = append(out, entryLine(x.Entry, v, c, st))
	}
	flushRuns(time.Time{}, true)
	return out
}

// runLine is a lox run session's start, mode switch or stop as a
// separator line.
func runLine(r RunEvent, loc *time.Location, w int, st Style) line {
	ts := r.At.In(loc).Format("15:04:05")
	lead := line{{" " + st.g("──", "--") + " ", sgrDim}}
	switch r.Event {
	case RunStart:
		who := clean(r.User)
		if who == "" {
			who = "someone"
		}
		l := lead.add("lox run", sgrBold).add(" started by ", sgrDim).add(who, join(st.agentColor(who), sgrBold)).add(" at "+ts+" in ", sgrDim)
		l = l.add(clean(r.Mode), join(st.modeStyle(r.Mode), sgrBold)).add(" ", "")
		if n := w - l.width(); n > 0 {
			l = l.add(strings.Repeat(st.g("─", "-"), n), sgrDim)
		}
		return l
	case RunMode:
		return lead.add("switched to ", sgrDim).add(clean(r.Mode), join(st.modeStyle(r.Mode), sgrBold)).add(" at "+ts+" ", sgrDim).
			add(st.g("──", "--"), sgrDim)
	case RunVaultToken:
		return lead.add("vault token: "+clean(r.Vault), sgrBold).add(" for "+clean(r.Instance)+" at "+ts+" ", sgrDim).
			add(st.g("──", "--"), sgrDim)
	}
	return sepLine("lox run stopped at "+ts+": tickets wait for the next one", sgrDim, w, st)
}

// AuditRunLine is a session event as a listing line (lox audit --follow).
func AuditRunLine(r RunEvent, loc *time.Location, w int, st Style) string {
	if loc == nil {
		loc = time.Local
	}
	return finish(runLine(r, loc, max(w, 40), st), max(w, 40), st)
}

// AuditSummary is the summary line of xs.
func AuditSummary(xs []Exchange, w int, st Style) string {
	return finish(summaryLine(CountAudit(xs), st), max(w, 40), st)
}

// AuditListing draws a listing at w columns (see auditListing): one
// string per line, styled as lox run's feed.
func AuditListing(xs []Exchange, runs []RunEvent, loc *time.Location, w int, st Style) []string {
	return renderAll(auditListing(xs, runs, loc, w, st), w, st)
}

// AuditLine is one exchange as a listing line (lox audit --follow).
func AuditLine(x Exchange, loc *time.Location, w int, st Style) string {
	return finish(entryLine(x.Entry, View{Loc: loc}, layout(max(w, 40)), st), max(w, 40), st)
}

func renderAll(ls []line, w int, st Style) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = finish(l, w, st)
	}
	return out
}

// dur is a short duration with sub-second precision: 340ms, 1.2s, 4m.
func dur(d time.Duration) string {
	switch {
	case d < 0:
		return "0ms"
	case d < time.Second:
		return fmt.Sprintf("%dms", d/time.Millisecond)
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return age(d)
}

// auditDetail is the detail panel before drawing.
func auditDetail(x Exchange, loc *time.Location, w int, st Style) []line {
	w = max(w, 40)
	ell := st.ellipsis()
	fsgr := sgrDim
	if x.Production {
		fsgr = st.prod()
	}
	tl, tr, bl, br, hz, vt := st.g("┌", "+"), st.g("┐", "+"), st.g("└", "+"), st.g("┘", "+"), st.g("─", "-"), st.g("│", "|")
	inner := w - 4
	title := line{{" exchange ", sgrBold}, {x.Instance + "/" + x.ID + " ", ""}}
	if x.Production {
		title = title.add(" PRODUCTION ", join(st.prod(), sgrReverse)).add(" ", "")
	}
	title = title.trunc(w-4, ell)
	top := line{{" " + tl, fsgr}}
	top = append(top, title...)
	if n := w - top.width() - 1; n > 0 {
		top = top.add(strings.Repeat(hz, n), fsgr)
	}
	top = top.add(tr, fsgr)
	row := func(content line) line {
		l := line{{" " + vt + " ", fsgr}}
		l = append(l, content.pad(inner-1, ell)...)
		return l.add(vt, fsgr)
	}
	label := func(s string) line { return line{{s, sgrDim}}.pad(11, "") }
	var rows []line

	agent := x.Agent
	if agent == "" {
		agent = "an agent"
	}
	who := line{{agent, join(st.agentColor(agent), sgrBold)}, {" asked (unverified name)", sgrDim}}
	who = who.add(" "+st.g("·", "-")+" "+st.lockIcon(x.Lock)+" "+x.Lock, sgrDim)
	rows = append(rows, row(who))
	where := append(label("on"), line{{x.Instance, ""}}...)
	if x.Profile != "" {
		psgr := ""
		prof := x.Profile
		if x.Production {
			psgr = st.prod()
			if !st.Color {
				prof += "!"
			}
		}
		where = where.add("/", sgrDim).add(prof, psgr)
	}
	where = where.add("   kind ", sgrDim).add(kindLabel(x.Kind), join(st.kindStyle(x.Kind), sgrBold))
	if x.Risk != "" {
		where = where.add("   risk ", sgrDim).add(x.Risk, "")
	}
	rows = append(rows, row(where), row(nil))

	rows = append(rows, row(line{{"masked plan", sgrBold}, {" (as the lock masked it: the hub never sees it in clear)", sgrDim}}))
	if x.Header != "" {
		rows = append(rows, row(append(line{{"  ", ""}}, st.highlight(x.Header, sgrBold)...)))
	}
	for _, b := range x.Body {
		rows = append(rows, row(append(line{{"  ", ""}}, st.highlight(b, "")...)))
	}
	if x.Header == "" && len(x.Body) == 0 {
		rows = append(rows, row(append(line{{"  ", ""}}, st.highlight(x.Summary, "")...)))
	}
	for _, wn := range x.Warnings {
		rows = append(rows, row(line{{"  ! " + wn, st.denied()}}))
	}
	if len(x.Touched) > 0 {
		rows = append(rows, row(line{{"  personal data touched: " + strings.Join(x.Touched, ", ") + " (masked)", sgrMasked}}))
	}
	rows = append(rows, row(nil))

	dec := append(label("decision"), statusCell(x.Entry, st)...)
	switch {
	case x.Rule != "":
		dec = dec.add("  by the auto rule ", sgrDim).add(x.Rule, sgrBold)
	case x.ByHuman():
		h := x.Approver
		if h == "" {
			h = "a human"
		}
		dec = dec.add("  by ", sgrDim).add(h, sgrBold).add(" on the ", sgrDim).add(x.Facade, sgrBold).add(" facade", sgrDim)
	case x.Status == Waiting && x.State == "pending":
		dec = dec.add("  waiting for an answer", st.asked())
	default:
		dec = dec.add("  never decided", sgrDim)
	}
	rows = append(rows, row(dec))
	if x.Reason != "" {
		rows = append(rows, row(append(label("reason"), line{{x.Reason, ""}}...)))
	}
	if x.Asked != "" && x.Rule == "" {
		rows = append(rows, row(append(label("why asked"), line{{x.Asked, sgrDim}}...)))
	}
	tz := loc
	if tz == nil {
		tz = time.Local
	}
	tm := append(label("timings"), line{{"asked " + x.At.In(tz).Format("2006-01-02 15:04:05.000"), ""}}...)
	if !x.Decided.IsZero() {
		tm = tm.add(" "+st.g("·", "-")+" decided +"+dur(x.Decided.Sub(x.At)), "")
	}
	if !x.Ended.IsZero() && x.State != "pending" && x.State != "approved" {
		from := x.Decided
		if from.IsZero() {
			from = x.At
		}
		tm = tm.add(" "+st.g("·", "-")+" "+x.State+" +"+dur(x.Ended.Sub(from)), "")
	}
	rows = append(rows, row(tm), row(append(label("state"), line{{x.State, ""}}...)))
	// One row per signature checked: the ticket's, the decision's.
	for i, note := range strings.Split(x.SigNote, "; ") {
		sig := label("signature")
		if i > 0 {
			sig = label("")
		}
		switch x.Sig {
		case SigOK:
			sig = sig.add(st.g("✓", "ok")+" ", join(st.approved(), sgrBold)).add(note, "")
		case SigBad:
			sig = sig.add(st.g("✗", "BAD")+" ", join(st.denied(), sgrBold)).add(note, st.denied())
		default:
			sig = sig.add("? ", sgrBold).add(note, sgrDim)
		}
		rows = append(rows, row(sig))
	}
	rows = append(rows, row(line{{"the whole chain, and the lock's own log: lox audit verify", sgrDim}}))
	bottom := line{{" " + bl + strings.Repeat(hz, w-4) + br, fsgr}}
	return append(append([]line{top}, rows...), bottom)
}

// AuditDetail draws the detail panel of one exchange: its masked plan,
// the rule or human that decided, timings and signature status.
func AuditDetail(x Exchange, loc *time.Location, w int, st Style) []string {
	return renderAll(auditDetail(x, loc, w, st), max(w, 40), st)
}

// ExchangeOf is the exchange of a ticket before its decision: its feed
// line and the lock's masked screen, as lox run shows them (made safe
// for a terminal). What became of it (Status, Rule, State…) is the
// caller's to set. The ticket's sealed values and the agent's note are
// left out: only what the lock masked is shown.
func ExchangeOf(tk *ticket.Ticket) Exchange {
	kind := tk.EffectiveKind()
	var subj *ticket.Subject
	if tk.V >= ticket.VersionKinds {
		subj = tk.Subject
	}
	x := Exchange{Entry: Entry{ID: clean(tk.ID), At: tk.Created, Agent: clean(tk.Requester.Agent), Instance: clean(tk.Source.Instance),
		Lock: clean(tk.Source.Lock), Kind: kind, Production: tk.Flags.Production, Summary: summary(tk)},
		Risk: clean(string(tk.Risk)), Header: clean(tk.Screen.Header), Touched: cleanAll(tk.PII.Touched), Warnings: cleanAll(tk.Screen.Warnings)}
	if subj != nil {
		x.Profile, x.Target = clean(subj.Profile), clean(subj.Target)
	}
	for _, b := range tk.Screen.Body {
		if s := clean(b); strings.TrimSpace(s) != "" {
			x.Body = append(x.Body, s)
		}
	}
	return x
}

func cleanAll(ss []string) []string {
	var out []string
	for _, s := range ss {
		out = append(out, clean(s))
	}
	return out
}
