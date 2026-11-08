package loxrun

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// Status is where a ticket stands in the feed.
type Status int

const (
	// Waiting: asked, the human has not answered.
	Waiting Status = iota
	// AutoApproved: a rule approved it.
	AutoApproved
	// Approved: the human approved it.
	Approved
	// Denied: the human or a deny rule refused it.
	Denied
	// Failed: lox run could not get it decided (the error is in Note).
	Failed
	// Elsewhere: another facade decided it, or it left the queue before
	// lox run decided it.
	Elsewhere
	// Undecided: it ended with no decision (lox audit: expired,
	// withdrawn, or its lock removed while it waited).
	Undecided
)

// Result is what became of a decided ticket, as the hub knows it (never
// a value: only its state).
type Result string

// Results.
const (
	ResNone      Result = ""
	ResRan       Result = "consumed"
	ResExpired   Result = "expired"
	ResWithdrawn Result = "withdrawn"
	ResRemoved   Result = "lock_removed"
)

// Entry is one line of the feed: one ticket, or a run of equal auto reads
// (Count > 1).
type Entry struct {
	ID         string
	At         time.Time
	Agent      string
	Instance   string
	Lock       string
	Profile    string
	Kind       ticket.Kind
	Production bool
	// Summary is the lock's masked request, one line.
	Summary string
	// Target is the subject's target (a table, a queue), for grouping.
	Target string
	Status Status
	// Rule is the rule that decided (auto), "" for the human.
	Rule string
	// Tag is the engine's verdict in a word (auto:read, ask:lock), for
	// the decision column of an auto decision or a question.
	Tag string
	// Asked is why the human was asked (the auto mode's reason), on a
	// question and the human's decision on it.
	Asked  string
	Result Result
	Count  int
	Note   string
	// By, when set, names the human who decided in the decision column
	// (lox audit: decisions of any facade, not only this terminal's).
	By string
}

// group is the key that folds equal auto reads into one line.
func (e Entry) group() string {
	if e.Status == Failed && e.Summary == unreadableSummary {
		// Tickets that fail verification the same way (#147).
		return strings.Join([]string{"unreadable", e.Instance, e.Note}, "\x00")
	}
	if e.Status != AutoApproved || (e.Kind != ticket.KindRead && e.Kind != ticket.KindAction) {
		return ""
	}
	return strings.Join([]string{e.Agent, e.Instance, e.Profile, string(e.Kind), firstWord(e.Summary), e.Target}, "\x00")
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t("); i > 0 {
		s = s[:i]
	}
	return strings.ToUpper(s)
}

// Card is a question waiting for the human: what, who, which profile,
// the lock's masked screen, and the answer being typed when it needs one
// (a production name, a secret).
type Card struct {
	ID, Instance, Lock, Agent, Profile string
	Kind                               ticket.Kind
	Risk                               string
	Production                         bool
	Workspace                          string
	Header, Note                       string
	Body, Warnings, Touched            []string
	// Why is why it is asked (the engine's word).
	Why     string
	Expires time.Time
	// Prompt, when set, is the line the human types into: Secret hides
	// what is typed (only its length shows as dots, never the text).
	Prompt *Prompt
	// Details shows the whole screen.
	Details bool
	// Unverified: lox run could not check the ticket under the pinned
	// lock key (shown on the card).
	Unverified bool
	// Console: a question of the lock's console at its terminal, not a
	// ticket (Header is its prompt, Body the lines above it).
	Console bool
}

// Prompt is a line typed on a card.
type Prompt struct {
	Label string
	// Default: Enter alone keeps the session's secret.
	Default bool
	Secret  bool
	Typed   []rune
	Error   string
}

// ProfileConn is a profile whose connection the session approved.
type ProfileConn struct {
	Name       string // instance/profile
	Since      time.Time
	Production bool
	// ReadsAsked: its lock asks its reads (never-auto: its profile's auto
	// rule for reads is not auto), shown next to it.
	ReadsAsked bool
}

// View is everything one frame shows.
type View struct {
	Workspace string
	Mode      Mode
	HubOK     bool
	HubErr    string
	Locks     int
	Profiles  []ProfileConn
	Cards     []Card
	Feed      []Entry
	// Overlay is "help", "audit" (the session's decisions) or
	// "withdraw" (the hub's pending tickets), "" none.
	Overlay string
	// Flash is a short message on the footer line.
	Flash string
	Now   time.Time
	Loc   *time.Location
	// Quitting: q pressed once, q again quits.
	Quitting bool
	// Audit is the hub's audit when the audit overlay shows it (nil: the
	// overlay shows this session's decisions).
	Audit *auditView
	// Consoles are the locks' consoles as lox run reaches them (none: it
	// does not, and the header shows no lock line).
	Consoles []LockConsole
	// Sound is the session's sound state in the header (SoundNone: not shown).
	Sound SoundState
	// Withdraw is the w overlay (the hub's pending tickets), when open.
	Withdraw *WithdrawView
}

// SoundState is whether a question plays a sound.
type SoundState int

// Sound states.
const (
	SoundNone SoundState = iota
	SoundOn
	SoundOff
)

// auditView is the hub's audit as lox run last read it.
type auditView struct {
	xs   []Exchange
	runs []RunEvent
	err  string
}

func (v View) loc() *time.Location {
	if v.Loc == nil {
		return time.Local
	}
	return v.Loc
}

// columns of the feed for a width.
type columns struct {
	time, agent, lock, profile, kind, decision, request int
}

func layout(w int) columns {
	c := columns{time: 8, agent: 8, lock: 10, profile: 8, kind: 6, decision: 14}
	switch {
	case w >= 140:
		c.agent, c.lock, c.profile = 14, 16, 12
	case w >= 110:
		c.agent, c.lock, c.profile = 12, 14, 10
	case w < 64:
		c.time, c.agent, c.decision = 5, 0, 10
	}
	fixed := 1 + c.time + 1 + c.lock + 1 + c.profile + 1 + c.kind + 1 + 1 + c.decision
	if c.agent > 0 {
		fixed += c.agent + 1
	}
	c.request = max(w-fixed, 8)
	return c
}

// frameLines is Frame before drawing.
func frameLines(v View, w, h int, st Style) []line {
	w, h = max(w, 40), max(h, 6)
	head := header(v, w, st)
	foot := footer(v, w, st)
	var cards []line
	if len(v.Cards) > 0 {
		cards = card(v, v.Cards[0], len(v.Cards), w, st)
	}
	room := h - len(head) - len(foot) - len(cards)
	if room < 1 && len(cards) > 0 {
		// A short terminal: the question first, cut from the bottom.
		cards = cards[:max(len(cards)+room-1, 1)]
		room = 1
	}
	var body []line
	switch v.Overlay {
	case "help", "audit", overlayWithdraw:
		// An overlay reads from its top; the feed from its newest line.
		switch {
		case v.Overlay == "help":
			body = helpLines(w, st)
		case v.Overlay == overlayWithdraw && v.Withdraw != nil:
			body = withdrawLines(v, w, room, st)
		case v.Audit != nil:
			body = hubAuditLines(v, w, room, st)
		default:
			body = auditLines(v, w, st)
		}
		if len(body) > room {
			body = body[:room]
		}
		for len(body) < room {
			body = append(body, nil)
		}
	default:
		body = feedLines(v, w, st)
		if len(body) > room {
			body = body[len(body)-room:]
		}
		for len(body) < room {
			body = append([]line{nil}, body...)
		}
	}
	all := append(append(append(head, cards...), body...), foot...)
	all = all[:min(len(all), h)]
	for i, l := range all {
		all[i] = fit(l, w, st)
	}
	return all
}

// Frame draws v at w×h: header, question cards, the feed, footer. Every
// line is at most w columns; there are exactly h lines (h >= 6).
func Frame(v View, w, h int, st Style) []string {
	ls := frameLines(v, w, h, st)
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.render(st.Color)
	}
	return out
}

// fit cuts l to w and keeps it to ASCII without Unicode.
func fit(l line, w int, st Style) line {
	l = l.trunc(w, st.ellipsis())
	if !st.Unicode {
		l = slices.Clone(l)
		for i := range l {
			l[i].s = asciiOnly(l[i].s)
		}
	}
	return l
}

// finish cuts l to w and draws it.
func finish(l line, w int, st Style) string { return fit(l, w, st).render(st.Color) }

func rule(w int, st Style, sgr string) line {
	return line{{strings.Repeat(st.g("─", "-"), w), sgr}}
}

func header(v View, w int, st Style) []line {
	var l line
	l = l.add(" lox run ", sgrBold)
	badge := " " + v.Mode.String() + " "
	if st.Color {
		l = l.add(badge, st.badge(v.Mode))
	} else {
		l = l.add("["+v.Mode.String()+"]", sgrBold)
	}
	right := line{}
	if v.HubOK {
		right = right.add(st.g("●", "*")+" hub up", st.approved())
	} else {
		msg := "hub unreachable"
		if v.HubErr != "" {
			msg += " (" + v.HubErr + ")"
		}
		right = right.add(st.g("○", "o")+" "+msg, st.errored())
	}
	if v.Locks > 0 {
		right = right.add(fmt.Sprintf(" %s %d lock%s", st.g("·", "-"), v.Locks, plural(v.Locks)), sgrDim)
	}
	if n := len(v.Cards); n > 0 {
		right = right.add(fmt.Sprintf(" %s ", st.g("·", "-")), sgrDim).add(fmt.Sprintf("%d waiting", n), st.asked())
	}
	switch v.Sound {
	case SoundOn:
		right = right.add(" "+st.g("·", "-")+" "+st.g("🔔", "sound on"), sgrDim)
	case SoundOff:
		right = right.add(" "+st.g("·", "-")+" "+st.g("🔕", "sound off"), sgrDim)
	}
	ws := line{{"  " + v.Workspace, sgrDim}}
	gap := w - l.width() - right.width() - 1
	if gap < 4 {
		ws = nil
		gap = w - l.width() - right.width() - 1
	}
	ws = ws.trunc(max(gap-1, 0), st.ellipsis())
	l = append(l, ws...)
	if n := w - l.width() - right.width() - 1; n > 0 {
		l = l.add(strings.Repeat(" ", n), "")
	}
	l = append(l, right...)

	conn := line{{" connected ", sgrDim}}
	if len(v.Profiles) == 0 {
		conn = conn.add("none yet: a lock connects on its agent's first request", sgrDim)
	}
	for i, p := range v.Profiles {
		if i > 0 {
			conn = conn.add(" "+st.g("·", "-")+" ", sgrDim)
		}
		sgr := ""
		name := p.Name
		if p.Production {
			sgr = st.prod()
			if !st.Color {
				name += "!"
			}
		}
		conn = conn.add(name, sgr)
		if p.ReadsAsked {
			conn = conn.add(" reads asked", st.asked())
		}
		conn = conn.add(" "+age(v.Now.Sub(p.Since)), sgrDim)
	}
	out := []line{l, conn.trunc(w, st.ellipsis())}
	if len(v.Consoles) > 0 {
		out = append(out, consolesLine(v, st).trunc(w, st.ellipsis()))
	}
	return append(out, rule(w, st, sgrDim))
}

// consolesLine is the header's line of the locks' consoles: each one's
// state, the question it waits for first (they are the ones to see).
func consolesLine(v View, st Style) line {
	cs := slices.Clone(v.Consoles)
	rank := func(s ConsoleState) int {
		switch s {
		case ConsoleWaiting:
			return 0
		case ConsoleStopped, ConsoleUnreachable:
			return 1
		}
		return 2
	}
	slices.SortStableFunc(cs, func(a, b LockConsole) int { return rank(a.State) - rank(b.State) })
	l := line{{" locks ", sgrDim}}
	for i, c := range cs {
		if i > 0 {
			l = l.add(" "+st.g("·", "-")+" ", sgrDim)
		}
		l = l.add(st.lockIcon(c.Lock)+" "+c.Instance+" ", "")
		switch c.State {
		case ConsoleWaiting:
			l = l.add("waiting for you: "+c.Question, join(st.asked(), sgrBold))
		case ConsoleStopped:
			msg := "stopped"
			if c.Err != "" {
				msg += ": " + c.Err
			}
			l = l.add(msg, st.errored())
		case ConsoleUnreachable:
			msg := "not reached here"
			if c.Err != "" {
				msg += " (" + c.Err + ")"
			}
			l = l.add(msg+": lox attach "+c.Instance, st.errored())
		case ConsoleServing:
			l = l.add("serving", st.approved())
		default:
			l = l.add(string(c.State), sgrDim)
		}
	}
	return l
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// age is a short duration: 12s, 4m, 2h05m.
func age(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	}
	return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
}

func footer(v View, w int, st Style) []line {
	l := line{{" ", ""}}
	if v.Flash != "" {
		return []line{rule(w, st, sgrDim), l.add(v.Flash, sgrBold)}
	}
	if v.Quitting {
		return []line{rule(w, st, sgrDim), l.add("press q again to quit: decisions stop, tickets wait for the next lox run", st.asked())}
	}
	keys := [][2]string{{"Shift+Tab", "mode"}, {"y/n", "answer"}, {"d", "details"}, {"a", "audit"}, {"?", "help"}, {"q", "quit"}}
	if len(v.Cards) == 0 {
		keys = append(keys[:1], keys[3:]...)
	}
	for i, k := range keys {
		if i > 0 {
			l = l.add("  ", "")
		}
		l = l.add(k[0], sgrBold).add(" "+k[1], sgrDim)
	}
	return []line{rule(w, st, sgrDim), l}
}

// statusCell is the decision column of an entry.
func statusCell(e Entry, st Style) line {
	var label, sgr string
	switch e.Status {
	case Waiting:
		label, sgr = st.g("◆ asked", "? asked"), st.asked()
		if e.Tag != "" {
			label = st.g("◆ ", "? ") + e.Tag
		}
	case AutoApproved:
		label, sgr = autoTag(e), st.auto()
	case Approved:
		label, sgr = st.g("✔ you", "+ you"), st.approved()
		if e.By != "" {
			label = st.g("✔ ", "+ ") + e.By
		}
	case Denied:
		label, sgr = st.g("✘ denied", "x denied"), st.denied()
		if e.Rule != "" {
			label = st.g("✘ rule", "x rule")
		}
	case Failed:
		label, sgr = "! error", st.errored()
	case Elsewhere:
		label, sgr = "elsewhere", sgrDim
	case Undecided:
		label, sgr = st.g("– none", "- none"), sgrDim
	}
	l := line{{label, sgr}}
	switch e.Result {
	case ResRan:
		l = l.add(" "+st.g("✓", "ok"), st.approved())
	case ResExpired:
		l = l.add(" "+st.g("⌛", "exp"), st.errored())
	case ResWithdrawn, ResRemoved:
		l = l.add(" "+st.g("↩", "wd"), sgrDim)
	}
	return l
}

// autoTag names the rule of an auto decision: the engine's tag, else
// (an entry of lox audit) its rule's action.
func autoTag(e Entry) string {
	switch {
	case e.Tag != "":
		return e.Tag
	case strings.HasPrefix(e.Rule, "session:"):
		return "auto:session"
	case e.Rule != "":
		if _, a, ok := strings.Cut(e.Rule, ":"); ok {
			return "auto:" + a
		}
	}
	return "auto"
}

func entryLine(e Entry, v View, c columns, st Style) line {
	ell := st.ellipsis()
	ts := e.At.In(v.loc()).Format("15:04:05")
	if c.time == 5 {
		ts = e.At.In(v.loc()).Format("15:04")
	}
	l := line{{" ", ""}}
	l = l.add(ts, sgrDim).add(" ", "")
	if c.agent > 0 {
		agent := e.Agent
		if agent == "" {
			agent = "-"
		}
		l = append(l, line{{agent, st.agentColor(agent)}}.pad(c.agent, ell)...)
		l = l.add(" ", "")
	}
	l = append(l, line{{st.lockIcon(e.Lock) + " ", sgrDim}, {e.Instance, ""}}.pad(c.lock, ell)...)
	l = l.add(" ", "")
	prof := e.Profile
	psgr := sgrDim
	if e.Production {
		psgr = st.prod()
		if !st.Color {
			prof += "!"
		}
	}
	if prof == "" {
		prof = "-"
	}
	l = append(l, line{{prof, psgr}}.pad(c.profile, ell)...)
	l = l.add(" ", "")
	l = append(l, line{{kindLabel(e.Kind), st.kindStyle(e.Kind)}}.pad(c.kind, "")...)
	l = l.add(" ", "")
	var req line
	if e.Count > 1 {
		req = req.add(fmt.Sprintf("%s %d ", st.g("×", "x"), e.Count), sgrBold)
		what := firstWord(e.Summary)
		if e.Summary == unreadableSummary {
			what = e.Summary
		}
		if e.Target != "" {
			what += " on " + e.Target
		}
		req = append(req, st.highlight(what, "")...)
	} else {
		req = st.highlight(e.Summary, "")
	}
	if e.Note != "" {
		req = req.add(" "+e.Note, st.errored())
	}
	l = append(l, req.pad(c.request, ell)...)
	l = l.add(" ", "")
	if c.decision < 14 {
		// Too narrow for the rule: auto and asked alone.
		e.Tag = ""
		if e.Status == AutoApproved {
			e.Rule = ""
		}
	}
	l = append(l, statusCell(e, st).pad(c.decision, "")...)
	return l
}

// FeedLine is one entry as a plain log line (lox run without a
// terminal on stdout), w columns at most.
func FeedLine(e Entry, v View, w int, st Style) string {
	return finish(entryLine(e, v, layout(w), st), w, st)
}

func feedLines(v View, w int, st Style) []line {
	c := layout(w)
	if len(v.Feed) == 0 {
		return []line{{{"  no ticket yet: every ticket and decision of the hub shows here, masked by its lock", sgrDim}}}
	}
	out := make([]line, 0, len(v.Feed))
	for _, e := range v.Feed {
		out = append(out, entryLine(e, v, c, st))
	}
	return out
}

// card draws the question card: framed, above the feed.
func card(v View, c Card, waiting, w int, st Style) []line {
	ell := st.ellipsis()
	fsgr := st.frame(c.Production)
	tl, tr, bl, br, hz, vt := st.g("┌", "+"), st.g("┐", "+"), st.g("└", "+"), st.g("┘", "+"), st.g("─", "-"), st.g("│", "|")
	inner := w - 4
	title := line{{" " + st.g("◆", "?") + " QUESTION ", fsgr}}
	kind := kindLabel(c.Kind)
	if c.Console {
		kind = "console"
	} else if c.Kind == ticket.KindConnect {
		kind = "connect"
	} else if c.Kind == ticket.KindEndpoint {
		kind = "new endpoint"
	}
	title = title.add(kind, join(st.kindStyle(c.Kind), sgrBold))
	where := " on " + c.Instance
	if c.Profile != "" {
		where += "/" + c.Profile
	}
	title = title.add(where+" ", sgrBold)
	if c.Production {
		title = title.add(" PRODUCTION ", join(st.prod(), sgrReverse))
	}
	more := line{}
	if waiting > 1 {
		more = more.add(fmt.Sprintf(" 1 of %d waiting ", waiting), fsgr)
	}
	title = title.trunc(w-2-more.width()-2, ell)
	top := line{{" " + tl, fsgr}}
	top = append(top, title...)
	if n := w - top.width() - more.width() - 2; n > 0 {
		top = top.add(strings.Repeat(hz, n), fsgr)
	}
	top = append(top, more...).add(tr, fsgr)

	row := func(content line) line {
		l := line{{" " + vt + " ", fsgr}}
		l = append(l, content.pad(inner-1, ell)...)
		return l.add(vt, fsgr)
	}
	var rows []line
	who := line{}
	agent := c.Agent
	if agent == "" {
		agent = "an agent"
	}
	if c.Console {
		who = who.add("the console of "+c.Instance, sgrBold).add(" asks at its terminal", sgrDim)
	} else {
		who = who.add(agent, join(st.agentColor(agent), sgrBold)).add(" asks (unverified name)", sgrDim)
	}
	who = who.add(" "+st.g("·", "-")+" "+st.lockIcon(c.Lock)+" "+c.Lock, sgrDim)
	if !c.Expires.IsZero() {
		who = who.add(" "+st.g("·", "-")+" expires in "+age(c.Expires.Sub(v.Now)), sgrDim)
	}
	rows = append(rows, row(who))
	if c.Header != "" && !(c.Console && c.Prompt != nil) { // a console's prompt is the typed line
		rows = append(rows, row(st.highlight(c.Header, sgrBold)))
	}
	body := c.Body
	limit := 4
	if c.Console {
		limit = 12 // a policy review's changes, a host key: read before answering
	}
	if c.Details {
		limit = 1 << 30
	}
	for i, b := range body {
		if i == limit {
			rows = append(rows, row(line{{fmt.Sprintf("  %s %d more line%s: d for details", ell, len(body)-limit, plural(len(body)-limit)), sgrDim}}))
			break
		}
		rows = append(rows, row(append(line{{"  ", ""}}, st.highlight(b, "")...)))
	}
	if c.Details && c.Note != "" {
		rows = append(rows, row(line{{"note (the agent's, untrusted): ", sgrDim}, {c.Note, sgrDim}}))
	}
	for _, wn := range c.Warnings {
		rows = append(rows, row(line{{"! " + wn, st.denied()}}))
	}
	if len(c.Touched) > 0 {
		rows = append(rows, row(line{{"personal data touched: " + strings.Join(c.Touched, ", ") + " (masked)", sgrMasked}}))
	}
	if c.Unverified {
		rows = append(rows, row(line{{"! not checked under the pinned lock key", st.errored()}}))
	}
	rows = append(rows, row(line{{"why asked: " + c.Why, sgrDim}}))
	if p := c.Prompt; p != nil {
		typed := string(p.Typed)
		if p.Secret {
			typed = strings.Repeat(st.g("•", "*"), min(len(p.Typed), 24))
		}
		pl := line{{p.Label + " ", sgrBold}, {typed, ""}, {st.g("▏", "_"), sgrBold}}
		rows = append(rows, row(pl))
		hint := line{{"Enter", sgrBold}, {" confirm  ", sgrDim}, {"Esc", sgrBold}, {" cancel", sgrDim}}
		if p.Error != "" {
			hint = append(line{{p.Error + "  ", st.denied()}}, hint...)
		}
		rows = append(rows, row(hint))
	} else if c.Console {
		keys := line{{"y", join(st.approved(), sgrBold)}, {" yes   ", sgrDim}, {"n", join(st.denied(), sgrBold)}, {" no   ", sgrDim}}
		keys = keys.add("d", sgrBold).add(" details", sgrDim)
		rows = append(rows, row(keys))
	} else {
		keys := line{{"y", join(st.approved(), sgrBold)}, {" approve   ", sgrDim}, {"n", join(st.denied(), sgrBold)}, {" deny   ", sgrDim}}
		if c.Details {
			keys = keys.add("d", sgrBold).add(" less", sgrDim)
		} else {
			keys = keys.add("d", sgrBold).add(" details", sgrDim)
		}
		keys = keys.add("   x", sgrBold).add(" forget profile", sgrDim)
		rows = append(rows, row(keys))
	}
	bottom := line{{" " + bl + strings.Repeat(hz, w-4) + br, fsgr}}
	return append(append([]line{top}, rows...), bottom)
}

func helpLines(w int, st Style) []line {
	rows := [][2]string{
		{"Shift+Tab", "switch auto / manual (manual: every ticket is asked)"},
		{"y / n", "approve / deny the question on top"},
		{"d", "the question's whole masked screen"},
		{"x", "forget the profile on top (none up: all): asked again, password too"},
		{"w", "pending tickets and their age: withdraw one (x), its lock's (X), unverifiable (U)"},
		{"a", "the hub's audit (lox audit): each exchange and the rule or human that decided it"},
		{"s / ?", "sound on / off (a question plays a sound) / this help; Esc or ? closes"},
		{"q q, Ctrl-C", "quit: decisions stop, tickets wait (fail closed)"},
	}
	out := []line{{{" keys", sgrBold}}}
	for _, r := range rows {
		out = append(out, line{{"   " + r[0], sgrBold}}.pad(16, "").add(r[1], ""))
	}
	out = append(out, nil,
		line{{" auto mode (default)", sgrBold}},
		line{{"   reads auto · writes and DDL asked every time · a connection asked once per profile per session", ""}},
		line{{"   a new HTTP endpoint asked once · policy loosening always asked · deny rules always hold", ""}},
		line{{"   masked values look like ", ""}, {st.g("‹", "<") + "j***(20)" + st.g("›", ">"), sgrMasked}, {": lox run never sees them in clear", ""}},
	)
	return out
}

// hubAuditLines is the audit overlay on the hub's audit: lox audit's
// listing, its summary on top, its newest lines filling the room left.
func hubAuditLines(v View, w, room int, st Style) []line {
	out := []line{{{" the hub's audit", sgrBold}, {" · lox audit for filters · lox audit show ID for one", sgrDim}}}
	if v.Audit.err != "" {
		out = append(out, line{{"   cannot read it: " + v.Audit.err, st.errored()}})
	}
	ls := auditListing(v.Audit.xs, v.Audit.runs, v.loc(), w, st)
	head, rest := ls[:2], ls[2:]
	out = append(out, head...)
	if n := room - len(out); len(rest) > n {
		rest = rest[len(rest)-max(n, 0):]
	}
	return append(out, rest...)
}

func auditLines(v View, w int, st Style) []line {
	c := layout(w)
	out := []line{{{" this session's decisions (the hub's signed audit: lox audit verify)", sgrBold}}}
	n := 0
	for i := len(v.Feed) - 1; i >= 0; i-- {
		e := v.Feed[i] // newest first
		if e.Status == Waiting {
			continue
		}
		l := entryLine(e, v, c, st)
		who := "you"
		if e.Rule != "" {
			who = "rule " + e.Rule
		} else if e.Asked != "" {
			who += " (asked: " + e.Asked + ")"
		}
		switch e.Status {
		case Elsewhere:
			who = "another facade, or it left the queue"
		case Failed:
			who = "nobody: " + e.Note
		}
		out = append(out, l, line{{"            " + st.g("└", "`") + " decided by " + who, sgrDim}})
		n++
	}
	if n == 0 {
		out = append(out, line{{"   nothing decided yet", sgrDim}})
	}
	return out
}

// join joins SGR parameters, skipping empty ones.
func join(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + ";" + b
}
