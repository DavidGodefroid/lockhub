package loxrun

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The per-lock view (#146): what a lock decides on its own side, read
// from its console's terminal (the lines lockconsoles takes from the
// docker attach lox run holds, a channel no agent reaches: it has no
// Docker). Nothing of it goes to the hub.
//
// A console prints values in clear (the agent's statement, a k-anonymity
// count's literals, result rows when the human turned results on). The
// feed keeps only the lines it knows, the statement masked from its first
// quote, comment or non-ASCII byte on (maskLiterals); the statement in
// clear stays in lox run's memory and shows only on the human's o.

// ConsoleFeed is what a console printed since the last event: its new
// lines, cleaned for a terminal, and its status row.
type ConsoleFeed struct {
	Lines []string
	// Status is the console's status row (StatusSet: it changed).
	Status    string
	StatusSet bool
	// Backlog: lines printed before lox run attached (docker logs).
	Backlog bool
}

// ItemKind is the kind of a line of a lock's feed.
type ItemKind int

// Item kinds.
const (
	// ItemPlan: a plan as the console framed it, its decision and outcome.
	ItemPlan ItemKind = iota
	// ItemRefusal: a lock-side refusal (Code, Reason), Count times in a row.
	ItemRefusal
	// ItemPolicy: a policy change, refused, pending or applied (Text).
	ItemPolicy
	// ItemSession: the console's session started or ended (Text).
	ItemSession
)

// LockItem is one line (or framed plan) of a lock's feed.
type LockItem struct {
	At   time.Time
	Kind ItemKind
	// Agent is who the console names as the requester; Intent the
	// agent's words (literals masked).
	Agent, Intent string
	// Head is the plan's frame title (profile · host / database · user ·
	// tier); Statement its statement, literals masked; Class its class,
	// EXPLAIN summary and verdict; Reasons the verdict's reasons; Details
	// the row bound, the PII masking, the warnings.
	Head      string
	Statement []string
	Class     string
	Reasons   []string
	Details   []string
	// Decision is how the console sent it on (pending: ticket …,
	// refused: …); Outcome what it gave (done: N rows in T ms, an error).
	Decision, Outcome string
	Failed            bool
	// Code, Reason and Count are a refusal's.
	Code, Reason string
	Count        int
	// Text is a policy or session line.
	Text string
	// clear is the statement in clear, shown only on o.
	clear []string
	// cut: a line of the statement was cut (maskCut).
	cut bool
}

// PolicyState is where a lock's policy stands, as its console said.
type PolicyState int

// Policy states.
const (
	PolicyUnknown PolicyState = iota
	// PolicyApproved: the files hold the approved policy (or a tightening
	// applied).
	PolicyApproved
	// PolicyPending: a loosening in the files waits for the human's
	// review.
	PolicyPending
	// PolicyRefused: the human refused the loosening in the files; the
	// last approved policy applies.
	PolicyRefused
)

func (p PolicyState) String() string {
	switch p {
	case PolicyApproved:
		return "approved"
	case PolicyPending:
		return "pending"
	case PolicyRefused:
		return "refused"
	}
	return "unknown"
}

// LockLimits are the session limits a console said are in force (the
// approved policy's, never the files').
type LockLimits struct {
	IdleTimeout, MaxSession time.Duration
	// EndsIn is the time left to the session at At (its :status), 0
	// unknown.
	EndsIn time.Duration
	At     time.Time
}

// RefusalLoop is how many identical lock-side refusals in a row raise an
// alert in the global feed, by default.
const RefusalLoop = 3

// maxLockItems bounds a lock's feed.
const maxLockItems = 300

// LockFeed is a lock's feed and state, as lox run read them at its
// console's terminal.
type LockFeed struct {
	Instance, Lock string
	Items          []*LockItem
	Policy         PolicyState
	// PolicyDiff is the policy change the console last showed (refused or
	// pending), as it worded it.
	PolicyDiff []string
	// PolicyNote is the console's last word on a review (nothing to
	// review…).
	PolicyNote string
	Limits     LockLimits
	// Started is when its session last started serving, Ended when it
	// last ended (EndReason why); LastActive the last request seen.
	Started, Ended time.Time
	EndReason      string
	LastActive     time.Time
	// StatusRow is the console's status row.
	StatusRow string

	// The parser's state.
	box       *LockItem
	stage     int // in a box: 0 requester and intent, 1 statement (to the class line), 2 verdict and details
	blanks    int // blank lines of the statement not yet followed by one
	block     block
	lastAgent string
	alerted   map[string]bool
}

// Attention is why a lock's tab wants the human: "" none.
func (f *LockFeed) Attention(loop int) string {
	switch f.Policy {
	case PolicyPending:
		return "policy pending"
	case PolicyRefused:
		return "policy refused"
	}
	for i := len(f.Items) - 1; i >= 0 && i >= len(f.Items)-20; i-- {
		if it := f.Items[i]; it.Kind == ItemRefusal && it.Count >= loop {
			return "refusal loop"
		}
	}
	return ""
}

var (
	refusedLine = regexp.MustCompile(`^refused \[([A-Za-z0-9_.-]+)\]: (.*)$`)
	statusEnds  = regexp.MustCompile(`ends in (\d+) min \(max_session ([^)]+)\) · idle_timeout (\S+)`)
	startLimits = regexp.MustCompile(`^session: idle_timeout (\S+) · max_session (\S+)`)
	// number is a token that starts with a digit: a decimal, hex, binary,
	// exponent or grouped literal (0x4A6F686E, 0b1010, 12.5E3, 123_456).
	number = regexp.MustCompile(`\b\d[\w.]*`)
)

// maskLiterals masks s (a statement, an agent's words) from its first
// byte that may open a literal, a quoted identifier or a comment in some
// dialect (cut) to its end, one ‹?› per line, its line breaks kept: no
// reading of what follows can show a value, as none is attempted. With
// numbers, every token before the cut that starts with a digit is masked
// too, whole, a LIMIT bound as well.
func maskLiterals(s string, numbers bool) string {
	m, _ := maskCut(s, numbers)
	return m
}

// maskCut is maskLiterals; cut tells s held a byte from which on it was
// masked.
func maskCut(s string, numbers bool) (m string, cut bool) {
	i := cutAt(s)
	head := s[:i]
	if numbers {
		head = number.ReplaceAllLiteralString(head, "‹?›")
	}
	if i == len(s) {
		return head, false
	}
	return head + maskLines(s[i:]), true
}

// cutAt is the index of s's first ' " ` [ $ # -- /* or non-ASCII byte,
// len(s) without one.
func cutAt(s string) int {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'', c == '"', c == '`', c == '[', c == '$', c == '#', c >= 0x80,
			c == '-' && i+1 < len(s) && s[i+1] == '-',
			c == '/' && i+1 < len(s) && s[i+1] == '*':
			return i
		}
	}
	return len(s)
}

// maskLines replaces each line of s holding more than blanks with ‹?›.
func maskLines(s string) string {
	ls := strings.Split(s, "\n")
	for i, l := range ls {
		if strings.TrimSpace(l) != "" {
			ls[i] = "‹?›"
		} else {
			ls[i] = ""
		}
	}
	return strings.Join(ls, "\n")
}

// unmark drops the marks a console paints before a line (✓, ✗, ▸…).
func unmark(s string) string {
	return strings.TrimLeftFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '[' && r != ':' && r != '(' && r != '+' && r != '~' && r != '-'
	})
}

// take reads the lines a console printed at now. It returns the refusals
// that reached the loop count with these lines (an alert each).
func (f *LockFeed) take(lines []string, now time.Time, loop int) []*LockItem {
	var alerts []*LockItem
	for _, raw := range lines {
		if a := f.line(raw, now, loop); a != nil {
			alerts = append(alerts, a)
		}
	}
	if len(f.Items) > maxLockItems {
		f.Items = f.Items[len(f.Items)-maxLockItems:]
	}
	return alerts
}

func (f *LockFeed) push(it *LockItem) { f.Items = append(f.Items, it) }

// block is what a console's indented lines belong to: the unindented line
// before them opened it. Default-deny: an indented line outside a block it
// fits is left out (a result's row, printed "  " and its cells).
type block int

const (
	// blockDrop (the zero value: the first lines read may be a result's
	// rows, its title before the backlog): indented lines are left out
	// until an unindented line the feed knows.
	blockDrop block = iota
	// blockNone: after a known line; only a :status opens on an indented
	// row (its profile row: the console prints no line before it).
	blockNone
	// blockStatus: the rows of a :status.
	blockStatus
	// blockDiff: the lines of a policy change (+ ~ -).
	blockDiff
	// blockDescribe: a profile's policy, at its first start.
	blockDescribe
)

var (
	// doneLine is a run's outcome, as locksql words it.
	doneLine = regexp.MustCompile(`^done: \d+ rows( affected)?( \(truncated\))? in \d+ ms$`)
	// statusKeys are the rows of a console's :status.
	statusKeys = map[string]bool{"profile": true, "databases": true, "decided": true, "auto mode": true,
		"results": true, "unmask": true, "limits": true, "session": true, "plans open": true,
		"policy change": true, "policy": true, "grant": true, "boundary": true}
)

// line reads one line. Only an unindented line (marks aside) the feed
// knows is read, and an indented one in the block such a line opened: a
// console prints a result's rows indented, after a title from which on
// every indented line is left out, so that no cell is read as a console
// line.
func (f *LockFeed) line(raw string, now time.Time, loop int) *LockItem {
	l := strings.TrimRight(raw, " ")
	if l == "" {
		f.box = nil
		if f.block != blockDrop {
			f.block = blockNone
		}
		return nil
	}
	if l[0] == ' ' || l[0] == '\t' {
		f.box = nil
		f.indented(l, now)
		return nil
	}
	switch {
	case strings.HasPrefix(l, "╭─"):
		f.block = blockNone
		f.box = &LockItem{At: now, Kind: ItemPlan, Head: strings.TrimSpace(strings.TrimRight(strings.TrimPrefix(l, "╭─"), "─ "))}
		f.stage, f.blanks = 0, 0
		f.push(f.box)
		f.LastActive = now
		return nil
	case strings.HasPrefix(l, "│"):
		if f.box != nil {
			f.boxLine(strings.TrimPrefix(strings.TrimPrefix(l, "│"), " "))
		}
		return nil
	case strings.HasPrefix(l, "╰─"):
		rest := strings.TrimSpace(strings.TrimPrefix(l, "╰─"))
		box := f.box
		f.box = nil
		if box == nil {
			return nil
		}
		f.block = blockNone
		if r, ok := strings.CutPrefix(rest, "refused: "); ok {
			box.Decision = "refused: " + maskLiterals(r, true)
			box.Failed = true
			return f.refusal(now, "REFUSED", r, loop)
		}
		box.Decision = maskLiterals(rest, false)
		return nil
	}
	f.box = nil
	return f.known(unmark(l), now, loop)
}

// known reads an unindented line, its marks dropped. A line it does not
// know is left out, and ends the block before it (a result's stays).
func (f *LockFeed) known(u string, now time.Time, loop int) *LockItem {
	next := blockNone
	defer func() { f.block = next }()
	switch {
	case strings.HasPrefix(u, "result in clear"), strings.HasPrefix(u, "PII: UNMASKED result"):
		next = blockDrop
	case refusedLine.MatchString(u):
		m := refusedLine.FindStringSubmatch(u)
		return f.refusal(now, m[1], m[2], loop)
	case strings.HasPrefix(u, "not submitted: "):
		r := strings.TrimPrefix(u, "not submitted: ")
		code := "NOT_SUBMITTED"
		if strings.Contains(r, "too many tickets") {
			code = "THROTTLED"
		}
		f.lastPlanFailed("not submitted")
		return f.refusal(now, code, strings.TrimPrefix(r, "hubclient: "), loop)
	case doneLine.MatchString(u):
		f.outcome(u, false, now)
	case strings.HasPrefix(u, "denied: "), strings.HasPrefix(u, "error: "), strings.HasPrefix(u, "failed: "):
		f.outcome(maskLiterals(u, true), true, now)
	case strings.HasPrefix(u, "pending policy change (loosening)"):
		f.setPolicy(PolicyPending, now, "a loosening of the policy waits for your review (r)")
	case strings.HasPrefix(u, "pending policy change for profile "), strings.HasPrefix(u, "The policy of profile ") && strings.HasSuffix(u, "changed since it was approved:"):
		f.PolicyDiff = nil
		next = blockDiff
	case strings.HasPrefix(u, "policy change refused"), strings.HasPrefix(u, "changes refused: the last approved policy applies"):
		f.setPolicy(PolicyRefused, now, "the loosening was refused: the last approved policy applies")
	case strings.HasPrefix(u, "policy change applied"):
		f.setPolicy(PolicyApproved, now, "policy change applied")
	case strings.HasPrefix(u, "policy tightened"):
		f.PolicyDiff = nil
		next = blockDiff
		f.setPolicy(PolicyApproved, now, "policy tightened")
	case strings.HasPrefix(u, "nothing to review"):
		f.PolicyNote = "the console has nothing to review"
		if f.Policy == PolicyRefused {
			f.PolicyNote += ": a refused loosening is offered again once the config files change"
		}
	case strings.HasPrefix(u, "First start of profile "):
		next = blockDescribe
	case strings.HasPrefix(u, "Requests are decided on lockhub"), strings.HasPrefix(u, "Policy only: "):
		f.Started, f.Ended, f.EndReason = now, time.Time{}, ""
		f.push(&LockItem{At: now, Kind: ItemSession, Text: "console serving"})
	case strings.HasPrefix(u, "session ended: "):
		f.Ended, f.EndReason = now, maskLiterals(strings.TrimPrefix(u, "session ended: "), false)
		f.push(&LockItem{At: now, Kind: ItemSession, Text: "session ended: " + f.EndReason})
	default:
		if f.block == blockDrop {
			next = blockDrop
		}
	}
	return nil
}

// indented reads an indented line, in the block it belongs to.
func (f *LockFeed) indented(l string, now time.Time) {
	switch f.block {
	case blockDrop:
		return
	case blockDiff:
		if d, ok := diffLine(l); ok {
			f.PolicyDiff = append(f.PolicyDiff, d)
			return
		}
	case blockDescribe:
		if m := startLimits.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			f.setLimits(m[1], m[2], now)
		}
		return
	}
	if k, v, ok := statusRow(l); ok && (f.block == blockStatus || k == "profile") {
		f.block = blockStatus
		f.statusRow(k, v, now)
		return
	}
	// An indented line no block takes: what follows is not read until a
	// known unindented line.
	f.block = blockDrop
}

// boxLine reads a line inside a plan's frame.
func (f *LockFeed) boxLine(c string) {
	b := f.box
	if strings.TrimSpace(c) == "" {
		// The blank line after the intent opens the statement; a blank
		// line in the statement is kept once a line follows it.
		switch f.stage {
		case 0:
			f.stage = 1
		case 1:
			if len(b.Statement) > 0 {
				f.blanks++
			}
		}
		return
	}
	switch {
	case f.stage == 0 && strings.HasPrefix(c, "requested by "):
		b.Agent = strings.TrimPrefix(c, "requested by ")
		f.lastAgent = b.Agent
	case f.stage == 0 && strings.HasPrefix(c, "agent: "):
		b.Intent = maskLiterals(strings.TrimPrefix(c, "agent: "), true)
	case f.stage < 2 && strings.HasPrefix(c, "class "):
		// The console indents the statement's lines: only its own
		// class line, unindented, ends the statement.
		f.stage, f.blanks = 2, 0
		b.Class = c
	case f.stage == 1:
		c = strings.TrimSpace(c)
		for ; f.blanks > 0; f.blanks-- {
			b.clear = append(b.clear, "")
			b.Statement = append(b.Statement, "")
		}
		// Once a line is cut, the statement's next lines are masked
		// whole: a literal or comment may span lines.
		b.clear = append(b.clear, c)
		if b.cut {
			b.Statement = append(b.Statement, "‹?›")
			break
		}
		m, cut := maskCut(c, true)
		b.Statement = append(b.Statement, m)
		b.cut = cut
	case strings.HasPrefix(c, "class "):
		b.Class = c
	case strings.HasPrefix(c, "  - "):
		r := strings.TrimPrefix(c, "  - ")
		if strings.Contains(r, "policy change in the config files was refused") {
			f.setPolicy(PolicyRefused, b.At, "the loosening was refused: the last approved policy applies")
		}
		b.Reasons = append(b.Reasons, maskLiterals(r, true))
	case strings.HasPrefix(c, "k-anonymity count"):
		// Its statement quotes the agent's literals: masked like the
		// agent's, shown once.
		head, stmt, _ := strings.Cut(c, ": ")
		d := head + ": " + maskLiterals(stmt, true)
		for _, x := range b.Details {
			if strings.HasPrefix(x, "k-anonymity count") {
				return
			}
		}
		b.Details = append(b.Details, d)
	case strings.HasPrefix(c, "returns at most"):
		// Its bound is the agent's LIMIT: a number it chose.
		b.Details = append(b.Details, maskLiterals(c, true))
	case strings.HasPrefix(c, "PII"), strings.HasPrefix(c, "warning: "),
		strings.HasPrefix(c, "reads"), strings.HasPrefix(c, "writes"), strings.HasPrefix(c, "row estimates"),
		strings.HasPrefix(c, "EXPLAIN only"), strings.HasPrefix(c, "result: "):
		b.Details = append(b.Details, maskLiterals(c, false))
	}
	// Anything else (a console's own lines a lock adds) is left out: it
	// may hold a value.
}

// refusal records a lock-side refusal: the same one as the last refusal
// from the same agent is counted on it.
func (f *LockFeed) refusal(now time.Time, code, reason string, loop int) *LockItem {
	reason = maskLiterals(reason, false)
	f.LastActive = now
	for i := len(f.Items) - 1; i >= 0; i-- {
		it := f.Items[i]
		if it.Kind != ItemRefusal {
			if it.Kind == ItemPlan && it.Decision != "" && !it.Failed {
				break // a plan went through since: not a loop
			}
			continue
		}
		if it.Code == code && it.Reason == reason && it.Agent == f.lastAgent {
			it.Count++
			it.At = now
			f.Items = append(append(f.Items[:i:i], f.Items[i+1:]...), it)
			if it.Count >= loop && !f.alerted[f.loopKey(it)] {
				if f.alerted == nil {
					f.alerted = map[string]bool{}
				}
				f.alerted[f.loopKey(it)] = true
				return it
			}
			return nil
		}
		break
	}
	it := &LockItem{At: now, Kind: ItemRefusal, Code: code, Reason: reason, Count: 1, Agent: f.lastAgent}
	delete(f.alerted, f.loopKey(it)) // a new loop of it alerts again
	f.push(it)
	if loop <= 1 {
		return it
	}
	return nil
}

func (f *LockFeed) loopKey(it *LockItem) string {
	return it.Code + "\x00" + it.Reason + "\x00" + it.Agent
}

// lastPlanFailed marks the last plan with no decision as failed (why).
func (f *LockFeed) lastPlanFailed(why string) {
	for i := len(f.Items) - 1; i >= 0; i-- {
		if it := f.Items[i]; it.Kind == ItemPlan {
			if it.Decision == "" || strings.HasPrefix(it.Decision, "pending") {
				it.Failed, it.Outcome = true, why
			}
			return
		}
	}
}

// outcome is a plan's result: on the last plan without one.
func (f *LockFeed) outcome(text string, failed bool, now time.Time) {
	f.LastActive = now
	for i := len(f.Items) - 1; i >= 0; i-- {
		if it := f.Items[i]; it.Kind == ItemPlan {
			if it.Outcome == "" {
				it.Outcome, it.Failed = text, failed
				return
			}
			break
		}
	}
	f.push(&LockItem{At: now, Kind: ItemPlan, Outcome: text, Failed: failed})
}

func (f *LockFeed) setPolicy(p PolicyState, now time.Time, text string) {
	if f.Policy == p && text == "" {
		return
	}
	changed := f.Policy != p
	f.Policy = p
	if p != PolicyRefused {
		f.PolicyNote = ""
	}
	if changed && text != "" {
		f.push(&LockItem{At: now, Kind: ItemPolicy, Text: text})
	}
}

// diffLine is a policy change's line ("  + x: v", "  ~ x: a → b",
// "  - x: v"), as the console words it.
func diffLine(l string) (string, bool) {
	if !strings.HasPrefix(l, "  ") {
		return "", false
	}
	t := strings.TrimSpace(l)
	if len(t) > 2 && (t[0] == '+' || t[0] == '~' || t[0] == '-') && t[1] == ' ' {
		return t, true
	}
	return "", false
}

// statusRow is a row of the console's :status ("  session  ends in …").
func statusRow(l string) (key, val string, ok bool) {
	if !strings.HasPrefix(l, "  ") || strings.HasPrefix(l, "   ") {
		return "", "", false
	}
	t := strings.TrimPrefix(l, "  ")
	k, v, found := strings.Cut(t, "  ")
	if !found {
		return "", "", false
	}
	if !statusKeys[k] {
		return "", "", false
	}
	return k, strings.TrimSpace(v), true
}

func (f *LockFeed) statusRow(k, v string, now time.Time) {
	switch k {
	case "session":
		if m := statusEnds.FindStringSubmatch(v); m != nil {
			f.setLimits(m[3], m[2], now)
			if n, err := strconv.Atoi(m[1]); err == nil {
				f.Limits.EndsIn = time.Duration(n) * time.Minute
			}
		}
	case "policy change":
		switch {
		case strings.Contains(v, "awaits"):
			f.setPolicy(PolicyPending, now, "a loosening of the policy waits for your review (r)")
		case v == "none" && f.Policy != PolicyRefused:
			f.setPolicy(PolicyApproved, now, "")
		}
	}
}

func (f *LockFeed) setLimits(idle, maxSession string, now time.Time) {
	if d, err := time.ParseDuration(idle); err == nil {
		f.Limits.IdleTimeout = d
	}
	if d, err := time.ParseDuration(maxSession); err == nil {
		f.Limits.MaxSession = d
	}
	f.Limits.At, f.Limits.EndsIn = now, 0
}

// status reads the console's status row: a pending policy change shows
// there.
func (f *LockFeed) status(row string, now time.Time) {
	f.StatusRow = row
	if strings.Contains(row, "policy change pending") {
		f.setPolicy(PolicyPending, now, "a loosening of the policy waits for your review (r)")
	}
}

// IdleFor is how long the lock has seen no request at now (0: none seen
// since its session started).
func (f *LockFeed) IdleFor(now time.Time) time.Duration {
	last := f.LastActive
	if f.Started.After(last) {
		last = f.Started
	}
	if last.IsZero() {
		return 0
	}
	return now.Sub(last)
}

// SessionLeft is the time left before max_session at now, as the
// console's :status said (false: not known).
func (f *LockFeed) SessionLeft(now time.Time) (time.Duration, bool) {
	if f.Limits.EndsIn > 0 {
		return max(f.Limits.EndsIn-now.Sub(f.Limits.At), 0), true
	}
	if f.Limits.MaxSession > 0 && !f.Started.IsZero() {
		return max(f.Limits.MaxSession-now.Sub(f.Started), 0), true
	}
	return 0, false
}
