package loxrun

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// ConsoleCommander is a Consoles that can type one of a console's own
// commands (:review, :status) at its terminal, when it asks nothing.
// Like an answer, the command goes to the console's terminal only.
type ConsoleCommander interface {
	Command(instance, line string) error
}

// KindRefusal is the kind of a lock-side refusal loop's line in the
// global feed.
const KindRefusal ticket.Kind = "refuse"

// LockTab is a lock's tab: its instance, its lock and why it wants the
// human ("" nothing).
type LockTab struct {
	Instance, Lock string
	Attention      string
}

// LockView is the lock tab shown: its feed and state, the console's
// state, and whether the statements show in clear (o).
type LockView struct {
	Feed    LockFeed
	Console LockConsole
	Reveal  bool
	Loop    int
}

// loopAlert is a refusal loop's line in the global feed.
type loopAlert struct {
	item  *LockItem
	entry *Entry
}

func (st *state) refusalLoop() int {
	if st.s.RefusalLoop > 0 {
		return st.s.RefusalLoop
	}
	return RefusalLoop
}

// lockFeed is instance's feed, made on first use.
func (st *state) lockFeed(instance, lock string) *LockFeed {
	f, ok := st.locks[instance]
	if !ok {
		f = &LockFeed{Instance: clean(instance), Lock: clean(lock)}
		st.locks[instance] = f
	}
	return f
}

// onConsoleFeed takes what a console printed.
func (st *state) onConsoleFeed(e ConsoleEvent) {
	st.dirty = true
	f := st.lockFeed(e.Instance, e.Lock)
	now := st.s.now()
	if e.Feed.StatusSet {
		f.status(clean(e.Feed.Status), now)
	}
	lines := make([]string, len(e.Feed.Lines))
	for i, l := range e.Feed.Lines {
		lines[i] = clean(l)
	}
	before := f.Policy
	for _, it := range f.take(lines, now, st.refusalLoop()) {
		en := &Entry{At: now, Instance: f.Instance, Lock: f.Lock, Kind: KindRefusal, Status: Failed, Agent: it.Agent}
		st.loops = append(st.loops, loopAlert{it, en})
		st.feed = append(st.feed, en)
		if len(st.feed) > maxFeed {
			st.feed = st.feed[len(st.feed)-maxFeed:]
		}
		st.bell = true
		st.s.observe(Event{Kind: EvAlert, Instance: e.Instance})
	}
	for _, a := range st.loops {
		if a.entry.Instance == f.Instance {
			st.refreshLoop(a)
		}
	}
	if f.Policy != before {
		st.logf("lox run: %s: policy %s", f.Instance, f.Policy)
		st.s.observe(Event{Kind: EvPolicy, Instance: e.Instance})
	}
}

// refreshLoop words a loop's line with its count now.
func (st *state) refreshLoop(a loopAlert) {
	it := a.item
	was := a.entry.Summary
	a.entry.At = it.At
	a.entry.Summary = fmt.Sprintf("lock-side refusal loop: %s ×%d: %s", it.Code, it.Count, it.Reason)
	a.entry.Note = "(" + st.tabKey(a.entry.Instance) + ": its tab)"
	if a.entry.Summary != was {
		st.printEntry(a.entry)
	}
}

// tabs are the locks' tabs, by instance: the locks whose console lox
// run reaches or read.
func (st *state) tabs() []LockTab {
	names := map[string]string{}
	for i, c := range st.consoles {
		names[i] = c.Lock
	}
	for i, f := range st.locks {
		if _, ok := names[i]; !ok {
			names[i] = f.Lock
		}
	}
	out := make([]LockTab, 0, len(names))
	for i, l := range names {
		t := LockTab{Instance: clean(i), Lock: l}
		if f, ok := st.locks[i]; ok {
			t.Attention = f.Attention(st.refusalLoop())
		}
		if c, ok := st.consoles[i]; ok && c.State == ConsoleWaiting {
			t.Attention = "question"
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b LockTab) int { return strings.Compare(a.Instance, b.Instance) })
	return out
}

// tabKey is the key of instance's tab ("1"…"9", "Tab" past nine).
func (st *state) tabKey(instance string) string {
	for i, t := range st.tabs() {
		if t.Instance == instance {
			if i < 9 {
				return fmt.Sprint(i + 1)
			}
			break
		}
	}
	return "Tab"
}

// lockView is the lock tab shown, nil for the global feed.
func (st *state) lockView() *LockView {
	if st.tab == "" {
		return nil
	}
	v := &LockView{Reveal: st.reveal, Loop: st.refusalLoop()}
	if f, ok := st.locks[st.tab]; ok {
		v.Feed = *f
		v.Feed.Items = make([]*LockItem, len(f.Items))
		for i, it := range f.Items {
			c := *it
			if !st.reveal {
				c.clear = nil
			}
			v.Feed.Items[i] = &c
		}
	} else {
		v.Feed = LockFeed{Instance: clean(st.tab)}
	}
	if c, ok := st.consoles[st.tab]; ok {
		v.Console = *c
		if v.Feed.Lock == "" {
			v.Feed.Lock = c.Lock
		}
	}
	return v
}

// tabKeyPress handles the keys of the tabs: 0 the global feed, 1…9 a
// lock's tab, Tab the next one. True: the key was the tabs'.
func (st *state) tabKeyPress(k Key) bool {
	tabs := st.tabs()
	if len(tabs) == 0 {
		return false
	}
	switch {
	case k.Code == KeyTab:
		i := slices.IndexFunc(tabs, func(t LockTab) bool { return t.Instance == st.tab })
		if i+1 >= len(tabs) {
			st.setTab("")
		} else {
			st.setTab(tabs[i+1].Instance)
		}
		return true
	case k.Code == KeyRune && k.Rune == '0':
		st.setTab("")
		return true
	case k.Code == KeyRune && k.Rune >= '1' && k.Rune <= '9':
		if i := int(k.Rune - '1'); i < len(tabs) {
			st.setTab(tabs[i].Instance)
		}
		return true
	}
	return false
}

func (st *state) setTab(instance string) {
	if st.tab != instance {
		st.reveal = false
	}
	st.tab = instance
	st.overlay = ""
}

// lockKeyPress handles a lock tab's own keys: r review its policy, i ask
// its :status, o its statements in clear. True: the key was the tab's.
func (st *state) lockKeyPress(k Key) bool {
	if st.tab == "" || k.Code != KeyRune {
		return false
	}
	switch k.Rune {
	case 'o', 'O':
		st.reveal = !st.reveal
		if st.reveal {
			st.setFlash("statements in clear on this screen (o hides them): they never leave lox run")
		}
		return true
	case 'r', 'R':
		st.consoleCommand(":review", "review asked: the console shows the change in a question card; y applies it")
		return true
	case 'i', 'I':
		st.consoleCommand(":status", "the console's :status asked: its limits in force show here")
		return true
	}
	return false
}

// consoleCommand types line at the shown tab's console.
func (st *state) consoleCommand(line, done string) {
	cmd, ok := st.s.Consoles.(ConsoleCommander)
	if !ok {
		st.setFlash("lox run cannot type at this lock's console: lox attach " + clean(st.tab))
		return
	}
	if c, ok := st.consoles[st.tab]; !ok || c.State != ConsoleServing {
		st.setFlash("the console of " + clean(st.tab) + " is not serving (it asks something, or it is not reached)")
		return
	}
	if err := cmd.Command(st.tab, line); err != nil {
		st.setFlash("cannot type " + line + ": " + shortNote(err.Error()))
		return
	}
	st.setFlash(done)
}

// lockLines is a lock's tab: its session and policy state on top, then
// its feed, newest last.
func lockLines(v View, w int, st Style) (top, feed []line) {
	lv := v.Lock
	f := &lv.Feed
	sep := " " + st.g("·", "-") + " "
	head := line{{" " + st.lockIcon(f.Lock) + " ", sgrDim}, {f.Instance, sgrBold}}
	if f.Lock != "" {
		head = head.add(sep+f.Lock, sgrDim)
	}
	switch lv.Console.State {
	case ConsoleServing:
		head = head.add(sep+"console serving", st.approved())
	case ConsoleWaiting:
		head = head.add(sep+"console waiting for you: "+lv.Console.Question, st.asked())
	case "":
		head = head.add(sep+"console not followed", sgrDim)
	default:
		msg := "console " + string(lv.Console.State)
		if lv.Console.Err != "" {
			msg += ": " + lv.Console.Err
		}
		head = head.add(sep+msg, st.errored())
	}
	top = append(top, head)

	sess := line{{"   session ", sgrDim}}
	switch {
	case !f.Ended.IsZero() && !f.Ended.Before(f.Started):
		sess = sess.add("ended "+age(v.Now.Sub(f.Ended))+" ago: "+f.EndReason, st.errored())
	case !f.Started.IsZero():
		sess = sess.add("serving for "+age(v.Now.Sub(f.Started)), st.approved())
	default:
		sess = sess.add("start not seen", sgrDim)
	}
	l := f.Limits
	idle := f.IdleFor(v.Now)
	if l.IdleTimeout > 0 {
		left := max(l.IdleTimeout-idle, 0)
		sgr := ""
		if left < time.Minute {
			sgr = st.asked()
		}
		sess = sess.add(sep+"idle "+age(idle)+" of idle_timeout "+short(l.IdleTimeout), "").add(" ("+age(left)+" left)", sgr)
	} else if idle > 0 {
		sess = sess.add(sep+"idle "+age(idle), "")
	}
	if left, ok := f.SessionLeft(v.Now); ok {
		sess = sess.add(sep+"session ends in "+age(left), "")
	}
	if l.MaxSession > 0 {
		sess = sess.add(" (max_session "+short(l.MaxSession)+")", sgrDim)
	}
	if l.IdleTimeout == 0 && l.MaxSession == 0 {
		sess = sess.add(sep+"limits in force not known yet: i asks the console's :status", sgrDim)
	} else {
		sess = sess.add(sep+"limits in force, as the console said "+age(v.Now.Sub(l.At))+" ago", sgrDim)
	}
	top = append(top, sess)

	pol := line{{"   policy  ", sgrDim}}
	switch f.Policy {
	case PolicyPending:
		pol = pol.add("PENDING: a loosening waits for your review", join(st.asked(), sgrBold)).add(sep+"r reviews it here", sgrDim)
	case PolicyRefused:
		pol = pol.add("REFUSED: the last approved policy applies, not the files'", join(st.denied(), sgrBold)).add(sep+"r reviews it again", sgrDim)
	case PolicyApproved:
		pol = pol.add("approved: the files hold the policy in force", st.approved())
	default:
		pol = pol.add("no change seen", sgrDim)
	}
	top = append(top, pol)
	if f.Policy == PolicyPending || f.Policy == PolicyRefused {
		for _, d := range f.PolicyDiff {
			sgr := ""
			if strings.Contains(d, "(loosens)") {
				sgr = st.denied()
			}
			top = append(top, line{{"     " + d, sgr}})
		}
	}
	if f.PolicyNote != "" {
		top = append(top, line{{"     " + f.PolicyNote, sgrDim}})
	}
	title := " lock-side feed (masked; o shows the statements in clear)"
	if lv.Reveal {
		title = " lock-side feed (statements IN CLEAR: o hides them)"
	}
	top = append(top, line{{title, sgrDim}})

	if len(f.Items) == 0 {
		return top, []line{{{"  nothing yet: the plans, refusals and policy changes of this lock's console show here", sgrDim}}}
	}
	for _, it := range f.Items {
		feed = append(feed, itemLines(*it, v, lv, w, st)...)
	}
	return top, feed
}

// short is a duration as a policy writes it: 10m, 1h, 1h30m.
func short(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func itemLines(it LockItem, v View, lv *LockView, w int, st Style) []line {
	ts := line{{" " + it.At.In(v.loc()).Format("15:04:05") + " ", sgrDim}}
	ind := "          "
	switch it.Kind {
	case ItemRefusal:
		l := ts.add(st.g("✘", "x")+" refused ["+it.Code+"]", join(st.denied(), sgrBold))
		if it.Count > 1 {
			sgr := sgrBold
			if it.Count >= lv.Loop {
				sgr = join(st.asked(), sgrBold)
			}
			l = l.add(fmt.Sprintf(" %s%d", st.g("×", "x"), it.Count), sgr)
		}
		l = l.add(" "+it.Reason, "")
		if it.Agent != "" {
			l = l.add(" ("+it.Agent+")", sgrDim)
		}
		return []line{l}
	case ItemPolicy:
		return []line{ts.add("policy: "+it.Text, sgrBold)}
	case ItemSession:
		return []line{ts.add(it.Text, sgrDim)}
	}
	var out []line
	l := ts.add("plan", st.keyword())
	if it.Head == "" && len(it.Statement) == 0 {
		return []line{l.add(" "+it.Outcome, outcomeSGR(it, st))}
	}
	if it.Agent != "" {
		l = l.add(" "+it.Agent, st.agentColor(it.Agent))
	}
	if it.Intent != "" {
		l = l.add(": "+it.Intent, sgrDim)
	}
	if it.Agent == "" && it.Intent == "" {
		l = l.add(" "+it.Head, sgrDim)
	}
	out = append(out, l)
	stmt := it.Statement
	if lv.Reveal && it.clear != nil {
		stmt = it.clear
	}
	for _, s := range stmt {
		out = append(out, append(line{{ind, ""}}, st.highlight(s, "")...))
	}
	if it.Class != "" {
		out = append(out, line{{ind + it.Class, ""}})
	}
	for _, r := range it.Reasons {
		out = append(out, line{{ind + "  - " + r, sgrDim}})
	}
	if len(it.Details) > 0 {
		out = append(out, line{{ind + strings.Join(it.Details, " "+st.g("·", "-")+" "), sgrDim}})
	}
	if it.Decision != "" || it.Outcome != "" {
		d := line{{ind + st.g("→", "->") + " ", sgrDim}}
		if it.Decision != "" {
			d = d.add(it.Decision, "")
		}
		if it.Outcome != "" {
			if it.Decision != "" {
				d = d.add(" "+st.g("·", "-")+" ", sgrDim)
			}
			d = d.add(it.Outcome, outcomeSGR(it, st))
		}
		out = append(out, d)
	}
	return out
}

func outcomeSGR(it LockItem, st Style) string {
	if it.Failed {
		return st.errored()
	}
	return st.approved()
}

// tabsLine is the header's line of the tabs: the global feed, then one
// per lock, with its badge.
func tabsLine(v View, st Style) line {
	l := line{{" tabs ", sgrDim}}
	tab := func(key, name string, on bool, badge string) {
		sgr := sgrDim
		if on {
			sgr = join(sgrBold, sgrReverse)
		}
		l = l.add(" "+key+" "+name+" ", sgr)
		if badge != "" {
			l = l.add(st.g("◆", "!")+" "+badge, join(st.asked(), sgrBold))
		}
		l = l.add(" ", "")
	}
	tab("0", "feed", v.Lock == nil, "")
	for i, t := range v.Tabs {
		key := "Tab"
		if i < 9 {
			key = fmt.Sprint(i + 1)
		}
		tab(key, t.Instance, v.Lock != nil && v.Lock.Feed.Instance == t.Instance, t.Attention)
	}
	return l
}
