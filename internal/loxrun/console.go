package loxrun

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// ConsoleState is where a lock's console stands, as lox run sees it at
// the console's own terminal.
type ConsoleState string

// Console states.
const (
	// ConsoleStarting: not reached yet (lox run attaches to it).
	ConsoleStarting ConsoleState = "starting"
	// ConsoleServing: it runs and asks nothing.
	ConsoleServing ConsoleState = "serving"
	// ConsoleWaiting: it waits for the human's answer to a question.
	ConsoleWaiting ConsoleState = "waiting"
	// ConsoleStopped: its container does not run (Err: its last line).
	ConsoleStopped ConsoleState = "stopped"
	// ConsoleUnreachable: lox run cannot reach its terminal here (Err:
	// why); lox attach still does.
	ConsoleUnreachable ConsoleState = "unreachable"
	// ConsoleNotStarted: lox run did not start it (Err: why, such as a
	// mount plan it refused); the other locks are served.
	ConsoleNotStarted ConsoleState = "not started"
)

// ConsoleQuestion is a question a console waits for at its terminal: the
// prompt it recorded (lockkit's question file) and the lines it printed
// above it (a policy review's changes, a host key's fingerprint).
type ConsoleQuestion struct {
	// Seq tells one question from the next, even with the same prompt.
	Seq     int
	Prompt  string
	Context []string
}

// ConsoleEvent is a change of a lock's console.
type ConsoleEvent struct {
	Instance, Lock string
	State          ConsoleState
	// Question is set when State is ConsoleWaiting.
	Question *ConsoleQuestion
	Err      string
	// Feed, when set, is what the console printed: the event changes
	// nothing else (State is not set).
	Feed *ConsoleFeed
}

// Consoles is lox run's reach to the locks' terminals (consoles.Bridge):
// their states and questions, and the answers typed in lox run, written
// to the console's terminal only. An answer never goes through the hub,
// and an agent has no way to write one (it has no Docker).
type Consoles interface {
	Events() <-chan ConsoleEvent
	// Answer types answer and Enter at instance's terminal, if question
	// seq is still the one it waits for. The caller wipes answer.
	Answer(instance string, seq int, answer []byte) error
}

// KindPrompt is the kind of a console's question in the feed.
const KindPrompt ticket.Kind = "prompt"

// Prompt kinds of a console question.
const (
	cqYesNo  = "yesno"  // [y/N], [yes/N]: y or n
	cqTyped  = "typed"  // a value shown as typed (a profile name, a fingerprint's end)
	cqSecret = "secret" // a password, passphrase or token: shown as dots
)

// consoleQ is a console question lox run follows.
type consoleQ struct {
	instance, lock string
	seq            int
	prompt         string
	kind           string
	yes            string // the yes answer of a yes/no question
}

var yesNo = regexp.MustCompile(`\[(y|yes)/N\]\s*$`)

// classify reads a console's prompt: a yes/no question, a value typed in
// clear (the console's "Type …" confirmations), or anything else, a
// secret (shown as dots only).
func classify(prompt string) (kind, yes string) {
	if m := yesNo.FindStringSubmatch(prompt); m != nil {
		return cqYesNo, m[1]
	}
	p := strings.ToLower(prompt)
	for _, s := range []string{"password", "passphrase", "token", "secret"} {
		if strings.Contains(p, s) {
			return cqSecret, ""
		}
	}
	// "Type the profile name …", "Type the last 8 characters of the
	// fingerprint …", and the retype hint before it "(r to retype) Type …".
	if strings.HasPrefix(p, "type ") || strings.Contains(p, ") type ") {
		return cqTyped, ""
	}
	return cqSecret, ""
}

// production: the console's question is about a production profile (its
// banner above, or the typed profile name it asks).
func production(q ConsoleQuestion) bool {
	if strings.Contains(q.Prompt, "Type the profile name") {
		return true
	}
	return slices.ContainsFunc(q.Context, func(l string) bool { return strings.Contains(l, "PRODUCTION") })
}

// LockConsole is a lock's console state in the header.
type LockConsole struct {
	Instance, Lock string
	State          ConsoleState
	Question, Err  string
}

// consoleAnswer is an answer typed in this session to a console question
// that takes a value: Enter alone gives it again when the console asks
// the same thing again (it restarted after its idle end).
type consoleAnswer struct {
	value []byte
	at    time.Time
}

// rejectedWithin: the same question asked again this soon after it was
// answered with the session's answer means the console refused it: the
// answer is dropped, and typed again.
const rejectedWithin = 30 * time.Second

func answerKey(instance, prompt string) string { return instance + "\x00" + prompt }

// onConsole takes a change of a lock's console.
func (st *state) onConsole(e ConsoleEvent) {
	if e.Feed != nil {
		st.onConsoleFeed(e)
		return
	}
	st.dirty = true
	lc, ok := st.consoles[e.Instance]
	if !ok {
		lc = &LockConsole{Instance: clean(e.Instance), Lock: clean(e.Lock)}
		st.consoles[e.Instance] = lc
	}
	lc.State, lc.Err, lc.Question = e.State, clean(e.Err), ""
	if e.State == ConsoleWaiting && e.Question != nil {
		lc.Question = clean(e.Question.Prompt)
	}
	cur := st.consoleCards[e.Instance]
	if cur != nil && (e.Question == nil || e.State != ConsoleWaiting || cur.cq.seq != e.Question.Seq) {
		// Answered at its terminal (lox attach), or it asks another one,
		// or it stopped: the card goes.
		delete(st.consoleCards, e.Instance)
		st.removeCard(cur)
		if cur.entry.Status == Waiting {
			cur.entry.Status = Elsewhere
			st.printEntry(cur.entry)
		}
		cur.decided = true
	}
	if e.State == ConsoleWaiting && e.Question != nil && (cur == nil || cur.decided) {
		st.askConsole(e)
	}
}

// askConsole puts a console's question up as a card.
func (st *state) askConsole(e ConsoleEvent) {
	q := *e.Question
	kind, yes := classify(q.Prompt)
	cq := &consoleQ{instance: e.Instance, lock: e.Lock, seq: q.Seq, prompt: q.Prompt, kind: kind, yes: yes}
	k := answerKey(e.Instance, q.Prompt)
	if a, ok := st.consoleAnswers[k]; ok && kind != cqYesNo && st.s.now().Sub(a.at) < rejectedWithin {
		// Asked again right after the session's answer: refused.
		clear(a.value)
		delete(st.consoleAnswers, k)
	}
	prod := production(q)
	t := &tracked{instance: e.Instance, cq: cq, profileKey: e.Instance}
	t.entry = &Entry{At: st.s.now(), Instance: clean(e.Instance), Lock: clean(e.Lock), Kind: KindPrompt, Production: prod,
		Summary: clean(q.Prompt)}
	c := &Card{Instance: clean(e.Instance), Lock: clean(e.Lock), Kind: KindPrompt, Production: prod, Console: true,
		Header: clean(q.Prompt), Why: "the lock's console asks at its terminal; your answer goes there only, never through the hub"}
	for _, l := range q.Context {
		c.Body = append(c.Body, clean(l))
	}
	t.card = c
	if kind != cqYesNo {
		c.Prompt = st.consolePrompt(t)
	}
	st.consoleCards[e.Instance] = t
	t.entry.Status = Waiting
	st.pushEntry(t, false)
	st.cards = append(st.cards, t)
	st.call(t)
	if st.s.Size == nil {
		for _, l := range card(st.view(), *c, len(st.cards), 80, st.s.Style) {
			st.logf("%s", finish(l, 80, st.s.Style))
		}
		st.logf("answer: type it, then Enter (the question on top first)")
	}
	st.s.observe(Event{Kind: EvQuestion, Instance: e.Instance})
}

// consolePrompt is the line a console's question is typed into.
func (st *state) consolePrompt(t *tracked) *Prompt {
	label := strings.TrimSpace(clean(t.cq.prompt))
	p := &Prompt{Label: label, Secret: t.cq.kind == cqSecret}
	if _, ok := st.consoleAnswers[answerKey(t.instance, t.cq.prompt)]; ok {
		p.Label = "(Enter alone: this session's) " + label
		p.Default = true
	}
	return p
}

// answerConsole types answer at t's console and settles its card.
func (st *state) answerConsole(t *tracked, answer []byte, approved bool) {
	delete(st.consoleCards, t.instance)
	st.removeCard(t)
	t.decided = true
	if err := st.s.Consoles.Answer(t.instance, t.cq.seq, answer); err != nil {
		t.entry.Status, t.entry.Note = Failed, shortNote(err.Error())
		st.printEntry(t.entry)
		st.s.observe(Event{Kind: EvFailed, Instance: t.instance, Err: err})
		return
	}
	t.entry.Status = Denied
	if approved {
		t.entry.Status = Approved
	}
	st.printEntry(t.entry)
	st.s.observe(Event{Kind: EvDecided, Instance: t.instance, Approved: approved})
}

// consoleKey is y or n on a console's card.
func (st *state) consoleKey(t *tracked, yes bool) {
	switch {
	case t.cq.kind == cqYesNo && yes:
		st.answerConsole(t, []byte(t.cq.yes), true)
	case t.cq.kind == cqYesNo:
		st.answerConsole(t, []byte("n"), false)
	case yes:
		t.card.Prompt = st.consolePrompt(t)
	default:
		// An empty answer: the console refuses it and says why.
		st.answerConsole(t, nil, false)
	}
}

// consoleEnter is Enter on a console card's prompt with what was typed.
func (st *state) consoleEnter(t *tracked, typed []byte) {
	p := t.card.Prompt
	k := answerKey(t.instance, t.cq.prompt)
	if len(typed) == 0 {
		a, ok := st.consoleAnswers[k]
		if !ok {
			p.Error = "empty (Esc, then n, to answer nothing)"
			return
		}
		a.at = st.s.now()
		v := slices.Clone(a.value)
		defer clear(v)
		st.answerConsole(t, v, true)
		return
	}
	if old, ok := st.consoleAnswers[k]; ok {
		clear(old.value)
	}
	st.consoleAnswers[k] = &consoleAnswer{value: slices.Clone(typed), at: st.s.now()}
	st.answerConsole(t, typed, true)
}

// forgetConsole drops the answers kept for a lock's console (x).
func (st *state) forgetConsole(instance string) {
	for k, a := range st.consoleAnswers {
		if strings.HasPrefix(k, instance+"\x00") {
			clear(a.value)
			delete(st.consoleAnswers, k)
		}
	}
}

// lockConsoles is the header's view of the consoles, by instance.
func (st *state) lockConsoles() []LockConsole {
	out := make([]LockConsole, 0, len(st.consoles)+len(st.s.NotStarted))
	for _, c := range st.consoles {
		out = append(out, *c)
	}
	for _, c := range st.s.NotStarted {
		c.State = ConsoleNotStarted
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b LockConsole) int { return strings.Compare(a.Instance, b.Instance) })
	return out
}
