// Package loxrun is `lox run`: the terminal, outside any agent harness,
// that serves the hub's decisions in the foreground. It follows the hub's
// queue over the host facade socket, shows every ticket (masked by its
// lock) and every decision live, approves on its own what the auto mode
// allows (Engine), and asks the human the rest in a question card.
//
// The flow it serves: agent -> lock (socket) -> hub (masked ticket) ->
// lox run -> hub (signed decision) -> lock -> agent. lox run never sees a
// request or a result in clear: only what the lock put on the ticket.
package loxrun

import (
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// Mode is how lox run decides.
type Mode int

const (
	// Auto: the auto rules decide what they allow, the human the rest.
	Auto Mode = iota
	// Manual: every ticket is asked.
	Manual
)

func (m Mode) String() string {
	if m == Manual {
		return "MANUAL"
	}
	return "AUTO"
}

// Toggle is the other mode (Shift+Tab).
func (m Mode) Toggle() Mode {
	if m == Auto {
		return Manual
	}
	return Auto
}

// Action is what a profile rule rules on: a ticket kind, in the words of
// locksql's per-profile auto mode (locksql#185).
type Action string

// Actions.
const (
	ActConnect  Action = "connect"
	ActRead     Action = "read"
	ActWrite    Action = "write"
	ActDDL      Action = "ddl"
	ActAction   Action = "action"
	ActEndpoint Action = "endpoint"
	ActPolicy   Action = "policy"
	// ActReadPII is a read of risk read-pii (a locklog unmask or approved
	// lookup): a profile rule for it takes the place of read's for such
	// a ticket. With none, a read-pii read is ruled as read.
	ActReadPII Action = "read-pii"
)

// Value is a profile rule's answer for an action.
type Value string

// Values.
const (
	// Allow: decided by the rule, no question.
	Allow Value = "auto"
	// Ask: asked (once per session for connect and endpoint, every time
	// otherwise).
	Ask Value = "ask"
	// Deny: refused, even when asked.
	Deny Value = "deny"
)

// ProfileRules shape the auto mode of one profile: an action left out
// keeps its default (Defaults). They only change the auto mode: manual
// asks everything a rule does not deny. A lock defines them (locksql,
// lockmq per-profile auto mode) and lox run applies them.
type ProfileRules map[Action]Value

// Defaults are the auto mode's defaults, per action. Connect and endpoint
// are asked once per lox run session; write, ddl and policy every time;
// an action as its risk says (reads auto, the rest asked).
var Defaults = ProfileRules{
	ActConnect:  Ask,
	ActRead:     Allow,
	ActWrite:    Ask,
	ActDDL:      Ask,
	ActEndpoint: Ask,
	ActPolicy:   Ask,
}

// Request is what the engine rules on: a ticket, as its lock signed it.
type Request struct {
	Instance string
	// Lock is the product (locksql, lockmq, lockfile, lockhttp).
	Lock string
	// V is the ticket's schema version: only a version-2 ticket names
	// its kind, so only it is decided by a rule.
	V    int
	Kind ticket.Kind
	Risk ticket.Risk
	// Subject is the version-2 ticket's structured request (nil: none).
	Subject *ticket.Subject
	// NeverAuto and Production are the ticket's flags; Retype: approving
	// needs the instance name typed (the hub's rule).
	NeverAuto, Production, Retype bool
	// Verified: lox run checked the ticket under the lock key lox up
	// pinned. An unverified ticket is never decided by a rule.
	Verified bool
}

// Profile is the request's profile ("" when it names none).
func (r Request) Profile() string {
	if r.Subject == nil {
		return ""
	}
	return r.Subject.Profile
}

// inputsWhy is why a ticket that asks for typed values is asked.
const inputsWhy = "asks for typed values: a human decides"

// AsksInputs reports whether the request asks the human for typed values
// (Subject.Inputs).
func (r Request) AsksInputs() bool { return r.Subject != nil && len(r.Subject.Inputs) > 0 }

// verb is the request's verb ("" when it names none).
func (r Request) verb() string {
	if r.Subject == nil {
		return ""
	}
	return r.Subject.Verb
}

// Action is the request's profile action.
func (r Request) Action() Action {
	switch r.Kind {
	case ticket.KindConnect:
		return ActConnect
	case ticket.KindRead:
		return ActRead
	case ticket.KindWrite:
		return ActWrite
	case ticket.KindDDL:
		return ActDDL
	case ticket.KindAction:
		return ActAction
	case ticket.KindEndpoint:
		return ActEndpoint
	}
	return ActPolicy
}

// readRisk: a risk class that only reads.
func readRisk(r ticket.Risk) bool { return r == ticket.RiskRead || r == ticket.RiskReadPII }

// Outcome is the engine's answer.
type Outcome int

const (
	// Question: the human answers.
	Question Outcome = iota
	// Approve: a rule approves (Verdict.Rule).
	Approve
	// Refuse: a rule denies (Verdict.Rule).
	Refuse
)

// Verdict is the engine's answer for one request: Rule names the rule
// that decided (the decision carries it, for the lock's audit), or, for a
// question, the default that sends it to the human; Why is for the
// screen; Tag is Why in a word, for the feed's decision column
// (auto:read, ask:write, ask:lock).
type Verdict struct {
	Outcome Outcome
	Rule    string
	Why     string
	Tag     string
}

// Engine is the decision engine of one lox run session: the mode, the
// profile rules, and what the human approved once for the session
// (connections, endpoints). It is not safe for concurrent use.
type Engine struct {
	Mode Mode
	// Rules returns the rules of a profile of a lock (lock is the
	// product the ticket names, Request.Lock; nil: Defaults alone). A
	// locklog profile with no known rules asks its reads (rulesOf).
	Rules func(lock, instance, profile string) ProfileRules
	// Caps are the company's ceilings on the verdicts (nil: none).
	Caps *Caps

	connected map[string]bool // instance/profile: connection approved this session
	endpoints map[string]bool // instance/profile/endpoint/target: reached this session
}

// Caps are the managed file's ceilings on the engine's verdicts ([lox]
// auto_max and production_auto_max): a rule, a default or a session
// approval never decides more loosely than its action's cap. They only
// make a decision stricter, so the ticket's production flag is trusted
// for them.
type Caps struct {
	// Auto caps every ticket; Production a production ticket, with Auto
	// (the stricter wins).
	Auto, Production ProfileRules
}

var valueRank = map[Value]int{Deny: 0, Ask: 1, Allow: 2}

// capOf is the strictest cap on r for its actions a and ra, and the
// managed key that sets it ("" when none caps it).
func (c *Caps) capOf(r Request, a, ra Action) (Value, string) {
	if c == nil {
		return Allow, ""
	}
	v, key := Allow, ""
	try := func(m ProfileRules, table string) {
		for _, x := range []Action{a, ra} {
			if cv, ok := m[x]; ok && valueRank[cv] < valueRank[v] {
				v, key = cv, fmt.Sprintf("lox.%s.%s = %s", table, x, cv)
			}
		}
	}
	try(c.Auto, "auto_max")
	if r.Production {
		try(c.Production, "production_auto_max")
	}
	return v, key
}

// NewEngine is an engine in mode m, with the defaults.
func NewEngine(m Mode) *Engine {
	return &Engine{Mode: m, connected: map[string]bool{}, endpoints: map[string]bool{}}
}

// ruleAction is the action of r a profile rule decides: read-pii for a
// read of risk read-pii whose profile has a rule for it, else a.
func (e *Engine) ruleAction(r Request, a Action) Action {
	if r.Lock == LockLockssh && a == ActAction {
		// lockssh's actions by verb: run an allow-listed command (a
		// read), exec another (a write), unmask a run's output (read-pii).
		switch r.verb() {
		case "run":
			return ActRead
		case "exec":
			return ActWrite
		case "unmask":
			return ActReadPII
		}
		return a
	}
	if a == ActRead && r.Risk == ticket.RiskReadPII {
		if _, ok := e.rulesOf(r)[ActReadPII]; ok {
			return ActReadPII
		}
	}
	return a
}

func (e *Engine) rule(r Request, a Action) Value {
	if v, ok := e.rulesOf(r)[e.ruleAction(r, a)]; ok {
		return v
	}
	if a == ActAction {
		if readRisk(r.Risk) {
			return Allow
		}
		return Ask
	}
	return Defaults[a]
}

func sessionKey(r Request) string { return r.Instance + "/" + r.Profile() }

func endpointKey(r Request) string {
	s := r.Subject
	if s == nil {
		return sessionKey(r)
	}
	return sessionKey(r) + "/" + s.Endpoint + "/" + s.Target
}

// Decide rules on r. A rule decides only a version-2 ticket that lox run
// verified and that does not want a human (never-auto, a typed name); a
// deny rule holds in both modes; manual asks the rest.
//
// Production plays no part here (#149): a read of a production profile
// is decided as a read of any other profile, by default:read in auto
// mode. Production shows (the banner, the red frame) and keeps its
// writes asked by their own rules; a production read is asked only when
// its lock says so, by marking the ticket never-auto (its profile's auto
// rule for reads is ask) or asking the instance name typed.
func (e *Engine) Decide(r Request) Verdict {
	a := r.Action()
	ra := e.ruleAction(r, a) // the action named in the rule
	v := e.rule(r, a)
	if a == ActPolicy && v == Allow {
		v = Ask // a loosening of the policy is the human's, always
	}
	if r.Lock == LockLockssh && v == Allow && (ra == ActReadPII && a == ActAction || r.Risk == ticket.RiskProdWrite) {
		// lockssh: output in clear is never auto, nor a write on
		// production, whatever a rule says (the console signs both
		// never-auto anyway).
		v = Ask
	}
	// The company's ceiling: never looser than its action's cap.
	capped := ""
	if cv, key := e.Caps.capOf(r, a, ra); key != "" && valueRank[cv] < valueRank[v] {
		v, capped = cv, key
	}
	if r.AsksInputs() {
		// Typed values are the human's to type: no rule decides, not
		// even a deny (lockkit marks such a ticket NeverAuto too).
		return Verdict{Outcome: Question, Rule: "ask:" + string(ra), Why: inputsWhy, Tag: "ask:inputs"}
	}
	if v == Deny && r.V >= ticket.VersionKinds && r.Verified {
		if capped != "" {
			return Verdict{Outcome: Refuse, Rule: "deny:" + string(ra), Why: "blocked by company policy: " + capped, Tag: "deny:managed"}
		}
		return Verdict{Outcome: Refuse, Rule: "deny:" + string(ra), Why: fmt.Sprintf("the profile denies %s", ra), Tag: "deny:" + string(ra)}
	}
	ask := func(tag, why string) Verdict {
		return Verdict{Outcome: Question, Rule: "ask:" + string(ra), Why: why, Tag: "ask:" + tag}
	}
	switch {
	case e.Mode == Manual:
		return ask("manual", "manual mode: every ticket is asked")
	case r.V < ticket.VersionKinds:
		return ask("v1", "this lock's ticket does not name its kind (version 1): asked")
	case !r.Verified:
		return ask("unsigned", "the ticket was not checked under the pinned lock key: asked")
	case r.Risk == ticket.RiskGrant:
		return ask("grant", "a grant is always the human's")
	case r.NeverAuto:
		return ask("lock", fmt.Sprintf("the lock wants a human for this %s: its profile's auto rule for it is not auto", ra))
	case r.Retype:
		return ask("name", "approving it needs the instance name typed")
	}
	switch v {
	case Allow:
		return Verdict{Outcome: Approve, Rule: autoRule(e, r, a), Why: "auto: " + string(a), Tag: "auto:" + string(ra)}
	case Ask:
		session := Verdict{Outcome: Approve, Tag: "auto:session"}
		switch a {
		case ActConnect:
			if e.connected[sessionKey(r)] {
				session.Rule, session.Why = "session:connect", "connection approved earlier in this session"
				return session
			}
			return ask(string(ra), "first connection to this profile in this session")
		case ActEndpoint:
			if e.endpoints[endpointKey(r)] {
				session.Rule, session.Why = "session:endpoint", "endpoint approved earlier in this session"
				return session
			}
			return ask(string(ra), "new endpoint in this session")
		}
	}
	if capped != "" {
		return ask("managed", "company policy: "+capped)
	}
	return ask(string(ra), string(ra)+" is always asked")
}

// autoRule names the rule of an auto approval: the profile's own rule
// when it set the action, the default otherwise.
func autoRule(e *Engine, r Request, a Action) string {
	ra := e.ruleAction(r, a)
	if _, ok := e.rulesOf(r)[ra]; ok {
		return "profile:" + string(ra)
	}
	return "default:" + string(a)
}

// LockLocklog and LockLockssh are locklog's and lockssh's product names,
// as their tickets name their lock (Request.Lock).
const (
	LockLocklog = "locklog"
	LockLockssh = "lockssh"
)

// rulesOf are the rules of r's profile. A locklog ticket fails closed:
// the engine's defaults auto-approve reads, which for locklog would cover
// its scans and its read-pii unmasks and lookups, so a locklog profile
// whose rules are unknown (no Rules, an instance or profile lox run has
// no applied rules for, a rule left out) asks its read and read-pii. A
// lockssh ticket fails closed the same way, for each of its actions.
func (e *Engine) rulesOf(r Request) ProfileRules {
	var p ProfileRules
	if e.Rules != nil {
		p = e.Rules(r.Lock, r.Instance, r.Profile())
	}
	var out ProfileRules
	switch r.Lock {
	case LockLocklog:
		out = ProfileRules{ActRead: Ask, ActReadPII: Ask}
	case LockLockssh:
		// Every lockssh action asked when its rules are unknown: the
		// engine's defaults would approve its runs, unmasks and any verb
		// it does not know as reads.
		out = ProfileRules{ActConnect: Ask, ActRead: Ask, ActWrite: Ask, ActReadPII: Ask, ActAction: Ask}
	default:
		return p
	}
	for k, v := range p {
		out[k] = v
	}
	return out
}

// LocklogRules are the engine's rules for a locklog profile whose auto
// rules (`locklog profile rules`) give get(action) for its actions read
// (an approved scan, risk read), unmask and lookup (both risk read-pii,
// which a ticket does not tell apart: the stricter of the two). A value
// that is not auto, ask or deny is ask.
func LocklogRules(get func(action string) string) ProfileRules {
	val := func(a string) Value {
		switch v := Value(get(a)); v {
		case Allow, Ask, Deny:
			return v
		}
		return Ask
	}
	rank := map[Value]int{Deny: 0, Ask: 1, Allow: 2}
	pii := val("unmask")
	if l := val("lookup"); rank[l] < rank[pii] {
		pii = l
	}
	return ProfileRules{ActRead: val("read"), ActReadPII: pii}
}

// SSHRules are the engine's rules for a lockssh profile whose auto rules
// (`lockssh profile rules`) give get(action) for its actions connect,
// run (an allow-listed command, risk read), exec (another command, risk
// write) and unmask (a run's output in clear, risk read-pii: never auto).
// A value that is not auto, ask or deny is ask.
func SSHRules(get func(action string) string) ProfileRules {
	val := func(a string) Value {
		switch v := Value(get(a)); v {
		case Allow, Ask, Deny:
			return v
		}
		return Ask
	}
	unmask := val("unmask")
	if unmask == Allow {
		unmask = Ask
	}
	return ProfileRules{ActConnect: val("connect"), ActRead: val("run"), ActWrite: val("exec"), ActReadPII: unmask}
}

// Answered records the human's answer on r: an approved connection or
// endpoint is not asked again in this session (in auto mode). lox run
// records a connection only once the lock connected on it.
func (e *Engine) Answered(r Request, approved bool) {
	if !approved {
		return
	}
	switch r.Action() {
	case ActConnect:
		e.connected[sessionKey(r)] = true
	case ActEndpoint:
		e.endpoints[endpointKey(r)] = true
	}
}

// Forget drops what the session approved for a profile (its connection
// and endpoints): the next ticket asks again.
func (e *Engine) Forget(instance, profile string) {
	k := instance + "/" + profile
	delete(e.connected, k)
	for ek := range e.endpoints {
		if strings.HasPrefix(ek, k+"/") {
			delete(e.endpoints, ek)
		}
	}
}

// ForgetAll drops what the session approved for every profile.
func (e *Engine) ForgetAll() {
	clear(e.connected)
	clear(e.endpoints)
}

// Disconnect drops the session's approval of profile's connection alone
// (a connect approved on it did not connect): the next one asks again.
func (e *Engine) Disconnect(instance, profile string) {
	delete(e.connected, instance+"/"+profile)
}

// Connected reports whether the session approved profile's connection.
func (e *Engine) Connected(instance, profile string) bool {
	return e.connected[instance+"/"+profile]
}
