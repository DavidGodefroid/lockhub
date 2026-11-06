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
// screen.
type Verdict struct {
	Outcome Outcome
	Rule    string
	Why     string
}

// Engine is the decision engine of one lox run session: the mode, the
// profile rules, and what the human approved once for the session
// (connections, endpoints). It is not safe for concurrent use.
type Engine struct {
	Mode Mode
	// Rules returns the rules of a profile (nil: Defaults alone).
	Rules func(instance, profile string) ProfileRules

	connected map[string]bool // instance/profile: connection approved this session
	endpoints map[string]bool // instance/profile/endpoint/target: reached this session
}

// NewEngine is an engine in mode m, with the defaults.
func NewEngine(m Mode) *Engine {
	return &Engine{Mode: m, connected: map[string]bool{}, endpoints: map[string]bool{}}
}

func (e *Engine) rule(r Request, a Action) Value {
	if e.Rules != nil {
		if v, ok := e.Rules(r.Instance, r.Profile())[a]; ok {
			return v
		}
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
func (e *Engine) Decide(r Request) Verdict {
	a := r.Action()
	v := e.rule(r, a)
	if a == ActPolicy && v == Allow {
		v = Ask // a loosening of the policy is the human's, always
	}
	if v == Deny && r.V >= ticket.VersionKinds && r.Verified {
		return Verdict{Outcome: Refuse, Rule: "deny:" + string(a), Why: fmt.Sprintf("the profile denies %s", a)}
	}
	ask := func(why string) Verdict { return Verdict{Outcome: Question, Rule: "ask:" + string(a), Why: why} }
	switch {
	case e.Mode == Manual:
		return ask("manual mode: every ticket is asked")
	case r.V < ticket.VersionKinds:
		return ask("this lock's ticket does not name its kind (version 1): asked")
	case !r.Verified:
		return ask("the ticket was not checked under the lock key lox up pinned: asked")
	case r.NeverAuto || r.Risk == ticket.RiskGrant:
		return ask("the lock wants a human for this ticket")
	case r.Retype:
		return ask("approving it needs the instance name typed")
	}
	switch v {
	case Allow:
		return Verdict{Outcome: Approve, Rule: autoRule(e, r, a), Why: "auto: " + string(a)}
	case Ask:
		switch a {
		case ActConnect:
			if e.connected[sessionKey(r)] {
				return Verdict{Outcome: Approve, Rule: "session:connect", Why: "connection approved earlier in this session"}
			}
			return ask("first connection to this profile in this session")
		case ActEndpoint:
			if e.endpoints[endpointKey(r)] {
				return Verdict{Outcome: Approve, Rule: "session:endpoint", Why: "endpoint approved earlier in this session"}
			}
			return ask("new endpoint in this session")
		}
	}
	return ask(string(a) + " is always asked")
}

// autoRule names the rule of an auto approval: the profile's own rule
// when it set the action, the default otherwise.
func autoRule(e *Engine, r Request, a Action) string {
	if e.Rules != nil {
		if _, ok := e.Rules(r.Instance, r.Profile())[a]; ok {
			return "profile:" + string(a)
		}
	}
	return "default:" + string(a)
}

// Answered records the human's answer on r: an approved connection or
// endpoint is not asked again in this session (in auto mode).
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

// Connected reports whether the session approved profile's connection.
func (e *Engine) Connected(instance, profile string) bool {
	return e.connected[instance+"/"+profile]
}
