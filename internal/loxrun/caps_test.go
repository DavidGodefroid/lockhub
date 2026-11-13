package loxrun

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// The managed file's [lox] auto_max and production_auto_max cap the
// verdicts: never looser than their action's cap, in AUTO mode; manual
// stays manual.
func TestCapsLowerVerdicts(t *testing.T) {
	e := NewEngine(Auto)
	e.Rules = func(lock, instance, profile string) ProfileRules { return ProfileRules{ActWrite: Allow} }
	write := req(ticket.KindWrite, ticket.RiskWrite, "A")
	if v := e.Decide(write); v.Outcome != Approve {
		t.Fatalf("uncapped write: %+v", v)
	}
	e.Caps = &Caps{Auto: ProfileRules{ActWrite: Ask}}
	if v := e.Decide(write); v.Outcome != Question || v.Tag != "ask:managed" || !strings.Contains(v.Why, "lox.auto_max.write = ask") {
		t.Errorf("capped write: %+v", v)
	}
	// A default that allows is capped too.
	e.Rules = nil
	e.Caps = &Caps{Auto: ProfileRules{ActRead: Deny}}
	if v := e.Decide(req(ticket.KindRead, ticket.RiskRead, "A")); v.Outcome != Refuse || !strings.Contains(v.Why, "blocked by company policy: lox.auto_max.read = deny") {
		t.Errorf("capped read: %+v", v)
	}

	// production_auto_max: a production read is asked, another read is not.
	e.Caps = &Caps{Production: ProfileRules{ActRead: Ask}}
	read := req(ticket.KindRead, ticket.RiskRead, "A")
	if v := e.Decide(read); v.Outcome != Approve {
		t.Errorf("non-production read: %+v", v)
	}
	read.Production = true
	if v := e.Decide(read); v.Outcome != Question || !strings.Contains(v.Why, "lox.production_auto_max.read = ask") {
		t.Errorf("production read: %+v", v)
	}
	// Both set: the stricter wins.
	e.Caps = &Caps{Auto: ProfileRules{ActRead: Deny}, Production: ProfileRules{ActRead: Ask}}
	if v := e.Decide(read); v.Outcome != Refuse {
		t.Errorf("production read under both: %+v", v)
	}
	// A cap never loosens: an ask stays asked under auto.
	e.Caps = &Caps{Auto: ProfileRules{ActDDL: Allow}}
	if v := e.Decide(req(ticket.KindDDL, ticket.RiskWrite, "A")); v.Outcome != Question || v.Tag == "ask:managed" {
		t.Errorf("ddl under an auto cap: %+v", v)
	}

	// Manual mode is unaffected: asked, as before.
	m := NewEngine(Manual)
	m.Caps = &Caps{Auto: ProfileRules{ActWrite: Ask}}
	if v := m.Decide(write); v.Outcome != Question || v.Tag != "ask:manual" {
		t.Errorf("manual: %+v", v)
	}
}

// A session approval of a connection holds under an ask cap, not under a
// deny.
func TestCapsSession(t *testing.T) {
	e := NewEngine(Auto)
	e.Caps = &Caps{Auto: ProfileRules{ActConnect: Ask}}
	c := req(ticket.KindConnect, ticket.RiskRead, "A")
	if v := e.Decide(c); v.Outcome != Question {
		t.Fatalf("first connect: %+v", v)
	}
	e.Answered(c, true)
	if v := e.Decide(c); v.Outcome != Approve {
		t.Errorf("approved connect: %+v", v)
	}
	e.Caps = &Caps{Auto: ProfileRules{ActConnect: Deny}}
	if v := e.Decide(c); v.Outcome != Refuse {
		t.Errorf("denied connect: %+v", v)
	}
}
