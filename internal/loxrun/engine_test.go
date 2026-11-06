package loxrun

import (
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
)

func req(kind ticket.Kind, risk ticket.Risk, profile string) Request {
	r := Request{Instance: "shop", Lock: "locksql", V: ticket.VersionKinds, Kind: kind, Risk: risk, Verified: true,
		Subject: &ticket.Subject{Profile: profile}}
	if kind == ticket.KindConnect {
		r.Subject.Endpoint, r.Subject.Credential = "db:5432/shop", ticket.CredentialKeychain
	}
	return r
}

func TestEngineDefaults(t *testing.T) {
	cases := []struct {
		name string
		r    Request
		want Outcome
		rule string
	}{
		{"select", req(ticket.KindRead, ticket.RiskRead, "a"), Approve, "default:read"},
		{"select pii", req(ticket.KindRead, ticket.RiskReadPII, "a"), Approve, "default:read"},
		{"update", req(ticket.KindWrite, ticket.RiskWrite, "a"), Question, "ask:write"},
		{"prod update", req(ticket.KindWrite, ticket.RiskProdWrite, "a"), Question, "ask:write"},
		{"ddl", req(ticket.KindDDL, ticket.RiskWrite, "a"), Question, "ask:ddl"},
		{"policy", req(ticket.KindPolicy, ticket.RiskPolicyLoosen, ""), Question, "ask:policy"},
		{"connect", req(ticket.KindConnect, ticket.RiskRead, "a"), Question, "ask:connect"},
		{"mq peek", req(ticket.KindAction, ticket.RiskRead, "a"), Approve, "default:action"},
		{"mq purge", req(ticket.KindAction, ticket.RiskWrite, "a"), Question, "ask:action"},
		{"endpoint", req(ticket.KindEndpoint, ticket.RiskRead, "a"), Question, "ask:endpoint"},
	}
	for _, c := range cases {
		e := NewEngine(Auto)
		got := e.Decide(c.r)
		if got.Outcome != c.want || got.Rule != c.rule {
			t.Errorf("%s: %+v, want outcome %d rule %s", c.name, got, c.want, c.rule)
		}
	}
}

// A connection is asked once per session per profile: the agent's SELECT
// on A asks for A's connection the first time only; moving to B asks for
// B; an UPDATE on either is always asked.
func TestEngineSessionConnectAndProfileSwitch(t *testing.T) {
	e := NewEngine(Auto)
	ca, cb := req(ticket.KindConnect, ticket.RiskRead, "A"), req(ticket.KindConnect, ticket.RiskRead, "B")
	if v := e.Decide(ca); v.Outcome != Question {
		t.Fatalf("first connect to A: %+v", v)
	}
	e.Answered(ca, true)
	if v := e.Decide(ca); v.Outcome != Approve || v.Rule != "session:connect" {
		t.Fatalf("second connect to A (after an idle close): %+v", v)
	}
	if v := e.Decide(req(ticket.KindRead, ticket.RiskRead, "A")); v.Outcome != Approve {
		t.Fatalf("SELECT on A: %+v", v)
	}
	if v := e.Decide(cb); v.Outcome != Question {
		t.Fatalf("switch to B: %+v (want its own question)", v)
	}
	e.Answered(cb, false)
	if v := e.Decide(cb); v.Outcome != Question {
		t.Fatalf("B denied, then asked again: %+v", v)
	}
	e.Answered(cb, true)
	for _, p := range []string{"A", "B"} {
		if v := e.Decide(req(ticket.KindWrite, ticket.RiskWrite, p)); v.Outcome != Question {
			t.Errorf("UPDATE on %s: %+v (writes always asked)", p, v)
		}
	}
	// The same profile name on another instance is another connection.
	other := ca
	other.Instance = "crm"
	if v := e.Decide(other); v.Outcome != Question {
		t.Errorf("A on another lock: %+v", v)
	}
	e.Forget("shop", "A")
	if v := e.Decide(ca); v.Outcome != Question {
		t.Errorf("after Forget: %+v", v)
	}
}

func TestEngineEndpointOncePerSession(t *testing.T) {
	e := NewEngine(Auto)
	r := req(ticket.KindEndpoint, ticket.RiskRead, "api")
	r.Subject.Endpoint, r.Subject.Verb, r.Subject.Target = "api.example.com", "GET", "/v1/orders"
	if e.Decide(r).Outcome != Question {
		t.Fatal("new endpoint not asked")
	}
	e.Answered(r, true)
	if v := e.Decide(r); v.Outcome != Approve || v.Rule != "session:endpoint" {
		t.Fatalf("seen endpoint: %+v", v)
	}
	r2 := r
	s := *r.Subject
	s.Target = "/v1/users"
	r2.Subject = &s
	if e.Decide(r2).Outcome != Question {
		t.Error("another route not asked")
	}
}

// Manual mode asks every ticket, even what auto approves or the session
// approved already; back in auto, the session's approvals still hold.
func TestEngineManual(t *testing.T) {
	e := NewEngine(Auto)
	c := req(ticket.KindConnect, ticket.RiskRead, "A")
	e.Answered(c, true)
	e.Mode = e.Mode.Toggle()
	if e.Mode != Manual {
		t.Fatal("toggle")
	}
	for _, r := range []Request{c, req(ticket.KindRead, ticket.RiskRead, "A"), req(ticket.KindAction, ticket.RiskRead, "A")} {
		if v := e.Decide(r); v.Outcome != Question {
			t.Errorf("manual %s: %+v", r.Kind, v)
		}
	}
	e.Mode = e.Mode.Toggle()
	if v := e.Decide(c); v.Outcome != Approve {
		t.Errorf("back to auto: %+v", v)
	}
}

// What wants a human is never decided by a rule.
func TestEngineNeverAuto(t *testing.T) {
	e := NewEngine(Auto)
	base := req(ticket.KindRead, ticket.RiskRead, "A")
	for name, mod := range map[string]func(*Request){
		"version 1":  func(r *Request) { r.V, r.Kind, r.Subject = ticket.Version, "", nil },
		"unverified": func(r *Request) { r.Verified = false },
		"never auto": func(r *Request) { r.NeverAuto = true },
		"grant":      func(r *Request) { r.Risk = ticket.RiskGrant },
		"retype":     func(r *Request) { r.Retype = true },
	} {
		r := base
		mod(&r)
		if v := e.Decide(r); v.Outcome != Question {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// Not even a connection the session approved.
	c := req(ticket.KindConnect, ticket.RiskRead, "A")
	e.Answered(c, true)
	c.NeverAuto = true
	if v := e.Decide(c); v.Outcome != Question {
		t.Errorf("never-auto connect: %+v", v)
	}
}

// Profile rules (the lock's per-profile auto mode) change the auto
// defaults only; deny holds in both modes; policy is never auto.
func TestEngineProfileRules(t *testing.T) {
	e := NewEngine(Auto)
	e.Rules = func(instance, profile string) ProfileRules {
		switch profile {
		case "local":
			return ProfileRules{ActConnect: Allow, ActWrite: Allow, ActDDL: Allow, ActPolicy: Allow}
		case "prod":
			return ProfileRules{ActRead: Ask, ActDDL: Deny}
		}
		return nil
	}
	check := func(r Request, out Outcome, rule string) {
		t.Helper()
		if v := e.Decide(r); v.Outcome != out || v.Rule != rule {
			t.Errorf("%s on %s (%s): %+v, want %d %s", r.Kind, r.Profile(), e.Mode, v, out, rule)
		}
	}
	check(req(ticket.KindConnect, ticket.RiskRead, "local"), Approve, "profile:connect")
	check(req(ticket.KindWrite, ticket.RiskWrite, "local"), Approve, "profile:write")
	check(req(ticket.KindRead, ticket.RiskRead, "local"), Approve, "default:read")
	check(req(ticket.KindPolicy, ticket.RiskPolicyLoosen, "local"), Question, "ask:policy")
	check(req(ticket.KindRead, ticket.RiskRead, "prod"), Question, "ask:read")
	check(req(ticket.KindDDL, ticket.RiskWrite, "prod"), Refuse, "deny:ddl")
	e.Mode = Manual
	check(req(ticket.KindWrite, ticket.RiskWrite, "local"), Question, "ask:write")
	check(req(ticket.KindDDL, ticket.RiskWrite, "prod"), Refuse, "deny:ddl")
}
