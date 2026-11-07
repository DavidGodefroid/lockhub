package loxrun

import (
	"strings"
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
	e.Rules = func(_, instance, profile string) ProfileRules {
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

// A locklog profile's auto rules: read for its scans (risk read), the
// stricter of unmask and lookup for its read-pii tickets, which name no
// other action; a ticket the console signed never-auto is asked whatever
// they say.
func TestEngineLocklogRules(t *testing.T) {
	rules := map[string]map[string]string{
		"app":  {"read": "auto", "unmask": "auto", "lookup": "ask"},
		"prod": {"read": "ask", "unmask": "deny", "lookup": "auto"},
		"odd":  {"read": "yes"},
	}
	e := NewEngine(Auto)
	e.Rules = func(_, instance, profile string) ProfileRules {
		if instance != "logs" {
			return nil
		}
		r, ok := rules[profile]
		if !ok {
			return nil
		}
		return LocklogRules(func(a string) string { return r[a] })
	}
	lr := func(risk ticket.Risk, profile string) Request {
		r := req(ticket.KindRead, risk, profile)
		r.Instance, r.Lock = "logs", "locklog"
		return r
	}
	cases := []struct {
		name string
		r    Request
		want Outcome
		rule string
	}{
		{"app scan", lr(ticket.RiskRead, "app"), Approve, "profile:read"},
		{"app unmask (lookup ask is stricter)", lr(ticket.RiskReadPII, "app"), Question, "ask:read-pii"},
		{"prod scan", lr(ticket.RiskRead, "prod"), Question, "ask:read"},
		{"prod unmask denied", lr(ticket.RiskReadPII, "prod"), Refuse, "deny:read-pii"},
		{"unknown value asks", lr(ticket.RiskRead, "odd"), Question, "ask:read"},
		{"odd read-pii asks", lr(ticket.RiskReadPII, "odd"), Question, "ask:read-pii"},
		// A locklog profile with no rules fails closed: its reads are
		// asked; another lock's read-pii read is ruled as read.
		{"no rules", lr(ticket.RiskRead, "other"), Question, "ask:read"},
		{"no rules read-pii", lr(ticket.RiskReadPII, "other"), Question, "ask:read-pii"},
		{"locksql pii", req(ticket.KindRead, ticket.RiskReadPII, "app"), Approve, "default:read"},
	}
	for _, c := range cases {
		got := e.Decide(c.r)
		if got.Outcome != c.want || got.Rule != c.rule {
			t.Errorf("%s: %+v, want outcome %d rule %s", c.name, got, c.want, c.rule)
		}
	}
	never := lr(ticket.RiskRead, "app")
	never.NeverAuto = true
	if v := e.Decide(never); v.Outcome != Question {
		t.Errorf("never-auto scan: %+v", v)
	}
	unknown := lr(ticket.RiskRead, "app")
	unknown.Instance = "gone"
	if v := e.Decide(unknown); v.Outcome != Question || v.Rule != "ask:read" {
		t.Errorf("unknown instance: %+v", v)
	}
	if r := LocklogRules(func(string) string { return "" }); r[ActRead] != Ask || r[ActReadPII] != Ask {
		t.Errorf("empty rules: %v", r)
	}
}

// A locklog ticket whose rules are unknown is asked, never auto: with no
// Rules at all (lox run could not read the lock file), with Rules that
// know nothing of its instance, or with rules that leave read or
// read-pii out, for read and read-pii alike; connect keeps its default,
// and another lock's reads stay auto.
func TestEngineLocklogUnknownRulesAsk(t *testing.T) {
	lr := func(risk ticket.Risk) Request {
		r := req(ticket.KindRead, risk, "app")
		r.Instance, r.Lock = "logs", LockLocklog
		return r
	}
	rules := map[string]func(lock, instance, profile string) ProfileRules{
		"no rules":       nil,
		"other instance": func(_, instance, _ string) ProfileRules { return nil },
		"empty":          func(string, string, string) ProfileRules { return ProfileRules{} },
		"connect only":   func(string, string, string) ProfileRules { return ProfileRules{ActConnect: Allow} },
	}
	for name, f := range rules {
		e := NewEngine(Auto)
		e.Rules = f
		if v := e.Decide(lr(ticket.RiskRead)); v.Outcome != Question || v.Rule != "ask:read" {
			t.Errorf("%s: read %+v", name, v)
		}
		if v := e.Decide(lr(ticket.RiskReadPII)); v.Outcome != Question || v.Rule != "ask:read-pii" {
			t.Errorf("%s: read-pii %+v", name, v)
		}
		c := lr(ticket.RiskRead)
		c.Kind = ticket.KindConnect
		if v := e.Decide(c); name != "connect only" && (v.Outcome != Question || v.Rule != "ask:connect") {
			t.Errorf("%s: connect %+v", name, v)
		}
		sql := req(ticket.KindRead, ticket.RiskReadPII, "app")
		if v := e.Decide(sql); v.Outcome != Approve {
			t.Errorf("%s: locksql read %+v", name, v)
		}
	}
	e := NewEngine(Auto)
	e.Rules = func(string, string, string) ProfileRules { return ProfileRules{ActConnect: Allow} }
	c := lr(ticket.RiskRead)
	c.Kind = ticket.KindConnect
	if v := e.Decide(c); v.Outcome != Approve || v.Rule != "profile:connect" {
		t.Errorf("a locklog rule set is kept: %+v", v)
	}
}

// Production does not turn reads into questions (#149): in auto mode a
// production read is approved by default:read as any read; writes, DDL,
// unmasked reads (never-auto), grants and a typed name stay asked, and
// the connection is asked once per session. A read is asked only when
// the lock marks it never-auto (its profile's auto rule for reads is
// ask), and the question says so. Manual mode asks all.
func TestEngineProduction(t *testing.T) {
	prod := func(kind ticket.Kind, risk ticket.Risk) Request {
		r := req(kind, risk, "shop-prod")
		r.Production = true
		return r
	}
	never := func(r Request) Request { r.NeverAuto = true; return r }
	retype := func(r Request) Request { r.Retype = true; return r }
	cases := []struct {
		name string
		r    Request
		want Outcome
		rule string
		why  string
	}{
		{"select", prod(ticket.KindRead, ticket.RiskRead), Approve, "default:read", "auto: read"},
		{"select touching pii (masked)", prod(ticket.KindRead, ticket.RiskReadPII), Approve, "default:read", "auto: read"},
		{"update", prod(ticket.KindWrite, ticket.RiskProdWrite), Question, "ask:write", "write is always asked"},
		{"update never-auto", never(prod(ticket.KindWrite, ticket.RiskProdWrite)), Question, "ask:write", "auto rule for it is not auto"},
		{"ddl", prod(ticket.KindDDL, ticket.RiskProdWrite), Question, "ask:ddl", "ddl is always asked"},
		{"unmask", never(prod(ticket.KindRead, ticket.RiskReadPII)), Question, "ask:read", "human for this read"},
		{"read = ask", never(prod(ticket.KindRead, ticket.RiskRead)), Question, "ask:read", "its profile's auto rule for it is not auto"},
		{"grant", never(prod(ticket.KindRead, ticket.RiskGrant)), Question, "ask:read", "a grant is always the human's"},
		{"typed name", retype(prod(ticket.KindRead, ticket.RiskRead)), Question, "ask:read", "instance name typed"},
		{"policy", prod(ticket.KindPolicy, ticket.RiskPolicyLoosen), Question, "ask:policy", "policy is always asked"},
		{"connect", prod(ticket.KindConnect, ticket.RiskProdWrite), Question, "ask:connect", "first connection"},
	}
	for _, c := range cases {
		e := NewEngine(Auto)
		got := e.Decide(c.r)
		if got.Outcome != c.want || got.Rule != c.rule || !strings.Contains(got.Why, c.why) {
			t.Errorf("%s: %+v, want outcome %d rule %s why ~%q", c.name, got, c.want, c.rule, c.why)
		}
		// The same ticket off production is decided the same way.
		off := c.r
		off.Production = false
		if o := e.Decide(off); o != got && c.r.Kind != ticket.KindConnect {
			t.Errorf("%s: %+v off production, %+v on it", c.name, o, got)
		}
		if m := NewEngine(Manual).Decide(c.r); m.Outcome != Question {
			t.Errorf("%s in manual mode: %+v", c.name, m)
		}
	}

	// The connection: asked once per session, then session:connect.
	e := NewEngine(Auto)
	c := prod(ticket.KindConnect, ticket.RiskProdWrite)
	if v := e.Decide(c); v.Outcome != Question {
		t.Fatalf("first production connect: %+v", v)
	}
	e.Answered(c, true)
	if v := e.Decide(c); v.Outcome != Approve || v.Rule != "session:connect" {
		t.Fatalf("production reconnect: %+v", v)
	}
}
