package main

import (
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// lox run's engine takes a locklog lock's applied auto rules for the
// profile its console serves; another of its profiles, unknown rules, or
// an instance with no rules at all ask; the other locks keep the
// defaults, even on an instance named like a locklog one.
func TestProfileRules(t *testing.T) {
	r := profileRules(map[string]*family.LogRules{
		"logs": {Profile: "app", Rules: map[string]string{"read": "auto", "unmask": "deny", "lookup": "ask"}},
		"old":  {Unknown: "no applied plan"},
	}, nil)
	if got := r("locklog", "logs", "app"); got[loxrun.ActRead] != loxrun.Allow || got[loxrun.ActReadPII] != loxrun.Deny {
		t.Errorf("logs/app: %v", got)
	}
	for _, k := range [][2]string{{"logs", "other"}, {"old", ""}, {"old", "app"}, {"missing", "app"}} {
		e := loxrun.NewEngine(loxrun.Auto)
		e.Rules = r
		for _, risk := range []ticket.Risk{ticket.RiskRead, ticket.RiskReadPII} {
			req := loxrun.Request{Instance: k[0], Lock: "locklog", V: ticket.VersionKinds, Kind: ticket.KindRead, Risk: risk,
				Subject: &ticket.Subject{Profile: k[1]}, Verified: true}
			if v := e.Decide(req); v.Outcome != loxrun.Question {
				t.Errorf("%s/%s %s: %+v", k[0], k[1], risk, v)
			}
		}
	}
	for _, k := range [][2]string{{"locksql", "crm"}, {"locksql", "logs"}} {
		if got := r(k[0], k[1], "app"); got != nil {
			t.Errorf("%s on %s: %v", k[0], k[1], got)
		}
	}
	// The lock file did not load: no rules, and a locklog read is asked.
	e := loxrun.NewEngine(loxrun.Auto)
	if v := e.Decide(loxrun.Request{Instance: "logs", Lock: "locklog", V: ticket.VersionKinds, Kind: ticket.KindRead,
		Risk: ticket.RiskReadPII, Subject: &ticket.Subject{Profile: "app"}, Verified: true}); v.Outcome != loxrun.Question {
		t.Errorf("no lock file: %+v", v)
	}
}

// A lockssh lock's applied rules decide its tickets by verb, for their
// profile; unknown rules, another profile or no rules at all ask every
// action; unmask and a production exec are never auto.
func TestProfileRulesLockssh(t *testing.T) {
	r := profileRules(nil, map[string]map[string]*family.LogRules{
		"web": {"prod": {Lock: "lockssh", Profile: "prod", Rules: map[string]string{"connect": "auto", "run": "auto", "exec": "auto", "unmask": "auto"}}},
		"old": {"": {Lock: "lockssh", Unknown: "lockssh profile rules failed"}},
	})
	decide := func(inst, profile string, kind ticket.Kind, risk ticket.Risk, verb string) loxrun.Verdict {
		e := loxrun.NewEngine(loxrun.Auto)
		e.Rules = r
		return e.Decide(loxrun.Request{Instance: inst, Lock: "lockssh", V: ticket.VersionKinds, Kind: kind, Risk: risk,
			Subject: &ticket.Subject{Profile: profile, Verb: verb}, Verified: true})
	}
	for _, c := range []struct {
		kind ticket.Kind
		risk ticket.Risk
		verb string
		want loxrun.Outcome
	}{
		{ticket.KindConnect, ticket.RiskReadPII, "", loxrun.Approve},
		{ticket.KindAction, ticket.RiskRead, "run", loxrun.Approve},
		{ticket.KindAction, ticket.RiskWrite, "exec", loxrun.Approve},
		{ticket.KindAction, ticket.RiskProdWrite, "exec", loxrun.Question},
		{ticket.KindAction, ticket.RiskReadPII, "unmask", loxrun.Question},
		{ticket.KindAction, ticket.RiskRead, "upload", loxrun.Question},
	} {
		if v := decide("web", "prod", c.kind, c.risk, c.verb); v.Outcome != c.want {
			t.Errorf("web/prod %s %s: %+v", c.kind, c.verb, v)
		}
	}
	for _, k := range [][2]string{{"web", "other"}, {"old", ""}, {"old", "prod"}, {"missing", "prod"}} {
		for _, verb := range []string{"run", "unmask"} {
			if v := decide(k[0], k[1], ticket.KindAction, ticket.RiskRead, verb); v.Outcome != loxrun.Question {
				t.Errorf("%s/%s %s: %+v", k[0], k[1], verb, v)
			}
		}
		if v := decide(k[0], k[1], ticket.KindConnect, ticket.RiskReadPII, ""); v.Outcome != loxrun.Question {
			t.Errorf("%s/%s connect: %+v", k[0], k[1], v)
		}
	}
	// A deny holds.
	r = profileRules(nil, map[string]map[string]*family.LogRules{
		"web": {"dev": {Lock: "lockssh", Profile: "dev", Rules: map[string]string{"connect": "ask", "run": "auto", "exec": "deny", "unmask": "ask"}}},
	})
	if v := decide("web", "dev", ticket.KindAction, ticket.RiskWrite, "exec"); v.Outcome != loxrun.Refuse {
		t.Errorf("exec denied: %+v", v)
	}
}
