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
	})
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
