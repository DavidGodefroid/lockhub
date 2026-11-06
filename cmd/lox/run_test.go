package main

import (
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// lox run's engine takes a locklog lock's applied auto rules for the
// profile its console serves; another of its profiles, or unknown rules,
// ask; the other locks keep the defaults.
func TestProfileRules(t *testing.T) {
	r := profileRules(map[string]*family.LogRules{
		"logs": {Profile: "app", Rules: map[string]string{"read": "auto", "unmask": "deny", "lookup": "ask"}},
		"old":  {Unknown: "no applied plan"},
	})
	if got := r("logs", "app"); got[loxrun.ActRead] != loxrun.Allow || got[loxrun.ActReadPII] != loxrun.Deny {
		t.Errorf("logs/app: %v", got)
	}
	for _, k := range [][2]string{{"logs", "other"}, {"old", ""}, {"old", "app"}} {
		if got := r(k[0], k[1]); got[loxrun.ActRead] != loxrun.Ask || got[loxrun.ActReadPII] != loxrun.Ask {
			t.Errorf("%s/%s: %v", k[0], k[1], got)
		}
	}
	if got := r("crm", "app"); got != nil {
		t.Errorf("another lock: %v", got)
	}
}
