package loxaudit

import (
	"time"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// Record is an exchange as lox audit --json writes it (one JSON object
// per line): the same fields as the listing, never a value in clear.
type Record struct {
	ID         string     `json:"id"`
	At         time.Time  `json:"at"`
	Agent      string     `json:"agent"`
	Instance   string     `json:"instance"`
	Lock       string     `json:"lock"`
	Profile    string     `json:"profile,omitempty"`
	Kind       string     `json:"kind"`
	Risk       string     `json:"risk,omitempty"`
	Production bool       `json:"production,omitempty"`
	Write      bool       `json:"write,omitempty"`
	Request    string     `json:"request"`
	Decision   string     `json:"decision"`
	Rule       string     `json:"rule,omitempty"`
	Facade     string     `json:"facade,omitempty"`
	Approver   string     `json:"approver,omitempty"`
	State      string     `json:"state"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	// DecideMS is the time from the ticket to its decision.
	DecideMS  *int64 `json:"decide_ms,omitempty"`
	Signature string `json:"signature"`
	SigNote   string `json:"signature_note,omitempty"`
	// The masked screen: lox audit show --json only.
	Header   string   `json:"header,omitempty"`
	Body     []string `json:"body,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Touched  []string `json:"touched,omitempty"`
}

// RecordOf is x as a Record; detail adds the masked screen.
func RecordOf(x loxrun.Exchange, detail bool) Record {
	r := Record{ID: x.ID, At: x.At.UTC(), Agent: x.Agent, Instance: x.Instance, Lock: x.Lock, Profile: x.Profile,
		Kind: string(x.Kind), Risk: x.Risk, Production: x.Production, Write: x.Write(), Request: x.Summary,
		Decision: x.Decision(), Rule: x.Rule, Facade: x.Facade, Approver: x.Approver, State: x.State, SigNote: x.SigNote}
	switch x.Sig {
	case loxrun.SigOK:
		r.Signature = "ok"
	case loxrun.SigBad:
		r.Signature = "bad"
	default:
		r.Signature = "unchecked"
	}
	if !x.Decided.IsZero() {
		t := x.Decided.UTC()
		r.DecidedAt = &t
		ms := max(x.Decided.Sub(x.At).Milliseconds(), 0)
		r.DecideMS = &ms
	}
	if !x.Ended.IsZero() {
		t := x.Ended.UTC()
		r.EndedAt = &t
	}
	if detail {
		r.Header, r.Body, r.Warnings, r.Touched = x.Header, x.Body, x.Warnings, x.Touched
	}
	return r
}
