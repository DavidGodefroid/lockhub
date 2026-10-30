// Package route decides which facade may answer which ticket.
//
// v1 defaults:
//
//	facade            read  read-pii  write  prod-write  policy-loosen  unlock  reveal
//	tty, deck          yes    yes      yes      yes          yes         yes     yes
//	mobile             yes    yes      yes      yes          yes         no      yes
//	slack, telegram    yes    yes      yes      no           no          no      no
//
// Mobile decisions are signed by the device itself (locks verify them);
// unlock stays off mobile until secrets can be typed there.
//
// A chat facade is routed only when the hub's configuration lists it
// (Rules.Enabled): with no list (no routing.json, or one without
// "facades"), only the local facades are, so a hub never routes a ticket
// to a chat facade it does not run (invariant I9; fail closed).
//
// A workspace's configuration can only narrow this table (remove facades
// for an instance), never widen it.
package route

import (
	"fmt"
	"slices"
)

// Facades.
const (
	TTY      = "tty"
	Deck     = "deck"
	Mobile   = "mobile"
	Slack    = "slack"
	Telegram = "telegram"
)

// Risk classes (lockkit ticket.Risk names).
const (
	Read         = "read"
	ReadPII      = "read-pii"
	Write        = "write"
	ProdWrite    = "prod-write"
	PolicyLoosen = "policy-loosen"
	Unlock       = "unlock"
)

var (
	facades = []string{TTY, Deck, Mobile, Slack, Telegram}
	risks   = []string{Read, ReadPII, Write, ProdWrite, PolicyLoosen, Unlock}
	// local facades show clear values and accept every risk.
	local = []string{TTY, Deck, Mobile}
	// chatRisks are what a chat facade may answer.
	chatRisks = []string{Read, ReadPII, Write}
	// mobileRisks are what the mobile facade may answer.
	mobileRisks = []string{Read, ReadPII, Write, ProdWrite, PolicyLoosen}
)

// KnownFacade reports whether f is a facade name.
func KnownFacade(f string) bool { return slices.Contains(facades, f) }

// KnownRisk reports whether r is a risk class.
func KnownRisk(r string) bool { return slices.Contains(risks, r) }

// Rules is the routing in force. The zero value is the defaults.
type Rules struct {
	// Enabled lists the facades this hub runs; empty: the local ones
	// only (tty, deck, mobile), never a chat facade.
	Enabled []string `json:"facades,omitempty"`
	// Only, per instance, lists the facades that may answer it. Facades
	// outside the defaults are ignored: Only narrows, never widens.
	Only map[string][]string `json:"only,omitempty"`
}

// Allowed reports whether facade f may decide a ticket of risk r from
// instance inst, and why not.
func (r Rules) Allowed(inst, f, risk string) error {
	switch {
	case !KnownFacade(f):
		return fmt.Errorf("unknown facade %q", f)
	case !KnownRisk(risk):
		return fmt.Errorf("unknown risk class %q", risk)
	case f == Mobile && !slices.Contains(mobileRisks, risk):
		return fmt.Errorf("%s tickets cannot be answered on %s; use the terminal or the deck", risk, f)
	case !slices.Contains(local, f) && !slices.Contains(chatRisks, risk):
		return fmt.Errorf("%s tickets cannot be answered on %s; use the terminal or the deck", risk, f)
	}
	if !r.On(f) {
		return fmt.Errorf("facade %s is not enabled on this hub", f)
	}
	if only, ok := r.Only[inst]; ok && !slices.Contains(only, f) {
		return fmt.Errorf("instance %s is not routed to %s", inst, f)
	}
	return nil
}

// On reports whether facade f is enabled on this hub: listed in Enabled,
// or, with no list, a local facade. A chat facade is never on unless
// listed.
func (r Rules) On(f string) bool {
	if len(r.Enabled) == 0 {
		return slices.Contains(local, f)
	}
	return slices.Contains(r.Enabled, f)
}

// CanReveal reports whether facade f may show a ticket's clear values
// (end-to-end encrypted to it).
func CanReveal(f string) bool { return slices.Contains(local, f) }

// OnDemand reports whether facade f may ask a lock, through the hub, for
// a ticket's clear values (Ctrl-O) or for the renewal of an expired
// ticket: the host's own facades only, whose keys the locks pin (lockkit
// ticket.CanReveal). A device gets its clear screen sealed at submit time
// and asks nothing; a chat facade never shows clear values and never
// renews.
func OnDemand(f string) bool { return f == TTY || f == Deck }

// Facades lists the facades that may decide risk for inst, in a fixed
// order (for notifications).
func (r Rules) Facades(inst, risk string) []string {
	var out []string
	for _, f := range facades {
		if r.Allowed(inst, f, risk) == nil {
			out = append(out, f)
		}
	}
	return out
}
