package route

import (
	"slices"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// The table with every facade enabled; with none listed (no routing.json:
// the zero Rules), the local facades only, never a chat facade (#61, I9).
func TestDefaults(t *testing.T) {
	all := Rules{Enabled: facades}
	want := map[string][]string{
		Read: {TTY, Deck, Mobile, Slack, Telegram}, ReadPII: {TTY, Deck, Mobile, Slack, Telegram}, Grant: {TTY, Deck},
		Write: {TTY, Deck, Mobile, Slack, Telegram}, ProdWrite: {TTY, Deck, Mobile},
		PolicyLoosen: {TTY, Deck, Mobile}, Unlock: {TTY, Deck},
	}
	for risk, fs := range want {
		if got := all.Facades("any", risk); !slices.Equal(got, fs) {
			t.Errorf("%s: %v, want %v", risk, got, fs)
		}
	}
	for _, r := range []Rules{{}, {Enabled: []string{}}} {
		for _, risk := range risks {
			want := slices.DeleteFunc(slices.Clone(want[risk]), func(f string) bool { return f == Slack || f == Telegram })
			if got := r.Facades("any", risk); !slices.Equal(got, want) {
				t.Errorf("no facades listed %+v, %s: %v, want %v", r, risk, got, want)
			}
			for _, f := range []string{Slack, Telegram} {
				if r.On(f) || r.Allowed("any", f, risk) == nil {
					t.Errorf("no facades listed %+v: %s routed for %s", r, f, risk)
				}
			}
		}
	}
	// Only narrows, never enables: an instance routed to chat with no
	// facades listed reaches the terminal only.
	only := Rules{Only: map[string][]string{"any": {TTY, Slack, Telegram}}}
	if got := only.Facades("any", Read); !slices.Equal(got, []string{TTY}) {
		t.Errorf("Only with no facades listed: %v", got)
	}
	for _, f := range []string{Slack, Telegram} {
		if CanReveal(f) {
			t.Errorf("%s can reveal", f)
		}
	}
	for _, f := range local {
		if !CanReveal(f) {
			t.Errorf("%s cannot reveal", f)
		}
	}
}

func TestOnlyNarrows(t *testing.T) {
	r := Rules{Enabled: facades, Only: map[string][]string{"crm-prod": {TTY, Slack}}}
	if err := r.Allowed("crm-prod", Deck, Read); err == nil {
		t.Error("deck allowed despite Only")
	}
	if err := r.Allowed("crm-prod", Slack, Read); err != nil {
		t.Error(err)
	}
	// Only cannot widen a chat facade to a prod write.
	if err := r.Allowed("crm-prod", Slack, ProdWrite); err == nil {
		t.Error("Only widened slack to prod-write")
	}
	// Nor a phone or a chat to a grant.
	r.Only["crm-prod"] = []string{Mobile, Slack, Telegram}
	for _, f := range []string{Mobile, Slack, Telegram} {
		if r.Allowed("crm-prod", f, Grant) == nil {
			t.Errorf("Only widened %s to grant", f)
		}
	}
	if err := r.Allowed("other", Deck, Read); err != nil {
		t.Errorf("other instance: %v", err)
	}
}

func TestUnknown(t *testing.T) {
	var r Rules
	if r.Allowed("i", "email", Read) == nil || r.Allowed("i", TTY, "delete") == nil {
		t.Error("unknown facade or risk accepted")
	}
}

func TestEnabled(t *testing.T) {
	r := Rules{Enabled: []string{TTY}}
	if r.Allowed("i", Deck, Read) == nil {
		t.Error("disabled facade allowed")
	}
	if r.Allowed("i", TTY, ProdWrite) != nil {
		t.Error("enabled facade refused")
	}
}

// The hub knows exactly lockkit's risk classes: a class the locks may
// sign and the hub refuses (or the other way round) is a lost ticket.
func TestRisksAreLockkits(t *testing.T) {
	if !ticket.Risk(Grant).Valid() {
		t.Skip("lockkit before v0.12.0 has no grant (compat build)")
	}
	var want []string
	for _, r := range ticket.Risks {
		want = append(want, string(r))
	}
	if !slices.Equal(risks, want) {
		t.Errorf("risks %v, lockkit %v", risks, want)
	}
}
