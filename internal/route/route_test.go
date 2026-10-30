package route

import (
	"slices"
	"testing"
)

func TestDefaults(t *testing.T) {
	var r Rules
	want := map[string][]string{
		Read: {TTY, Deck, Mobile, Slack, Telegram}, ReadPII: {TTY, Deck, Mobile, Slack, Telegram},
		Write: {TTY, Deck, Mobile, Slack, Telegram}, ProdWrite: {TTY, Deck, Mobile},
		PolicyLoosen: {TTY, Deck, Mobile}, Unlock: {TTY, Deck},
	}
	for risk, fs := range want {
		if got := r.Facades("any", risk); !slices.Equal(got, fs) {
			t.Errorf("%s: %v, want %v", risk, got, fs)
		}
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
	r := Rules{Only: map[string][]string{"crm-prod": {TTY, Slack}}}
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
