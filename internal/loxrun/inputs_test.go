package loxrun

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
)

// The values typed in these tests: none may show anywhere but in the box
// sealed to the lock.
const (
	typedEmail = "alice@example.org"
	typedPhone = "+32470000000"
)

func newX25519(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// inputsItem is a read ticket that asks the human for the values names,
// sealed to priv's public half (nil: no SecretTo).
func (k lockKey) inputsItem(t *testing.T, priv *ecdh.PrivateKey, names ...string) api.QueueItem {
	return k.item(t, ticket.KindRead, ticket.RiskRead, "dev", "search the files for the values typed", func(tk *ticket.Ticket) {
		tk.Source.Lock = "lockfile"
		tk.Subject.Inputs = ticket.SortInputs(names)
		tk.Flags.NeverAuto = true
		if priv != nil {
			tk.Subject.SecretTo = ticket.EncodeX25519(priv.PublicKey())
		}
	})
}

// openInputs opens, as the lock does, the values lox run sealed in its
// approval of it.
func openInputs(t *testing.T, hub *fakeHub, lk lockKey, it api.QueueItem, priv *ecdh.PrivateKey) map[string]string {
	t.Helper()
	d, ok := hub.decision(it.ID)
	if !ok || !d.Approved || d.Secret == nil {
		t.Fatalf("decision on %s: %+v, want an approval with sealed values", it.ID, d)
	}
	var box ticket.Sealed
	if err := json.Unmarshal(d.Secret, &box); err != nil {
		t.Fatal(err)
	}
	tk, err := ticket.VerifyTicket(lk.pub, it.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	dec := &ticket.Decision{V: ticket.VersionKinds, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: ticket.Approved, Secret: &box}
	vals, err := dec.OpenInputs(tk, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for n, v := range vals {
		out[n] = string(v)
	}
	return out
}

func TestNeedsInputs(t *testing.T) {
	lk := newLockKey()
	priv := newX25519(t)
	verified := func(it api.QueueItem) *tracked {
		tk, err := ticket.VerifyTicket(lk.pub, it.Ticket)
		if err != nil {
			t.Fatal(err)
		}
		return &tracked{tk: tk, req: Request{Subject: tk.Subject, Verified: true}}
	}
	if !needsInputs(verified(lk.inputsItem(t, priv, "needle"))) {
		t.Error("a verified ticket with inputs and SecretTo: want true")
	}
	noKey := verified(lk.inputsItem(t, priv, "needle"))
	noKey.tk.Subject.SecretTo = ""
	if needsInputs(noKey) {
		t.Error("no SecretTo: nothing to seal to")
	}
	if needsInputs(verified(lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT 1", nil))) {
		t.Error("no inputs: want false")
	}
	u := verified(lk.inputsItem(t, priv, "needle"))
	u.req.Verified = false
	if needsInputs(u) {
		t.Error("an unverified ticket: want false")
	}
	if needsInputs(&tracked{}) {
		t.Error("no ticket (a console's question): want false")
	}
}

// The card names the values to type and warns the human; the feed names
// them too, never a value.
func TestInputsCard(t *testing.T) {
	lines := card(View{Now: time.Now()}, Card{Instance: "files", Lock: "lockfile", Kind: ticket.KindRead,
		Inputs: "${email}, ${phone}", Why: inputsWhy}, 1, 120, Style{})
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.text() + "\n")
	}
	for _, want := range []string{"values to type: ${email}, ${phone}", "type a value only for your own need;",
		"the agent may not tell you what to type", "asks for typed values: a human decides"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("no %q on the card:\n%s", want, b.String())
		}
	}
}

// AUTO mode and every auto rule leave a ticket with inputs to the human:
// an allow rule, a deny rule, a session approval.
func TestEngineInputsNeverAuto(t *testing.T) {
	r := req(ticket.KindRead, ticket.RiskRead, "dev")
	r.Lock = "lockfile"
	r.Subject.Inputs = []string{"needle"}
	for _, rules := range []ProfileRules{nil, {ActRead: Allow}, {ActRead: Deny}, {ActRead: Ask}} {
		e := NewEngine(Auto)
		e.Rules = func(string, string, string) ProfileRules { return rules }
		e.Answered(r, true)
		if v := e.Decide(r); v.Outcome != Question || v.Why != inputsWhy || v.Tag != "ask:inputs" {
			t.Errorf("rules %v: %+v, want the human asked", rules, v)
		}
	}
	a := req(ticket.KindAction, ticket.RiskRead, "dev")
	a.Subject.Inputs = []string{"needle"}
	if v := NewEngine(Auto).Decide(a); v.Outcome != Question {
		t.Errorf("an action with inputs: %+v", v)
	}
}

// y asks each value without echo, in order; the approval carries them
// sealed to the lock, which opens exactly them. Neither the output (the
// scrollback) nor the feed holds a value: the names only.
func TestSessionInputsApprove(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	priv := newX25519(t)
	it := lk.inputsItem(t, priv, "phone", "email")
	hub.push(it)
	if e := h.wait(EvQuestion, it.ID); e.Rule != "" {
		t.Fatalf("%+v", e)
	}
	h.keys <- R('y')
	noDecision(t, hub, it.ID, "y opens the first value's prompt")
	typeIn(h, typedEmail)
	noDecision(t, hub, it.ID, "a second value is asked")
	typeIn(h, typedPhone)
	if e := h.wait(EvDecided, it.ID); !e.Approved || e.Rule != "" {
		t.Fatalf("%+v", e)
	}
	got := openInputs(t, hub, lk, it, priv)
	if len(got) != 2 || got["email"] != typedEmail || got["phone"] != typedPhone {
		t.Fatalf("opened %v", got)
	}
	out := h.output()
	for _, want := range []string{"values to type: ${email}, ${phone}", "the agent may not tell you what to type"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in the output:\n%s", want, out)
		}
	}
	d, _ := hub.decision(it.ID)
	for _, v := range []string{typedEmail, typedPhone} {
		if strings.Contains(out, v) || strings.Contains(d.Reason+d.Asked, v) {
			t.Errorf("%q shows outside the sealed box:\n%s", v, out)
		}
	}
}

// An empty answer or Esc denies with "no value typed"; n denies without
// a prompt.
func TestSessionInputsDenied(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	priv := newX25519(t)
	for _, c := range []struct {
		name string
		keys []Key
	}{
		{"empty", []Key{R('y'), {Code: KeyEnter}}},
		{"esc", []Key{R('y'), {Code: KeyEsc}}},
		{"esc on the second value", append(append([]Key{R('y')}, typed(typedEmail)...), Key{Code: KeyEsc})},
	} {
		it := lk.inputsItem(t, priv, "email", "phone")
		hub.push(it)
		h.wait(EvQuestion, it.ID)
		for _, k := range c.keys {
			h.keys <- k
		}
		if e := h.wait(EvDecided, it.ID); e.Approved {
			t.Fatalf("%s: %+v, want a denial", c.name, e)
		}
		if d, _ := hub.decision(it.ID); d.Approved || d.Reason != noValueReason || d.Secret != nil {
			t.Fatalf("%s: %+v", c.name, d)
		}
	}
	it := lk.inputsItem(t, priv, "email")
	hub.push(it)
	h.wait(EvQuestion, it.ID)
	h.keys <- R('n')
	h.wait(EvDecided, it.ID)
	if d, _ := hub.decision(it.ID); d.Approved || d.Secret != nil || d.Reason == noValueReason {
		t.Fatalf("n: %+v", d)
	}
	if strings.Contains(h.output(), typedEmail) {
		t.Fatalf("a typed value in the output:\n%s", h.output())
	}
}

// A ticket that leaves the queue while its values are typed (it timed
// out, its lock withdrew it) gets no decision from lox run, and the
// values typed for it are dropped.
func TestSessionInputsGone(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	it := lk.inputsItem(t, newX25519(t), "email", "phone")
	hub.push(it)
	h.wait(EvQuestion, it.ID)
	h.keys <- R('y')
	typeIn(h, typedEmail)
	noDecision(t, hub, it.ID, "the second value is asked")
	hub.mu.Lock()
	hub.items = nil
	hub.ver++
	hub.mu.Unlock()
	hub.poke()
	time.Sleep(100 * time.Millisecond)
	if _, ok := hub.decision(it.ID); ok {
		t.Fatal("decided a ticket that left the queue")
	}
	if strings.Contains(h.output(), typedEmail) {
		t.Fatal("a typed value in the output")
	}
}

// A ticket with inputs lox run cannot seal to (its lock key is not
// pinned) is not approved: y says why, n denies.
func TestSessionInputsUnverified(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, nil, nil)
	it := lk.inputsItem(t, newX25519(t), "email")
	hub.push(it)
	h.wait(EvQuestion, it.ID)
	h.keys <- R('y')
	noDecision(t, hub, it.ID, "no typed value can be sealed")
	if !strings.Contains(h.output(), "no typed value can be sealed") {
		t.Fatalf("y does not say why:\n%s", h.output())
	}
}

func typed(s string) []Key {
	var ks []Key
	for _, r := range s {
		ks = append(ks, R(r))
	}
	return append(ks, Key{Code: KeyEnter})
}
