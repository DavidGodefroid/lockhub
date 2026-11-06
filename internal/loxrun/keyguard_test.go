package loxrun

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
)

// guardState is a session state on a fake clock, with two write
// questions, a on top then b, both shown and armed.
type guardState struct {
	st    *state
	now   time.Time
	a, b  api.QueueItem
	out   *strings.Builder
	keys  chan Key
	clock func(time.Duration)
}

func newGuardState(t *testing.T, a func(*ticket.Ticket), aRetype string) *guardState {
	t.Helper()
	lk := newLockKey()
	g := &guardState{out: &strings.Builder{}, keys: make(chan Key, 16)}
	g.now = time.Unix(1_800_000_000, 0)
	g.clock = func(d time.Duration) { g.now = g.now.Add(d) }
	s := &Session{Out: g.out, Keys: g.keys, LockKeys: map[string]ed25519.PublicKey{"shop": lk.pub},
		KeyArm: 400 * time.Millisecond, ReconnectAsk: -1, IdleConn: time.Minute, Now: func() time.Time { return g.now }}
	g.st = newState(s)
	g.a = lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE a", a)
	g.a.Retype = aRetype
	g.b = lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE b", nil)
	g.st.onQueue(api.QueueResult{Tickets: []api.QueueItem{g.a, g.b}}, nil)
	if len(g.st.cards) != 2 || g.st.cards[0].id != g.a.ID {
		t.Fatalf("cards %d", len(g.st.cards))
	}
	g.st.syncTop() // the frame shows a on top
	g.st.flushKeys = false
	g.clock(time.Second)
	return g
}

// decided returns the decision queued for id, if any.
func (g *guardState) decided(id string) (api.DecideRequest, bool) {
	for _, ef := range g.st.pending {
		if ef.t.id == id {
			return ef.req, true
		}
	}
	return api.DecideRequest{}, false
}

// aLeaves: a leaves the queue (decided elsewhere): b comes on top.
func (g *guardState) aLeaves() {
	g.st.onQueue(api.QueueResult{Tickets: []api.QueueItem{g.b}}, nil)
}

// A y or n pressed right after the top card changed (a decided
// elsewhere, b on top) is not taken for b: b is answered only once it
// was shown for KeyArm, by a fresh key.
func TestKeyGuardTopChangedIgnoresAnswer(t *testing.T) {
	for _, r := range []rune{'y', 'n'} {
		g := newGuardState(t, nil, "")
		g.aLeaves()
		g.st.syncTop() // the loop shows b on top
		if !g.st.flushKeys {
			t.Fatal("the keys typed before b came on top are not dropped")
		}
		g.clock(50 * time.Millisecond)
		g.st.onKey(R(r))
		if _, ok := g.decided(g.b.ID); ok {
			t.Fatalf("%c meant for a answered b", r)
		}
		if !strings.Contains(g.st.flash, "just changed") {
			t.Errorf("flash %q", g.st.flash)
		}
		g.clock(400 * time.Millisecond)
		g.st.onKey(R(r))
		d, ok := g.decided(g.b.ID)
		if !ok || d.Approved != (r == 'y') || d.Rule != "" {
			t.Fatalf("%c on b once shown: %+v %v", r, d, ok)
		}
	}
}

// A key that arrives before the loop showed the new top card (the card
// changed under it) is not taken for that card either.
func TestKeyGuardTopChangedBeforeFrame(t *testing.T) {
	g := newGuardState(t, nil, "")
	g.aLeaves()
	g.st.onKey(R('y')) // no frame drawn since a left
	if _, ok := g.decided(g.b.ID); ok {
		t.Fatal("y answered a card the screen did not show")
	}
	if g.st.shownTop == nil || g.st.shownTop.id != g.b.ID {
		t.Fatal("b not noted as on top")
	}
}

// Tab is a change of the top card too.
func TestKeyGuardTabArms(t *testing.T) {
	g := newGuardState(t, nil, "")
	g.st.onKey(Key{Code: KeyTab})
	g.st.syncTop()
	g.st.onKey(R('y'))
	if _, ok := g.decided(g.b.ID); ok {
		t.Fatal("y right after Tab answered b")
	}
	if _, ok := g.decided(g.a.ID); ok {
		t.Fatal("y right after Tab answered a")
	}
	g.clock(time.Second)
	g.st.onKey(R('y'))
	if _, ok := g.decided(g.b.ID); !ok {
		t.Fatal("y on b once shown did not answer it")
	}
}

// The card of an open prompt goes away while the human types into it:
// what they type next (a password, the instance name) is that prompt's,
// dropped until Enter or Esc, never y, n, x or q on the next card.
func TestKeyGuardOrphanedPromptDiscards(t *testing.T) {
	for _, end := range []KeyCode{KeyEnter, KeyEsc} {
		g := newGuardState(t, func(tk *ticket.Ticket) {
			tk.Risk, tk.Flags = ticket.RiskProdWrite, ticket.Flags{Production: true, Retype: "shop"}
		}, "shop")
		g.st.onKey(R('y'))
		if g.st.cards[0].card.Prompt == nil {
			t.Fatal("y did not open a's prompt")
		}
		g.st.onKey(R('s'))
		g.aLeaves()
		g.st.syncTop()
		if !g.st.discard {
			t.Fatal("a's prompt went away: keys not dropped")
		}
		gen := g.st.gen[g.st.cards[0].profileKey]
		g.clock(time.Second) // b armed: the guard is the discard, not the delay
		for _, r := range "yhnopxq" {
			if g.st.onKey(R(r)) {
				t.Fatal("quit")
			}
		}
		if _, ok := g.decided(g.b.ID); ok {
			t.Fatal("the orphaned prompt's input answered b")
		}
		if g.st.quitting || g.st.gen[g.st.cards[0].profileKey] != gen || g.st.cards[0].card.Prompt != nil {
			t.Fatal("the orphaned prompt's input acted on the next card or the session")
		}
		g.st.onKey(Key{Code: end})
		if g.st.discard {
			t.Fatalf("%v did not end the dropped input", end)
		}
		if _, ok := g.decided(g.b.ID); ok {
			t.Fatal("the end of the dropped input answered b")
		}
		g.st.onKey(R('n'))
		if d, ok := g.decided(g.b.ID); !ok || d.Approved {
			t.Fatalf("n after the dropped input: %+v %v", d, ok)
		}
	}
}

// Entering a prompt's input on a card that just came on top waits for
// KeyArm too.
func TestKeyGuardPromptEnterArmed(t *testing.T) {
	g := newGuardState(t, nil, "")
	b := g.st.cards[1]
	b.card.Prompt = &Prompt{Label: "x"} // as the hub's retype error opens it
	b.promptKind = promptRetype
	b.item.Retype = "shop"
	g.aLeaves()
	g.st.syncTop()
	for _, r := range "shop" {
		g.st.onKey(R(r))
	}
	g.st.onKey(Key{Code: KeyEnter})
	if _, ok := g.decided(g.b.ID); ok {
		t.Fatal("Enter right after b came on top approved it")
	}
}

// The keys already typed when the top card changes are dropped; Enter
// or Esc among them ends an orphaned prompt's input; Ctrl-C still quits.
func TestKeyGuardDropTyped(t *testing.T) {
	g := newGuardState(t, nil, "")
	g.keys <- R('y')
	g.keys <- R('y')
	if g.st.dropTyped() || len(g.keys) != 0 {
		t.Fatal("typed keys not dropped")
	}
	g.st.discard = true
	g.keys <- R('a')
	g.keys <- Key{Code: KeyEnter}
	g.keys <- R('y')
	if g.st.dropTyped() || g.st.discard || len(g.keys) != 0 {
		t.Fatal("Enter among the dropped keys did not end the prompt's input")
	}
	g.keys <- R('y')
	g.keys <- Key{Code: KeyCtrlC}
	if !g.st.dropTyped() {
		t.Fatal("Ctrl-C among the dropped keys did not quit")
	}
	close(g.keys)
	if g.st.dropTyped() || g.st.s.Keys != nil {
		t.Fatal("closed keys")
	}
}

// The whole session loop: a y typed for a question that went away
// before it was read is dropped, and the human's half-typed instance
// name for a vanished prompt does not answer the next card.
func TestSessionKeyGuard(t *testing.T) {
	const arm = 150 * time.Millisecond
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) { s.KeyArm = arm })
	a := lk.item(t, ticket.KindWrite, ticket.RiskProdWrite, "prod", "DELETE FROM carts", func(tk *ticket.Ticket) {
		tk.Flags = ticket.Flags{Production: true, Retype: "shop"}
	})
	a.Retype = "shop"
	b := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE b", nil)
	hub.push(a)
	h.wait(EvShown, a.ID)
	hub.push(b)
	h.wait(EvQuestion, b.ID)
	time.Sleep(arm + 50*time.Millisecond)
	h.keys <- R('y') // a's instance-name prompt
	h.keys <- R('s')
	time.Sleep(30 * time.Millisecond)
	// a is decided elsewhere while the name is being typed.
	hub.mu.Lock()
	hub.items = hub.items[1:]
	hub.ver++
	hub.mu.Unlock()
	hub.poke()
	h.wait(EvShown, b.ID)
	for _, r := range "hopy" {
		h.keys <- R(r)
	}
	noDecision(t, hub, b.ID, "the orphaned prompt's input answered b")
	h.keys <- Key{Code: KeyEnter}
	time.Sleep(arm)
	h.keys <- R('n')
	if e := h.wait(EvDecided, b.ID); e.Approved || e.Rule != "" {
		t.Fatalf("b: %+v", e)
	}
	if _, ok := hub.decision(a.ID); ok {
		t.Fatal("a decided by lox run")
	}
}
