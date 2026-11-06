package loxrun

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
)

// fakeHub is a hub queue in memory: lox run's decisions are recorded,
// and a decided ticket leaves the queue.
type fakeHub struct {
	mu       sync.Mutex
	ver      uint64
	items    []api.QueueItem
	decided  map[string]api.DecideRequest
	refuse   func(id string, req api.DecideRequest) error
	changed  chan struct{}
	states   map[string]string
	requests int
}

func newFakeHub() *fakeHub {
	return &fakeHub{decided: map[string]api.DecideRequest{}, changed: make(chan struct{}, 1), states: map[string]string{}}
}

func (h *fakeHub) push(it api.QueueItem) {
	h.mu.Lock()
	h.items = append(h.items, it)
	h.ver++
	h.mu.Unlock()
	h.poke()
}

func (h *fakeHub) poke() {
	select {
	case h.changed <- struct{}{}:
	default:
	}
}

func (h *fakeHub) QueueAll(ctx context.Context, since uint64, wait time.Duration) (api.QueueResult, error) {
	h.mu.Lock()
	ver := h.ver
	h.mu.Unlock()
	if since == ver && wait > 0 {
		select {
		case <-h.changed:
		case <-time.After(wait):
		case <-ctx.Done():
			return api.QueueResult{}, ctx.Err()
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return api.QueueResult{Tickets: append([]api.QueueItem(nil), h.items...), Version: h.ver}, nil
}

func (h *fakeHub) Decide(_ context.Context, instance, id string, req api.DecideRequest) error {
	h.mu.Lock()
	h.requests++
	refuse := h.refuse
	h.mu.Unlock()
	if refuse != nil {
		if err := refuse(id, req); err != nil {
			return err
		}
	}
	h.mu.Lock()
	h.decided[id] = req
	for i, it := range h.items {
		if it.ID == id {
			h.items = append(h.items[:i], h.items[i+1:]...)
			break
		}
	}
	h.states[id] = "approved"
	h.ver++
	h.mu.Unlock()
	h.poke()
	return nil
}

func (h *fakeHub) State(_ context.Context, instance, id string) (api.TicketState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return api.TicketState{ID: id, Instance: instance, State: h.states[id]}, nil
}

func (h *fakeHub) decision(id string) (api.DecideRequest, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	d, ok := h.decided[id]
	return d, ok
}

type lockKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newLockKey() lockKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return lockKey{pub, priv}
}

// item signs a ticket of kind as lock "shop" and lists it as the hub does.
func (k lockKey) item(t *testing.T, kind ticket.Kind, risk ticket.Risk, profile, body string, mod func(*ticket.Ticket)) api.QueueItem {
	t.Helper()
	tk := ticket.NewKindTicket(ticket.Source{Lock: "locksql", Instance: "shop", KeyID: ticket.KeyID(k.pub)}, kind, risk,
		&ticket.Subject{Profile: profile}, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), time.Now(), time.Hour)
	tk.Requester = ticket.Requester{Agent: "dev-1"}
	tk.Screen = ticket.Screen{Header: "shop · " + string(kind), Body: []string{body}, Warnings: []string{}}
	if mod != nil {
		mod(tk)
	}
	if err := tk.Sign(k.priv); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	return api.QueueItem{ID: tk.ID, Instance: "shop", Risk: string(tk.Risk), Created: tk.Created, Facades: []string{"tty", "deck"}, Ticket: raw}
}

type harness struct {
	t      *testing.T
	hub    *fakeHub
	keys   chan Key
	out    *strings.Builder
	outMu  *sync.Mutex
	events chan Event
	done   chan error
	cancel context.CancelFunc
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func start(t *testing.T, hub *fakeHub, keys map[string]ed25519.PublicKey, mod func(*Session)) *harness {
	h := &harness{t: t, hub: hub, keys: make(chan Key, 8), out: &strings.Builder{}, outMu: &sync.Mutex{}, events: make(chan Event, 128), done: make(chan error, 1)}
	s := &Session{Hub: hub, Keys: h.keys, Out: lockedWriter{h.outMu, h.out}, Style: Style{}, LockKeys: keys, Display: "david",
		QueueWait: time.Second, StatePoll: 20 * time.Millisecond, Observe: func(e Event) { h.events <- e },
		KeyArm: -1} // answers as soon as a question comes (keyguard_test.go sets it)
	if mod != nil {
		mod(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-h.done })
	return h
}

func (h *harness) wait(kind EventKind, id string) Event {
	h.t.Helper()
	to := time.After(5 * time.Second)
	for {
		select {
		case e := <-h.events:
			if e.Kind == kind && (id == "" || e.ID == id) {
				return e
			}
		case <-to:
			h.t.Fatalf("no %s for %q; output:\n%s", kind, id, h.output())
		}
	}
}

func (h *harness) output() string { h.outMu.Lock(); defer h.outMu.Unlock(); return h.out.String() }

// Without a terminal on stdout, lox run logs one plain line per ticket,
// no escape, and still answers the keys typed on stdin.
func TestSessionPlainLog(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	sel := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT id FROM orders", nil)
	hub.push(sel)
	if e := h.wait(EvDecided, sel.ID); e.Rule != "default:read" {
		t.Fatalf("SELECT: %+v", e)
	}
	upd := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = true", nil)
	hub.push(upd)
	h.wait(EvQuestion, upd.ID)
	h.keys <- R('n')
	if e := h.wait(EvDecided, upd.ID); e.Approved {
		t.Fatal("n approved")
	}
	out := h.output()
	for _, want := range []string{"SELECT id FROM orders", "auto", "QUESTION write on shop/dev", "UPDATE orders SET paid", "denied", "\a"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("escape in the plain log:\n%q", out)
	}
	if n := strings.Count(out, "\a"); n != 1 {
		t.Errorf("%d bells, want 1", n)
	}
}

// A ticket lox run cannot check (no pinned key, a version-1 ticket) is
// asked, never decided by a rule; one that does not verify under its
// pinned key is not decided at all.
func TestSessionUncheckedAsked(t *testing.T) {
	lk, other := newLockKey(), newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)

	forged := other.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT 1", nil)
	hub.push(forged)
	if e := h.wait(EvTicket, forged.ID); e.Err == nil {
		t.Error("a ticket that does not verify under its pinned key read as fine")
	}
	v1 := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT 2", func(tk *ticket.Ticket) {
		tk.V, tk.Kind, tk.Subject = ticket.Version, "", nil
	})
	hub.push(v1)
	h.wait(EvQuestion, v1.ID)
	if _, ok := hub.decision(forged.ID); ok {
		t.Error("a ticket that does not verify was decided")
	}
	h.keys <- R('y')
	if e := h.wait(EvDecided, v1.ID); !e.Approved || e.Rule != "" {
		t.Errorf("v1: %+v", e)
	}
}

// A rule's approval the hub refuses (it wants a human) becomes a
// question; a hub that cannot be reached gets the decision again.
func TestSessionHubRefusalsAndRetry(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	var once sync.Once
	hub.refuse = func(id string, req api.DecideRequest) error {
		if req.Rule != "" {
			return &approve.HubError{Status: 409, Kind: "needs_human", Message: "this ticket needs a human's decision"}
		}
		var err error
		once.Do(func() { err = errors.New("dial unix: connection refused") })
		return err
	}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	sel := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT 1", nil)
	hub.push(sel)
	h.wait(EvQuestion, sel.ID)
	h.keys <- R('y')
	// The first send fails (unreachable); the next queue update sends it
	// again.
	time.Sleep(50 * time.Millisecond)
	hub.mu.Lock()
	hub.ver++
	hub.mu.Unlock()
	hub.poke()
	if e := h.wait(EvDecided, sel.ID); !e.Approved || e.Rule != "" {
		t.Fatalf("%+v", e)
	}
}

// Back to auto mode, the waiting questions the rules decide are decided.
func TestSessionModeToggleReevaluates(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) { s.Mode = Manual })
	sel := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT 1", nil)
	hub.push(sel)
	h.wait(EvQuestion, sel.ID)
	h.keys <- Key{Code: KeyShiftTab}
	if m := h.wait(EvMode, ""); m.Mode != Auto {
		t.Fatal(m.Mode)
	}
	if e := h.wait(EvDecided, sel.ID); e.Rule != "default:read" {
		t.Fatalf("%+v", e)
	}
}

// A production ticket whose approval needs the instance name typed: y
// opens the prompt, a wrong name does not approve, the right one does.
func TestSessionRetype(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	it := lk.item(t, ticket.KindWrite, ticket.RiskProdWrite, "prod", "DELETE FROM carts", func(tk *ticket.Ticket) {
		tk.Flags = ticket.Flags{Production: true, Retype: "shop"}
	})
	it.Retype = "shop"
	hub.push(it)
	h.wait(EvQuestion, it.ID)
	for _, k := range []Key{R('y'), R('x'), {Code: KeyEnter}} {
		h.keys <- k
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := hub.decision(it.ID); ok {
		t.Fatal("approved with a wrong name")
	}
	for _, k := range []Key{R('s'), R('h'), R('o'), R('p'), {Code: KeyEnter}} {
		h.keys <- k
	}
	h.wait(EvDecided, it.ID)
	if d, _ := hub.decision(it.ID); !d.Approved || d.Retype != "shop" || d.Rule != "" {
		t.Errorf("decision %+v", d)
	}
}

// Equal auto reads fold into one feed line.
func TestSessionFoldsAutoReads(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	var frames []string
	var mu sync.Mutex
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		s.Size = func() (int, int) { return 100, 20 }
		s.Style = Style{Unicode: true}
		s.Out = writerFunc(func(p []byte) {
			mu.Lock()
			frames = append(frames, string(p))
			mu.Unlock()
		})
	})
	for i := 0; i < 5; i++ {
		it := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT id FROM orders WHERE id = 1", func(tk *ticket.Ticket) {
			tk.Subject.Target = "orders"
		})
		hub.push(it)
		h.wait(EvDecided, it.ID)
	}
	time.Sleep(50 * time.Millisecond)
	h.keys <- Key{Code: KeyEsc} // one more frame
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	last := frames[len(frames)-1]
	mu.Unlock()
	if !strings.Contains(last, "× 5") {
		t.Errorf("no folded line in the last frame:\n%s", last)
	}
}

type writerFunc func([]byte)

func (f writerFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

func TestParseKeys(t *testing.T) {
	got := ParseKeys([]byte("y\x1b[Z\x1b[A\r\n\x7f\x03é\x1b"))
	want := []Key{R('y'), {Code: KeyShiftTab}, {Code: KeyUnknown}, {Code: KeyEnter}, {Code: KeyBackspace}, {Code: KeyCtrlC}, R('é'), {Code: KeyEsc}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

// connectItem is a connect ticket of an "ask" profile that asks for the
// password, sealed to priv's public half.
func (k lockKey) connectItem(t *testing.T, profile string, priv *ecdh.PrivateKey) api.QueueItem {
	return k.item(t, ticket.KindConnect, ticket.RiskRead, profile, "connect", func(tk *ticket.Ticket) {
		tk.Subject.Endpoint = "db.internal:5432"
		tk.Subject.Credential = ticket.CredentialAsk
		tk.Subject.SecretTo = ticket.EncodeX25519(priv.PublicKey())
	})
}

// sealed opens the secret lox run sealed in its decision on it.
func sealed(t *testing.T, hub *fakeHub, lk lockKey, it api.QueueItem, priv *ecdh.PrivateKey) string {
	t.Helper()
	d, ok := hub.decision(it.ID)
	if !ok || !d.Approved || d.Secret == nil {
		t.Fatalf("decision on %s: %+v, want an approval with a secret", it.ID, d)
	}
	var box ticket.Sealed
	if err := json.Unmarshal(d.Secret, &box); err != nil {
		t.Fatal(err)
	}
	tk, err := ticket.VerifyTicket(lk.pub, it.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ticket.Open(priv, &box, ticket.SecretAAD(tk))
	if err != nil {
		t.Fatal(err)
	}
	return string(s)
}

func typeIn(h *harness, s string) {
	for _, r := range s {
		h.keys <- R(r)
	}
	h.keys <- Key{Code: KeyEnter}
}

// A mistyped password is not kept: its connect never ran (the lock could
// not connect), so the next connect of the profile is asked again and
// takes a new password; only once the lock connected with it is the
// password reused, and in manual mode y still asks for it.
func TestSessionWrongPasswordAskedAgain(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	newKey := func() *ecdh.PrivateKey {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	// 1. The first connect: asked, a wrong password typed. The lock
	// cannot connect: the ticket stays approved, never consumed.
	k1 := newKey()
	c1 := lk.connectItem(t, "dev", k1)
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	typeIn(h, "wrong")
	h.wait(EvDecided, c1.ID)
	if s := sealed(t, hub, lk, c1, k1); s != "wrong" {
		t.Fatalf("sealed %q", s)
	}

	// 2. The lock asks again: a question, not session:connect, and y
	// asks for the password again rather than reusing "wrong".
	k2 := newKey()
	c2 := lk.connectItem(t, "dev", k2)
	hub.push(c2)
	h.wait(EvQuestion, c2.ID)
	h.keys <- R('y')
	time.Sleep(50 * time.Millisecond)
	if _, ok := hub.decision(c2.ID); ok {
		t.Fatal("approved with the mistyped password, no prompt")
	}
	typeIn(h, "right")
	if e := h.wait(EvDecided, c2.ID); e.Rule != "" || !e.Approved {
		t.Fatalf("%+v", e)
	}
	if s := sealed(t, hub, lk, c2, k2); s != "right" {
		t.Fatalf("sealed %q, want the new password", s)
	}

	// 3. The lock connected with it: the next connect is the session's,
	// with the new password.
	hub.mu.Lock()
	hub.states[c2.ID] = "consumed"
	hub.mu.Unlock()
	if e := h.wait(EvResult, c2.ID); e.Result != ResRan {
		t.Fatalf("%+v", e)
	}
	runRead(t, h, hub, lk) // the connection works: a read ran on it
	k3 := newKey()
	c3 := lk.connectItem(t, "dev", k3)
	hub.push(c3)
	if e := h.wait(EvDecided, c3.ID); e.Rule != "session:connect" {
		t.Fatalf("%+v: want session:connect", e)
	}
	if s := sealed(t, hub, lk, c3, k3); s != "right" {
		t.Fatalf("sealed %q", s)
	}

	// 4. Manual mode: asked, and y opens the password prompt again.
	h.keys <- Key{Code: KeyShiftTab}
	h.wait(EvMode, "")
	k4 := newKey()
	c4 := lk.connectItem(t, "dev", k4)
	hub.push(c4)
	h.wait(EvQuestion, c4.ID)
	h.keys <- R('y')
	time.Sleep(50 * time.Millisecond)
	if _, ok := hub.decision(c4.ID); ok {
		t.Fatal("manual y reused the session password without a prompt")
	}
	typeIn(h, "other")
	h.wait(EvDecided, c4.ID)
	if s := sealed(t, hub, lk, c4, k4); s != "other" {
		t.Fatalf("sealed %q", s)
	}
}

// A connect approved with the session's password that never runs (the
// password changed at the backend) drops it: the next one is asked.
func TestSessionCachedPasswordDroppedWhenNotRun(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	key := func() *ecdh.PrivateKey { k, _ := ecdh.X25519().GenerateKey(rand.Reader); return k }
	setState := func(id, s string) { hub.mu.Lock(); hub.states[id] = s; hub.mu.Unlock() }

	c1 := lk.connectItem(t, "dev", key())
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	typeIn(h, "pw")
	h.wait(EvDecided, c1.ID)
	setState(c1.ID, "consumed")
	h.wait(EvResult, c1.ID)
	runRead(t, h, hub, lk)

	c2 := lk.connectItem(t, "dev", key())
	hub.push(c2)
	if e := h.wait(EvDecided, c2.ID); e.Rule != "session:connect" {
		t.Fatalf("%+v", e)
	}
	setState(c2.ID, "expired")
	if e := h.wait(EvResult, c2.ID); e.Result != ResExpired {
		t.Fatalf("%+v", e)
	}

	c3 := lk.connectItem(t, "dev", key())
	hub.push(c3)
	h.wait(EvQuestion, c3.ID)
}

// runRead has the agent run an auto read on profile dev.
func runRead(t *testing.T, h *harness, hub *fakeHub, lk lockKey) {
	t.Helper()
	r := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT 1", nil)
	hub.push(r)
	if e := h.wait(EvDecided, r.ID); e.Rule != "default:read" {
		t.Fatalf("%+v", e)
	}
}

// noDecision fails if lox run decided id (a prompt should be up).
func noDecision(t *testing.T, hub *fakeHub, id, why string) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	if _, ok := hub.decision(id); ok {
		t.Fatal(why)
	}
}

// A wrong password the backend took at the dial (the connect ran) is
// the session's: the next connect is approved with it. x drops it, with
// the session's connection approval: the next connect is asked, y opens
// an empty prompt (no session password to keep) and the new password is
// the one sealed. A connect approved before x that runs after it does
// not put the old password back.
func TestSessionForgetDropsWrongPassword(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	key := func() *ecdh.PrivateKey { k, _ := ecdh.X25519().GenerateKey(rand.Reader); return k }
	setState := func(id, s string) { hub.mu.Lock(); hub.states[id] = s; hub.mu.Unlock() }

	k1 := key()
	c1 := lk.connectItem(t, "dev", k1)
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	typeIn(h, "wrong")
	h.wait(EvDecided, c1.ID)
	setState(c1.ID, "consumed")
	h.wait(EvResult, c1.ID)
	runRead(t, h, hub, lk) // it failed later, at the backend

	// The reconnect: the session's, with the wrong password.
	k2 := key()
	c2 := lk.connectItem(t, "dev", k2)
	hub.push(c2)
	if e := h.wait(EvDecided, c2.ID); e.Rule != "session:connect" {
		t.Fatalf("%+v", e)
	}
	if s := sealed(t, hub, lk, c2, k2); s != "wrong" {
		t.Fatalf("sealed %q", s)
	}

	// x, no question up: every profile is forgotten.
	h.keys <- R('x')
	time.Sleep(50 * time.Millisecond)
	if !strings.Contains(h.output(), "forgot every profile") {
		t.Fatalf("no flash:\n%s", h.output())
	}
	setState(c2.ID, "consumed") // it ran after x: puts nothing back
	h.wait(EvResult, c2.ID)

	k3 := key()
	c3 := lk.connectItem(t, "dev", k3)
	hub.push(c3)
	if e := h.wait(EvQuestion, c3.ID); e.ID != c3.ID {
		t.Fatalf("%+v", e)
	}
	h.keys <- R('y')
	h.keys <- Key{Code: KeyEnter} // Enter alone: no session password to keep
	noDecision(t, hub, c3.ID, "Enter alone approved with a forgotten password")
	typeIn(h, "right")
	if e := h.wait(EvDecided, c3.ID); !e.Approved || e.Rule != "" {
		t.Fatalf("%+v", e)
	}
	if s := sealed(t, hub, lk, c3, k3); s != "right" {
		t.Fatalf("sealed %q, want the new password", s)
	}
}

// On a question, y shows the prompt even with a session password, and
// Enter alone keeps it; x on the question forgets its profile, so the
// prompt then has no default.
func TestSessionPromptDefaultAndForgetOnCard(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	key := func() *ecdh.PrivateKey { k, _ := ecdh.X25519().GenerateKey(rand.Reader); return k }
	setState := func(id, s string) { hub.mu.Lock(); hub.states[id] = s; hub.mu.Unlock() }

	c1 := lk.connectItem(t, "dev", key())
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	typeIn(h, "pw1")
	h.wait(EvDecided, c1.ID)
	setState(c1.ID, "consumed")
	h.wait(EvResult, c1.ID)
	runRead(t, h, hub, lk)

	h.keys <- Key{Code: KeyShiftTab} // manual: asked
	h.wait(EvMode, "")
	k2 := key()
	c2 := lk.connectItem(t, "dev", k2)
	hub.push(c2)
	h.wait(EvQuestion, c2.ID)
	h.keys <- R('y')
	noDecision(t, hub, c2.ID, "y reused the session password without a prompt")
	h.keys <- Key{Code: KeyEnter}
	h.wait(EvDecided, c2.ID)
	if s := sealed(t, hub, lk, c2, k2); s != "pw1" {
		t.Fatalf("sealed %q, want the session's", s)
	}

	k3 := key()
	c3 := lk.connectItem(t, "dev", k3)
	hub.push(c3)
	h.wait(EvQuestion, c3.ID)
	h.keys <- R('x')
	h.keys <- R('y')
	h.keys <- Key{Code: KeyEnter}
	noDecision(t, hub, c3.ID, "Enter alone kept a forgotten password")
	typeIn(h, "pw2")
	h.wait(EvDecided, c3.ID)
	if s := sealed(t, hub, lk, c3, k3); s != "pw2" {
		t.Fatalf("sealed %q", s)
	}
}

// A profile that asks to connect again right after the lock connected
// on it, with nothing run in between, did not get a working connection:
// its session password is dropped and the human asked, not the same
// credentials sent on every retry.
func TestSessionQuickReconnectAsked(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, nil)
	key := func() *ecdh.PrivateKey { k, _ := ecdh.X25519().GenerateKey(rand.Reader); return k }

	c1 := lk.connectItem(t, "dev", key())
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	typeIn(h, "wrong")
	h.wait(EvDecided, c1.ID)
	hub.mu.Lock()
	hub.states[c1.ID] = "consumed"
	hub.mu.Unlock()
	h.wait(EvResult, c1.ID)

	k2 := key()
	c2 := lk.connectItem(t, "dev", k2)
	hub.push(c2)
	h.wait(EvQuestion, c2.ID)
	if !strings.Contains(h.output(), "right after connecting") {
		t.Fatalf("why not shown:\n%s", h.output())
	}
	h.keys <- R('y')
	h.keys <- Key{Code: KeyEnter}
	noDecision(t, hub, c2.ID, "Enter alone kept the dropped password")
	typeIn(h, "right")
	h.wait(EvDecided, c2.ID)
	if s := sealed(t, hub, lk, c2, k2); s != "right" {
		t.Fatalf("sealed %q", s)
	}
}
