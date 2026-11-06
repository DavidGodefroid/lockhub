package loxrun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
		QueueWait: time.Second, StatePoll: 20 * time.Millisecond, Observe: func(e Event) { h.events <- e }}
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
