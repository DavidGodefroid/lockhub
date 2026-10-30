package chat_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// fakeChat is a transport whose Close fails as fail says.
type fakeChat struct {
	mu      sync.Mutex
	posts   int
	closes  []string // outcomes, one per Close call
	ok      int      // successful closes
	fail    func(n int) error
	answers chan chat.Answer
}

func (f *fakeChat) Facade() string { return route.Slack }

func (f *fakeChat) Post(context.Context, chat.Card) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posts++
	return fmt.Sprintf("m%d", f.posts), nil
}

func (f *fakeChat) Close(_ context.Context, _ string, _ chat.Card, outcome string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes = append(f.closes, outcome)
	if err := f.fail(len(f.closes)); err != nil {
		return err
	}
	f.ok++
	return nil
}

func (f *fakeChat) Listen(ctx context.Context, answers chan<- chat.Answer) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case a := <-f.answers:
			answers <- a
		}
	}
}

func (f *fakeChat) counts() (posts, closes, ok int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts, len(f.closes), f.ok
}

type env struct {
	e   hubtest.Env
	l   hubtest.Lock
	f   *fakeChat
	ref store.Ref
}

func run(t *testing.T, tries int, base time.Duration, fail func(n int) error) env {
	t.Helper()
	l := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) {
		c.Codec, c.Now = ticketcodec.Codec{}, nil
		c.Routes = route.Rules{Enabled: []string{route.TTY, route.Slack}}
	}, l)
	f := &fakeChat{fail: fail, answers: make(chan chat.Answer)}
	fc := &chat.Facade{H: e.Hub, T: f, Wait: 50 * time.Millisecond, RetryBase: base, RetryMax: 16 * base, RetryTries: tries}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { fc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, ticket.RiskRead,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: "dev-1", Session: "s"}
	tk.Screen = ticket.Screen{Header: "query on crm", Body: []string{"SELECT 1"}}
	if err := tk.Sign(l.Priv); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	if _, _, err := e.Hub.Push(context.Background(), "crm", raw); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "posted", func() bool { p, _, _ := f.counts(); return p == 1 })
	return env{e, l, f, store.Ref{Instance: "crm", ID: tk.ID}}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

var errDown = errors.New("chat.update: ratelimited")

// A close that fails is retried with backoff until it succeeds, then no
// more (#60): here a ticket answered in the terminal.
func TestFailedCloseRetried(t *testing.T) {
	e := run(t, 10, 10*time.Millisecond, func(n int) error {
		if n <= 3 {
			return errDown
		}
		return nil
	})
	ref := e.ref
	if _, err := e.e.Hub.Decide(context.Background(), ref, hub.Verdict{Approved: true, ApproverID: "host:david", Facade: route.TTY}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "closed after 3 failures", func() bool { _, c, ok := e.f.counts(); return c == 4 && ok == 1 })
	time.Sleep(200 * time.Millisecond)
	if _, c, _ := e.f.counts(); c != 4 {
		t.Fatalf("%d closes, want 4: retried after it succeeded", c)
	}
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	for _, o := range e.f.closes {
		if o != e.f.closes[0] || o == "" {
			t.Fatalf("retries changed the outcome: %q", e.f.closes)
		}
	}
}

// A close that keeps failing is tried RetryTries times, then given up.
// The stale buttons stay live in the chat: a click on them is refused by
// the facade, and the hub itself refuses a decision on the ticket.
func TestFailedCloseGivesUpAndStaleClickRefused(t *testing.T) {
	e := run(t, 3, 10*time.Millisecond, func(int) error { return errDown })
	replies := make(chan string, 4)
	click := func(approve bool) {
		e.f.answers <- chat.Answer{Instance: e.ref.Instance, ID: e.ref.ID, Approve: approve, ApproverID: "slack:T1:U1", Display: "u1",
			Reply: func(_ context.Context, s string) { replies <- s }}
	}
	click(true)
	if r := <-replies; r != "" {
		t.Fatalf("approval refused: %q", r)
	}
	waitFor(t, "3 tries", func() bool { _, c, _ := e.f.counts(); return c == 3 })
	time.Sleep(200 * time.Millisecond)
	if _, c, ok := e.f.counts(); c != 3 || ok != 0 {
		t.Fatalf("%d closes (%d ok), want 3 tries then none", c, ok)
	}
	for _, approve := range []bool{false, true} {
		click(approve)
		if r := <-replies; r != "this ticket is no longer pending" {
			t.Fatalf("stale click: %q", r)
		}
	}
	ref := e.ref
	_, err := e.e.Hub.Decide(context.Background(), ref, hub.Verdict{ApproverID: "slack:T1:U1", Facade: route.Slack})
	var te state.ErrTransition
	if !errors.As(err, &te) {
		t.Fatalf("hub decided a ticket already approved: %v", err)
	}
	var st state.State
	e.e.Store.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(ref)
		st = tk.State
		return err
	})
	if st != state.Approved {
		t.Fatalf("ticket is %s", st)
	}
}

// A click on a message whose close waits for its retry tries the close
// again at once (but not twice within RetryBase); a message the transport
// says is gone is not retried, by a click or by the timer.
func TestStaleClickRetriesNowAndGoneNotRetried(t *testing.T) {
	// Tries 1-3 fail (retried after 100, 200 ms; the 4th would wait
	// 400 ms); the 4th, brought forward by a click, says gone.
	e := run(t, 10, 100*time.Millisecond, func(n int) error {
		if n >= 4 {
			return fmt.Errorf("chat.update: message_not_found: %w", chat.ErrGone)
		}
		return errDown
	})
	if _, err := e.e.Hub.Decide(context.Background(), e.ref, hub.Verdict{ApproverID: "host:david", Facade: route.TTY}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "3 tries", func() bool { _, c, _ := e.f.counts(); return c == 3 })
	time.Sleep(120 * time.Millisecond)
	replies := make(chan string, 4)
	click := func() {
		e.f.answers <- chat.Answer{Instance: e.ref.Instance, ID: e.ref.ID, Approve: true, ApproverID: "slack:T1:U1", Display: "u1",
			Reply: func(_ context.Context, s string) { replies <- s }}
		if r := <-replies; r != "this ticket is no longer pending" {
			t.Fatalf("stale click: %q", r)
		}
	}
	start := time.Now()
	click()
	click() // within RetryBase of the first: no extra try
	waitFor(t, "the click's try", func() bool { _, c, _ := e.f.counts(); return c == 4 })
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("the click did not bring the retry forward (%s)", d)
	}
	time.Sleep(150 * time.Millisecond)
	click()
	// Not gone, the next timer retry would come 800 ms after the 4th.
	time.Sleep(1200 * time.Millisecond)
	if _, c, _ := e.f.counts(); c != 4 {
		t.Fatalf("a gone message was retried: %d closes", c)
	}
}
