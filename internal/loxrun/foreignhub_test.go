package loxrun

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
)

// queueCounter counts the queue reads and fails the next ones on demand
// (the hub lost).
type queueCounter struct {
	*fakeHub
	reads atomic.Int32
	fail  atomic.Int32
}

func (q *queueCounter) QueueAll(ctx context.Context, since uint64, wait time.Duration) (api.QueueResult, error) {
	q.reads.Add(1)
	if q.fail.Load() > 0 {
		q.fail.Add(-1)
		return api.QueueResult{}, errors.New("dial unix facade.sock: connect: connection refused")
	}
	return q.fakeHub.QueueAll(ctx, since, wait)
}

func runSession(t *testing.T, s *Session) (<-chan error, *strings.Builder, *sync.Mutex) {
	t.Helper()
	out, mu := &strings.Builder{}, &sync.Mutex{}
	s.Keys, s.Out, s.Display = make(chan Key), lockedWriter{mu, out}, "david"
	s.QueueWait, s.StatePoll, s.KeyArm = 50*time.Millisecond, 20*time.Millisecond, -1
	ctx, cancel := context.WithCancel(context.Background())
	done, fin := make(chan error, 1), make(chan struct{})
	go func() { done <- s.Run(ctx); close(fin) }()
	t.Cleanup(func() { cancel(); <-fin })
	return done, out, mu
}

// A facade socket served by another workspace's hub (#172): the session
// stops with CheckHub's refusal before reading that hub's queue, so none
// of its tickets is shown, nor decided.
func TestSessionRefusesForeignHub(t *testing.T) {
	k := newLockKey()
	hub := &queueCounter{fakeHub: newFakeHub()}
	hub.push(k.item(t, ticket.KindRead, ticket.RiskRead, "prod", "SELECT secret FROM other_workspace", nil))
	refusal := &ForeignHub{Msg: "the facade socket /run/user/1000/lockhub/facade.sock is served by the hub of workspace /home/u/a (lockfamily-aaaa)"}
	done, out, mu := runSession(t, &Session{Hub: hub, LockKeys: map[string]ed25519.PublicKey{"shop": k.pub},
		CheckHub: func(context.Context) error { return refusal }})
	select {
	case err := <-done:
		if !errors.Is(err, refusal) {
			t.Fatalf("Run: %v, want the refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session serves another workspace's hub")
	}
	if n := hub.reads.Load(); n != 0 {
		t.Errorf("%d queue read(s) of another workspace's hub", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(out.String(), "other_workspace") || strings.Contains(out.String(), "hub up") {
		t.Errorf("another workspace's hub shown:\n%s", out.String())
	}
	if len(hub.decided) != 0 {
		t.Errorf("decided: %v", hub.decided)
	}
}

// A hub that does not answer yet is unreachable, not refused: the session
// checks it again until it is this workspace's, then serves it; once the
// hub is lost, the one that comes back is checked again, and another
// workspace's stops the session.
func TestSessionChecksHubAgainAfterLoss(t *testing.T) {
	k := newLockKey()
	hub := &queueCounter{fakeHub: newFakeHub()}
	var checks atomic.Int32
	foreign := atomic.Bool{}
	refusal := &ForeignHub{Msg: "served by the hub of workspace /home/u/a (lockfamily-aaaa)"}
	done, out, mu := runSession(t, &Session{Hub: hub, LockKeys: map[string]ed25519.PublicKey{"shop": k.pub},
		CheckHub: func(context.Context) error {
			switch n := checks.Add(1); {
			case n == 1:
				return errors.New("no hub answers on the facade socket: connection refused")
			case foreign.Load():
				return refusal
			}
			return nil
		}})
	deadline := time.Now().Add(5 * time.Second)
	for hub.reads.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("this workspace's hub never served (%d checks)", checks.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := checks.Load(); n != 2 {
		t.Fatalf("%d checks before the first queue read, want 2", n)
	}
	// The hub is lost; another workspace's comes back on the socket.
	foreign.Store(true)
	hub.fail.Store(1)
	hub.poke()
	select {
	case err := <-done:
		if !errors.Is(err, refusal) {
			t.Fatalf("Run: %v, want the refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the hub that came back was not checked")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(out.String(), "hub up") {
		t.Errorf("this workspace's hub not shown up:\n%s", out.String())
	}
}
