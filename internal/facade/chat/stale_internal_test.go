package chat

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

type countPosts struct{ posts, closes int }

func (c *countPosts) Facade() string { return route.Slack }
func (c *countPosts) Post(context.Context, Card) (string, error) {
	c.posts++
	return "m", nil
}
func (c *countPosts) Close(context.Context, string, Card, string) error { c.closes++; return nil }
func (c *countPosts) Listen(ctx context.Context, _ chan<- Answer) error {
	<-ctx.Done()
	return ctx.Err()
}

// A queue snapshot taken before this facade decided a ticket (the queue
// goroutine was blocked sending it) does not post the ticket again with
// live buttons; a later snapshot without it forgets it.
func TestStaleSnapshotNotReposted(t *testing.T) {
	l := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) {
		c.Codec, c.Now = ticketcodec.Codec{}, nil
		c.Routes = route.Rules{Enabled: []string{route.TTY, route.Slack}}
	}, l)
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, ticket.RiskRead,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Requester = ticket.Requester{Agent: "dev-1", Session: "s"}
	if err := tk.Sign(l.Priv); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	ctx := context.Background()
	if _, _, err := e.Hub.Push(ctx, "crm", raw); err != nil {
		t.Fatal(err)
	}
	stale, _, err := e.Hub.Queue(ctx, 0, 0)
	if err != nil || len(stale) != 1 {
		t.Fatalf("queue %v %v", stale, err)
	}
	tr := &countPosts{}
	f := &Facade{H: e.Hub, T: tr}
	shown := map[store.Ref]*posted{}
	f.sync(ctx, shown, stale)
	f.answer(ctx, shown, Answer{Instance: "crm", ID: tk.ID, Approve: true, ApproverID: "slack:T1:U1", Display: "u1"})
	f.sync(ctx, shown, stale)
	if tr.posts != 1 || tr.closes != 1 || len(shown) != 0 {
		t.Fatalf("posts %d closes %d shown %d: the decided ticket was posted again", tr.posts, tr.closes, len(shown))
	}
	f.sync(ctx, shown, nil)
	if len(f.answered) != 0 {
		t.Fatalf("answered kept %v", f.answered)
	}
}

type failClose struct {
	countPosts
	calls int
}

func (f *failClose) Close(context.Context, string, Card, string) error {
	f.calls++
	return context.DeadlineExceeded
}

// A pass makes at most retriesPerPass retries; the rest wait for the next.
func TestRetriesPerPass(t *testing.T) {
	tr := &failClose{}
	f := &Facade{T: tr}
	now := time.Now()
	f.retries = map[retryKey]*closing{}
	for i := 0; i < retriesPerPass+3; i++ {
		f.retries[retryKey{store.Ref{Instance: "crm", ID: string(rune('a' + i))}, "m"}] = &closing{tries: 1, next: now}
	}
	f.retryCloses(context.Background(), now)
	if tr.calls != retriesPerPass {
		t.Fatalf("%d closes in one pass, want %d", tr.calls, retriesPerPass)
	}
}

// Clicks never postpone the timer's counted tries: a clicked try that
// fails keeps the timer's due time, and the backoff is capped at RetryMax.
func TestClickedFailureKeepsTheTimer(t *testing.T) {
	f := &Facade{T: &failClose{}, RetryBase: time.Second, RetryMax: 4 * time.Second}
	now := time.Now()
	k := retryKey{store.Ref{Instance: "crm", ID: "a"}, "m"}
	c := &closing{tries: 3, last: now.Add(-time.Minute), next: now.Add(4 * time.Second)}
	f.retries = map[retryKey]*closing{k: c}
	f.retrySoon(k.Ref, now)
	f.retryCloses(context.Background(), now)
	if c.tries != 3 || !c.next.Equal(now.Add(4*time.Second)) {
		t.Fatalf("after a clicked failure: tries %d, next in %s", c.tries, c.next.Sub(now))
	}
	f.failed(k, c, context.DeadlineExceeded, now)
	if d := c.next.Sub(now); d != 4*time.Second {
		t.Fatalf("backoff %s, want RetryMax", d)
	}
}
