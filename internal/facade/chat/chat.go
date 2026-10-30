// Package chat runs a remote chat facade (Slack, Telegram) inside the
// hub: it posts each pending ticket the facade may see, passes the
// human's answer to the hub, and closes the message once the ticket is
// decided, here or elsewhere.
//
// What a chat facade shows is the lock's masked screen only: never the
// sealed clear values, never a reveal. Production tickets and the risk
// classes the routing keeps off chat are shown without buttons.
package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Card is what a chat message shows of a ticket. Every string but ID,
// Instance and Risk comes from the lock or the agent: transports escape
// all of them.
type Card struct {
	ID, Instance, Risk string
	Lock, Workspace    string
	// Requester is the agent's own label, never authenticated.
	Requester string
	Header    string
	Note      string
	Body      []string
	Warnings  []string
	// PII names the kinds of personal data touched (masked on screen).
	PII        []string
	Red        bool
	Production bool
	Expires    *time.Time
	// Answerable: the message gets approve/deny buttons; otherwise Why
	// says where to answer.
	Answerable bool
	Why        string
}

// CardOf builds the card of a pending ticket for facade, and whether the
// facade shows it at all (an instance routed away from it: not shown).
func CardOf(t store.Ticket, rules route.Rules, facade string) (Card, bool) {
	if len(rules.Enabled) > 0 && !slices.Contains(rules.Enabled, facade) {
		return Card{}, false
	}
	if only, ok := rules.Only[t.Instance]; ok && !slices.Contains(only, facade) {
		return Card{}, false
	}
	c := Card{ID: t.ID, Instance: t.Instance, Risk: t.Risk}
	var tk ticket.Ticket
	if err := json.Unmarshal(t.Raw, &tk); err != nil {
		c.Why = "this ticket cannot be shown here: answer it in the terminal or the deck"
		return c, true
	}
	// Only the masked screen: tk.PII.ClearSealed is never read.
	c.Lock, c.Workspace, c.Requester = tk.Source.Lock, tk.Workspace, tk.Requester.Agent
	c.Header, c.Note, c.Body, c.Warnings = tk.Screen.Header, tk.Screen.Note, tk.Screen.Body, tk.Screen.Warnings
	c.PII, c.Red, c.Production = tk.PII.Touched, tk.Screen.Red, tk.Flags.Production
	if !t.Expires.IsZero() {
		e := t.Expires
		c.Expires = &e
	}
	switch err := rules.Allowed(t.Instance, facade, t.Risk); {
	case c.Production:
		c.Why = "production: answer it in the terminal or the deck"
	case err != nil:
		c.Why = fmt.Sprintf("%s: answer it in the terminal or the deck", t.Risk)
	default:
		c.Answerable = true
	}
	return c, true
}

// Inert makes untrusted text visible as what it is, on one line: C0/C1
// controls, bidi marks and newlines as escapes (sanitize.Terminal), and
// every other invisible format character (zero-width spaces and joiners,
// BOM, tag characters) as \uXXXX, so nothing hidden reaches a chat.
func Inert(s string) string {
	s = sanitize.Terminal(s, false)
	var b strings.Builder
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&b, "\\u%04X", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Answer is a human's click, already authenticated by the transport
// against its allowlist.
type Answer struct {
	Instance, ID string
	Approve      bool
	// ApproverID is "<facade>:<workspace or team>:<user>"; Display is for
	// screens.
	ApproverID, Display string
	// Reply is called once per answer: with why it was not taken, or
	// with "" once it was (may be nil).
	Reply func(ctx context.Context, text string)
}

// Transport is one chat service.
type Transport interface {
	// Facade is the facade name (route.Slack, route.Telegram).
	Facade() string
	// Post sends a new message for c and returns its reference.
	Post(ctx context.Context, c Card) (ref string, err error)
	// Close rewrites message ref: no buttons, the outcome shown. A
	// failed Close is retried (Facade.Run); an error wrapping ErrGone
	// (the message cannot be edited any more) is not. Close must be
	// safe to call again for a message it already rewrote.
	Close(ctx context.Context, ref string, c Card, outcome string) error
	// Listen delivers authenticated answers until ctx ends.
	Listen(ctx context.Context, answers chan<- Answer) error
}

// ErrGone, wrapped by a transport's Close error, says the message can no
// longer be edited (deleted, too old): the close is not retried.
var ErrGone = errors.New("the message can no longer be edited")

// Close retries (#60): a close that fails (a rate limit, a network error,
// a 5xx) would leave a decided, withdrawn or expired ticket's message with
// live buttons. It is retried with backoff, from RetryBase doubling up to
// RetryMax, at most RetryTries times. A click on the stale buttons
// meanwhile (or after the retries give up, or after a restart) is refused
// by the facade ("no longer pending"), and the hub refuses any decision
// on a ticket that is not pending.
const (
	DefaultRetryBase  = 2 * time.Second
	DefaultRetryMax   = 5 * time.Minute
	DefaultRetryTries = 15
)

// Facade runs a transport against the hub.
type Facade struct {
	H   *hub.Hub
	T   Transport
	Log io.Writer
	// Wait is the queue long-poll (default 30s).
	Wait time.Duration
	// retries are the failed closes, by ticket and message (Run's loop
	// only).
	retries map[retryKey]*closing
	// answered are the tickets this facade decided, until a queue
	// without them comes: a queue snapshot taken before the decision
	// must not post them again (Run's loop only).
	answered map[store.Ref]bool
	// RetryBase, RetryMax and RetryTries bound the retries of a failed
	// close (defaults DefaultRetry*); CloseTimeout bounds each close
	// (default DefaultCloseTimeout).
	RetryBase, RetryMax, CloseTimeout time.Duration
	RetryTries                        int
}

type posted struct {
	ref  string
	card Card
}

// retryKey is a failed close's ticket and message: a ticket reposted
// from a stale queue snapshot has two messages to close.
type retryKey struct {
	store.Ref
	msg string
}

// Each close is bounded on its own (CloseTimeout), and a pass tries at
// most retriesPerPass retries, so the loop goes back to answering clicks
// and syncing the queue between them.
const (
	DefaultCloseTimeout = 15 * time.Second
	retriesPerPass      = 2
)

// closing is a close that failed, waiting for its next try.
type closing struct {
	posted
	outcome    string
	tries      int
	last, next time.Time
	// clicked: this try was brought forward by a click.
	clicked bool
}

// Run serves until ctx ends or the transport fails for good.
func (f *Facade) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wait := f.Wait
	if wait == 0 {
		wait = 30 * time.Second
	}
	answers := make(chan Answer)
	lerr := make(chan error, 1)
	go func() { lerr <- f.T.Listen(ctx, answers) }()
	queues := make(chan []store.Ticket)
	qerr := make(chan error, 1)
	go func() {
		var since uint64
		for {
			tks, ver, err := f.H.Queue(ctx, since, wait)
			if err != nil {
				qerr <- err
				return
			}
			select {
			case queues <- tks:
			case <-ctx.Done():
				return
			}
			since = ver
		}
	}()
	shown := map[store.Ref]*posted{}
	for {
		var timer *time.Timer
		var due <-chan time.Time
		if next, ok := f.nextRetry(); ok {
			timer = time.NewTimer(time.Until(next))
			due = timer.C
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-lerr:
			return fmt.Errorf("%s: %w", f.T.Facade(), err)
		case err := <-qerr:
			return err
		case tks := <-queues:
			f.sync(ctx, shown, tks)
		case a := <-answers:
			f.answer(ctx, shown, a)
		case <-due:
			f.retryCloses(ctx, time.Now())
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// close rewrites p's message with outcome; on a failure, the close is
// kept for a retry.
func (f *Facade) close(ctx context.Context, r store.Ref, p *posted, outcome string) {
	err := f.closeOnce(ctx, p.ref, p.card, outcome)
	if err == nil {
		return
	}
	c := &closing{posted: *p, outcome: outcome}
	f.failed(retryKey{r, p.ref}, c, err, time.Now())
}

// closeOnce is one try of a close, within CloseTimeout.
func (f *Facade) closeOnce(ctx context.Context, ref string, c Card, outcome string) error {
	d := f.CloseTimeout
	if d <= 0 {
		d = DefaultCloseTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return f.T.Close(cctx, ref, c, outcome)
}

func (f *Facade) retryBase() time.Duration {
	if f.RetryBase > 0 {
		return f.RetryBase
	}
	return DefaultRetryBase
}

// failed records a failed try of c: retried later, or dropped (gone, or
// out of tries).
func (f *Facade) failed(k retryKey, c *closing, err error, now time.Time) {
	if f.retries == nil {
		f.retries = map[retryKey]*closing{}
	}
	if !c.clicked {
		c.tries++ // a try a click brought forward does not count
	}
	c.clicked = false
	c.last = now
	base, maxd, tries := f.retryBase(), f.RetryMax, f.RetryTries
	if maxd <= 0 {
		maxd = DefaultRetryMax
	}
	if tries <= 0 {
		tries = DefaultRetryTries
	}
	switch {
	case errors.Is(err, ErrGone):
		f.logf("close %s/%s (message %s): %v (not retried)", k.Instance, k.ID, k.msg, err)
		delete(f.retries, k)
		return
	case c.tries >= tries:
		f.logf("close %s/%s (message %s): %v (gave up after %d tries: its buttons stay, and are refused)", k.Instance, k.ID, k.msg, err, c.tries)
		delete(f.retries, k)
		return
	}
	d := base << (c.tries - 1)
	if d > maxd || d <= 0 {
		d = maxd
	}
	c.next = now.Add(d)
	f.retries[k] = c
	f.logf("close %s/%s (message %s): %v (try %d, again in %s)", k.Instance, k.ID, k.msg, err, c.tries, d)
}

// nextRetry is when the earliest pending retry is due.
func (f *Facade) nextRetry() (time.Time, bool) {
	var next time.Time
	for _, c := range f.retries {
		if next.IsZero() || c.next.Before(next) {
			next = c.next
		}
	}
	return next, !next.IsZero()
}

// retryCloses tries again at most retriesPerPass of the closes due at
// now, each within retryTimeout.
func (f *Facade) retryCloses(ctx context.Context, now time.Time) {
	n := 0
	for k, c := range f.retries {
		if c.next.After(now) {
			continue
		}
		if n++; n > retriesPerPass {
			return
		}
		if err := f.closeOnce(ctx, c.ref, c.card, c.outcome); err != nil {
			f.failed(k, c, err, time.Now())
			continue
		}
		delete(f.retries, k)
		f.logf("close %s/%s (message %s): done", k.Instance, k.ID, k.msg)
	}
}

// retrySoon makes the failed closes of ticket r due now, unless one was
// tried less than RetryBase ago (a burst of clicks does not hammer a
// rate-limited service). Such a try does not count toward RetryTries.
func (f *Facade) retrySoon(r store.Ref, now time.Time) {
	for k, c := range f.retries {
		if k.Ref == r && now.Sub(c.last) >= f.retryBase() && c.next.After(now) {
			c.next, c.clicked = now, true
		}
	}
}

func (f *Facade) logf(format string, a ...any) {
	if f.Log != nil {
		fmt.Fprintf(f.Log, "lockhub: %s: "+format+"\n", append([]any{f.T.Facade()}, a...)...)
	}
}

// sync posts new pending tickets and closes those that left the queue.
func (f *Facade) sync(ctx context.Context, shown map[store.Ref]*posted, tks []store.Ticket) {
	pending := map[store.Ref]bool{}
	for _, t := range tks {
		r := store.Ref{Instance: t.Instance, ID: t.ID}
		pending[r] = true
		if shown[r] != nil || f.answered[r] {
			// answered: decided here, in a snapshot taken before.
			continue
		}
		c, ok := CardOf(t, f.H.Routes(), f.T.Facade())
		if !ok {
			continue
		}
		ref, err := f.T.Post(ctx, c)
		if err != nil {
			f.logf("post %s/%s: %v", t.Instance, t.ID, err)
			continue
		}
		shown[r] = &posted{ref, c}
	}
	for r, p := range shown {
		if !pending[r] {
			f.close(ctx, r, p, "no longer pending (answered elsewhere, withdrawn or expired)")
			delete(shown, r)
		}
	}
	for r := range f.answered {
		if !pending[r] {
			delete(f.answered, r)
		}
	}
}

func (f *Facade) answer(ctx context.Context, shown map[store.Ref]*posted, a Answer) {
	reply := func(s string) {
		if a.Reply != nil {
			a.Reply(ctx, s)
		}
	}
	r := store.Ref{Instance: a.Instance, ID: a.ID}
	p := shown[r]
	switch {
	case p == nil:
		// A stale button (its close failed or is still being retried,
		// or the facade restarted): refused here, and by the hub, which
		// decides only pending tickets. A close waiting for its retry
		// is tried again now.
		reply("this ticket is no longer pending")
		f.retrySoon(r, time.Now())
		return
	case !p.card.Answerable:
		reply(p.card.Why)
		return
	}
	_, err := f.H.Decide(ctx, r, hub.Verdict{Approved: a.Approve, ApproverID: a.ApproverID, ApproverDisplay: a.Display, Facade: f.T.Facade()})
	if err != nil {
		if errors.Is(err, hub.ErrNotRouted) || errors.Is(err, hub.ErrRetype) {
			reply("the hub refused: " + err.Error())
		} else {
			reply("the hub could not record the answer")
			f.logf("decide %s/%s: %v", a.Instance, a.ID, err)
		}
		return
	}
	reply("")
	verb := "denied"
	if a.Approve {
		verb = "approved"
	}
	f.close(ctx, r, p, verb+" by "+a.Display)
	delete(shown, r)
	if f.answered == nil {
		f.answered = map[store.Ref]bool{}
	}
	f.answered[r] = true
}
