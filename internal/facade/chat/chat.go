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
	if !rules.On(facade) {
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
	// Close rewrites message ref: no buttons, the outcome shown.
	Close(ctx context.Context, ref string, c Card, outcome string) error
	// Listen delivers authenticated answers until ctx ends.
	Listen(ctx context.Context, answers chan<- Answer) error
}

// Facade runs a transport against the hub.
type Facade struct {
	H   *hub.Hub
	T   Transport
	Log io.Writer
	// Wait is the queue long-poll (default 30s).
	Wait time.Duration
}

type posted struct {
	ref  string
	card Card
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
		if shown[r] != nil {
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
			if err := f.T.Close(ctx, p.ref, p.card, "no longer pending (answered elsewhere, withdrawn or expired)"); err != nil {
				f.logf("close %s/%s: %v", r.Instance, r.ID, err)
			}
			delete(shown, r)
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
		reply("this ticket is no longer pending")
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
	if err := f.T.Close(ctx, p.ref, p.card, verb+" by "+a.Display); err != nil {
		f.logf("close %s/%s: %v", a.Instance, a.ID, err)
	}
	delete(shown, r)
}
