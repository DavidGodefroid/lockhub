package loxrun

import (
	"context"
	"crypto/ed25519"
	"io"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
)

// Hub is what lox run needs of the hub's facade socket
// (approve.Client).
type Hub interface {
	QueueAll(ctx context.Context, since uint64, wait time.Duration) (api.QueueResult, error)
	Decide(ctx context.Context, instance, id string, req api.DecideRequest) error
	State(ctx context.Context, instance, id string) (api.TicketState, error)
}

var _ Hub = (*approve.Client)(nil)

// EventKind is what an Observe hook is told.
type EventKind string

// Events.
const (
	EvTicket   EventKind = "ticket"   // a new ticket in the feed
	EvQuestion EventKind = "question" // a question card waits (the bell rang)
	EvDecided  EventKind = "decided"  // the hub signed lox run's decision
	EvFailed   EventKind = "failed"   // a decision could not be sent
	EvResult   EventKind = "result"   // a decided ticket's result (consumed, expired…)
	EvMode     EventKind = "mode"     // the mode changed
	EvHub      EventKind = "hub"      // the hub became reachable or not
	EvShown    EventKind = "shown"    // another question is on top now (ID; "" none): keys typed before were dropped
)

// Event is one thing that happened in a session.
type Event struct {
	Kind     EventKind
	Instance string
	ID       string
	// Approved and Rule are the decision (EvDecided); Rule "" is the
	// human's.
	Approved bool
	Rule     string
	Result   Result
	Mode     Mode
	Err      error
}

// Session is one `lox run`'s decision service: Run follows the hub's
// queue and serves decisions until ctx ends or the human quits. When it
// returns, nothing decides any more: pending and new tickets wait at the
// hub (fail closed).
type Session struct {
	Hub Hub
	// Keys are the human's key presses (a terminal in raw mode).
	Keys <-chan Key
	// Out is the terminal. Size returns its size; nil (no terminal on
	// stdout) logs plain lines instead of drawing frames.
	Out  io.Writer
	Size func() (w, h int)
	// Resize ticks on a terminal resize (SIGWINCH).
	Resize <-chan struct{}
	Style  Style
	// Workspace and Locks are shown in the header.
	Workspace string
	Locks     int
	// LockKeys are the lock keys lox up pinned, by instance: a ticket is
	// decided by a rule, or gets a secret, only once it verifies under
	// its lock's.
	LockKeys map[string]ed25519.PublicKey
	// Display is the human's name for the decisions ($USER).
	Display string
	Mode    Mode
	// Rules are the profiles' auto-mode rules (nil: the defaults).
	Rules func(instance, profile string) ProfileRules
	Now   func() time.Time
	// Observe, if set, is told every Event (tests, logs). It runs on the
	// session's loop: it must not block.
	Observe func(Event)
	// IdleConn is how long a profile without a ticket stays shown as
	// connected (the locks close idle connections: lazyconn.DefaultIdle).
	IdleConn time.Duration
	// ReconnectAsk: a profile that asks to connect again this soon after
	// the lock connected on it, with no other ticket of the profile in
	// between, has its session connection and secret dropped and is
	// asked again: the connection did not work (a mistyped password the
	// backend took at the dial and refused after), and the session must
	// not send the same credentials on every retry. Default 30s;
	// negative turns it off.
	ReconnectAsk time.Duration
	// KeyArm is how long the question on top must have been shown
	// before y or n (or Enter on its prompt) answers it: a key pressed
	// for the question that just went away never answers the one that
	// took its place. When the top question changes, the keys already
	// typed are dropped too. Default 400ms; negative turns both off
	// (tests that answer as soon as a question comes).
	KeyArm time.Duration
	// Audit, if set, reads the hub's audit (lox audit's exchanges and
	// sessions): the a key shows it, read again every second while it is
	// open. Unset, a shows this session's decisions only.
	Audit func() ([]Exchange, []RunEvent, error)
	// QueueWait is the hub long-poll (default 25s); StatePoll how often
	// decided tickets' results are fetched (default 2s).
	QueueWait, StatePoll time.Duration
}

// tracked is a ticket lox run follows.
type tracked struct {
	instance, id string
	entry        *Entry
	req          Request
	tk           *ticket.Ticket
	item         api.QueueItem
	card         *Card
	decided      bool // lox run's decision is signed (or not lox run's to take)
	sending      bool // a decision is on its way
	profileKey   string
	gen          int // the profile's generation when it came: x bumps it
	answer
}

// state is the session's state, owned by Run's loop.
type state struct {
	s       *Session
	eng     *Engine
	feed    []*Entry
	cards   []*tracked
	seen    map[string]*tracked // instance/id
	results map[string]*tracked // decided, result not known yet
	conns   map[string]*ProfileConn
	active  map[string]time.Time // profile key → last ticket
	// secrets typed for "ask" profiles, kept in this process for the
	// session only (wiped when Run returns), sealed again to each
	// connect ticket of that profile.
	secrets map[string][]byte
	// ran: when the lock last connected on a profile, while no other
	// ticket of the profile came since (ReconnectAsk).
	ran map[string]time.Time
	// gen counts, per profile, the times the human dropped the session's
	// connection (x): a connect that comes back from before does not
	// put back what was dropped.
	gen      map[string]int
	hubOK    bool
	hubErr   string
	overlay  string
	audit    auditView
	flash    string
	flashTo  time.Time
	quitting bool
	pending  []effect
	bell     bool
	dirty    bool
	drawn    int // frames drawn (a terminal's first one clears it)
	keyGuard
}

// keyGuard ties the human's keys to the question the screen showed: y
// and n answer the card on top only once it has been shown (KeyArm),
// and the keys typed into a prompt whose card went away are dropped
// until Enter or Esc, never read as answers to the next card.
type keyGuard struct {
	shownTop    *tracked  // the card on top as last shown (nil none)
	shownAt     time.Time // when it came on top
	shownPrompt bool      // its prompt was open then
	discard     bool      // the card of an open prompt went away: keys are its input until Enter/Esc
	flushKeys   bool      // the top card changed: drop the keys already typed
}

// effect is a call the loop makes outside its state.
type effect struct {
	t   *tracked
	req api.DecideRequest
}

const maxFeed = 500

func key(instance, id string) string { return instance + "/" + id }

func (s *Session) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Session) observe(e Event) {
	if s.Observe != nil {
		s.Observe(e)
	}
}

func newState(s *Session) *state {
	st := &state{s: s, eng: NewEngine(s.Mode), seen: map[string]*tracked{}, results: map[string]*tracked{},
		conns: map[string]*ProfileConn{}, active: map[string]time.Time{}, secrets: map[string][]byte{},
		ran: map[string]time.Time{}, gen: map[string]int{}, dirty: true}
	st.eng.Rules = s.Rules
	return st
}

// Run serves decisions until ctx ends or the human quits (q q, Ctrl-C).
func (s *Session) Run(ctx context.Context) error {
	if s.QueueWait == 0 {
		s.QueueWait = 25 * time.Second
	}
	if s.StatePoll == 0 {
		s.StatePoll = 2 * time.Second
	}
	if s.IdleConn == 0 {
		s.IdleConn = 2 * time.Minute
	}
	if s.KeyArm == 0 {
		s.KeyArm = 400 * time.Millisecond
	}
	if s.ReconnectAsk == 0 {
		s.ReconnectAsk = 30 * time.Second
	}
	st := newState(s)
	defer st.wipe()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	type queueMsg struct {
		res api.QueueResult
		err error
	}
	queueCh := make(chan queueMsg, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ver uint64
		wait := time.Duration(0)
		backoff := 500 * time.Millisecond
		for ctx.Err() == nil {
			res, err := s.Hub.QueueAll(ctx, ver, wait)
			if ctx.Err() != nil {
				return
			}
			select {
			case queueCh <- queueMsg{res, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return
				}
				backoff = min(backoff*2, 5*time.Second)
				wait = 0
				continue
			}
			backoff = 500 * time.Millisecond
			ver, wait = res.Version, s.QueueWait
		}
	}()

	type decideMsg struct {
		t   *tracked
		req api.DecideRequest
		err error
	}
	decideCh := make(chan decideMsg, 16)
	type stateMsg struct {
		t   *tracked
		res api.TicketState
		err error
	}
	stateCh := make(chan stateMsg, 64)
	polling := false

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	statePoll := time.NewTicker(s.StatePoll)
	defer statePoll.Stop()

	if s.Size == nil {
		st.logf("lox run: serving decisions in %s mode (Shift+Tab switches; q q quits)", st.eng.Mode)
	}
	for {
		for _, ef := range st.pending {
			ef := ef
			ef.t.sending = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := s.Hub.Decide(ctx, ef.t.instance, ef.t.id, ef.req)
				select {
				case decideCh <- decideMsg{ef.t, ef.req, err}:
				case <-ctx.Done():
				}
			}()
		}
		st.pending = nil
		st.syncTop()
		if st.flushKeys {
			st.flushKeys = false
			if st.dropTyped() {
				return nil
			}
			ev := Event{Kind: EvShown}
			if t := st.shownTop; t != nil {
				ev.Instance, ev.ID = t.instance, t.id
			}
			st.s.observe(ev)
		}
		st.draw()
		select {
		case <-ctx.Done():
			return nil
		case m := <-queueCh:
			st.onQueue(m.res, m.err)
		case k, ok := <-s.Keys:
			if !ok {
				s.Keys = nil
				continue
			}
			if st.onKey(k) {
				return nil
			}
		case <-s.Resize:
			st.dirty = true
		case m := <-decideCh:
			st.onDecided(m.t, m.req, m.err)
		case m := <-stateCh:
			if m.t == nil {
				polling = false // the batch is done
				continue
			}
			st.onState(m.t, m.res, m.err)
		case <-statePoll.C:
			if polling || len(st.results) == 0 {
				continue
			}
			polling = true
			batch := make([]*tracked, 0, len(st.results))
			for _, t := range st.results {
				batch = append(batch, t)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i, t := range batch {
					if i == 32 {
						break
					}
					res, err := s.Hub.State(ctx, t.instance, t.id)
					select {
					case stateCh <- stateMsg{t, res, err}:
					case <-ctx.Done():
						return
					}
				}
				select {
				case stateCh <- stateMsg{}:
				case <-ctx.Done():
				}
			}()
		case <-tick.C:
			st.onTick()
		}
	}
}
