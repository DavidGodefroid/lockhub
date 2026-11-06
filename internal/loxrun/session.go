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
	secrets  map[string][]byte
	hubOK    bool
	hubErr   string
	overlay  string
	flash    string
	flashTo  time.Time
	quitting bool
	pending  []effect
	bell     bool
	dirty    bool
	drawn    int // frames drawn (a terminal's first one clears it)
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
	st := &state{s: s, eng: NewEngine(s.Mode), seen: map[string]*tracked{}, results: map[string]*tracked{},
		conns: map[string]*ProfileConn{}, active: map[string]time.Time{}, secrets: map[string][]byte{}, dirty: true}
	st.eng.Rules = s.Rules
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
