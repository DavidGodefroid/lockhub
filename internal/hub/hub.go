// Package hub is the approval hub's core: it accepts signed tickets from
// locks, records a human decision once per ticket, signs that decision,
// and hands each lock its own decisions.
//
// The hub never runs a request and never sees results. What it stores is
// what the locks signed (masked screens) and what it signed itself.
package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Info is what the hub needs from a verified ticket.
type Info struct {
	ID       string
	Instance string
	KeyID    string
	Risk     string
	PlanHash string
	Created  time.Time
	// TTL is how long the ticket may wait for a decision; 0: no limit.
	TTL time.Duration
	// Production tickets with a Retype need the human to type it.
	Production bool
	Retype     string
}

// Verdict is a human's answer, as a facade reports it.
type Verdict struct {
	Approved bool
	Reason   string
	// ApproverID identifies the human as the facade authenticated them
	// (a host account, a Slack user id…); Display is for screens.
	ApproverID      string
	ApproverDisplay string
	Facade          string
	// Retype is what the human typed, for production tickets.
	Retype string
}

// Codec is the ticket format: lockkit's ticket package in production,
// a fake in tests. It is the only place that knows the wire format.
type Codec interface {
	// VerifyTicket checks raw against the lock's key and returns its
	// fields.
	VerifyTicket(lock ed25519.PublicKey, raw []byte) (Info, error)
	// SignDecision builds and signs the decision on ticket t.
	SignDecision(hub ed25519.PrivateKey, t Info, v Verdict, at time.Time) ([]byte, error)
	// KeyID names a lock key as tickets do.
	KeyID(ed25519.PublicKey) string
	// TicketVersions are the ticket schema versions VerifyTicket
	// accepts, ascending.
	TicketVersions() []int
	// VerifyRequest checks a lock's request signature (Lock-Sig) over
	// the request's method, path and query, instance, time, nonce and body.
	VerifyRequest(lock ed25519.PublicKey, method, pathQuery, instance string, at time.Time, nonce string, body []byte, sig string) bool
}

// Errors the API maps to statuses.
var (
	ErrUnknownLock = errors.New("unknown lock instance")
	ErrForbidden   = errors.New("ticket does not belong to the calling instance")
	ErrBadTicket   = errors.New("ticket does not verify")
	ErrTooMany     = errors.New("too many pending tickets for this instance")
	ErrExpired     = errors.New("ticket expired")
	ErrNotRouted   = errors.New("this facade may not decide this ticket")
	ErrBadRequest  = errors.New("bad request")
	ErrRetype      = errors.New("approving this production ticket needs its name typed exactly")
)

// Config builds a Hub.
type Config struct {
	Store *store.Store
	Audit *audit.Log
	Codec Codec
	Key   ed25519.PrivateKey
	// Locks are the lock instances allowed to push, by instance name.
	Locks map[string]ed25519.PublicKey
	// MaxPending caps an instance's pending tickets (default 50).
	MaxPending int
	// Routes decides which facade may answer which ticket.
	Routes route.Rules
	// MaxSkew is how far in the future a ticket's creation time may be
	// (default 1 min).
	MaxSkew time.Duration
	Now     func() time.Time
}

// Hub is safe for concurrent use.
type Hub struct {
	c Config

	auditMu sync.Mutex // one outbox flush at a time

	mu       sync.Mutex
	waiters  map[string]chan struct{} // instance → closed on a new decision
	queueVer uint64                   // bumped on every change of the pending queue
}

// New returns a hub.
func New(c Config) *Hub {
	if c.MaxPending == 0 {
		c.MaxPending = 50
	}
	if c.MaxSkew == 0 {
		c.MaxSkew = time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Hub{c: c, waiters: map[string]chan struct{}{}}
}

// LockKey is the key of an instance.
func (h *Hub) LockKey(instance string) (ed25519.PublicKey, bool) {
	k, ok := h.c.Locks[instance]
	return k, ok
}

// Routes is the routing in force.
func (h *Hub) Routes() route.Rules { return h.c.Routes }

// Codec is the hub's codec.
func (h *Hub) Codec() Codec { return h.c.Codec }

// Now is the hub's clock.
func (h *Hub) Now() time.Time { return h.c.Now() }

// KeyID names the hub's key as decisions and tickets name keys ("" for
// a hub without a key).
func (h *Hub) KeyID() string {
	if len(h.c.Key) != ed25519.PrivateKeySize {
		return ""
	}
	return h.c.Codec.KeyID(h.c.Key.Public().(ed25519.PublicKey))
}

// Store is the hub's store.
func (h *Hub) Store() *store.Store { return h.c.Store }

func hashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// Every state change writes its audit record in the store transaction
// (the outbox, outbox.go), and the record goes to the audit log after the
// commit: an uncommitted change never has an audit record, and a
// committed one always gets one, at the latest when the hub next starts.

// Push accepts a ticket from instance. Sending the same ticket again is
// not an error (created is false).
func (h *Hub) Push(ctx context.Context, instance string, raw []byte) (info Info, created bool, err error) {
	key, ok := h.c.Locks[instance]
	if !ok {
		return Info{}, false, ErrUnknownLock
	}
	info, err = h.c.Codec.VerifyTicket(key, raw)
	if err != nil {
		return Info{}, false, fmt.Errorf("%w: %v", ErrBadTicket, err)
	}
	if info.Instance != instance || info.KeyID != h.c.Codec.KeyID(key) {
		return Info{}, false, ErrForbidden
	}
	if !validID(info.ID) || !route.KnownRisk(info.Risk) || len(info.PlanHash) > MaxID {
		return Info{}, false, fmt.Errorf("%w: bad id, risk class or plan hash", ErrBadTicket)
	}
	now := h.c.Now()
	if info.Created.After(now.Add(h.c.MaxSkew)) {
		return Info{}, false, fmt.Errorf("%w: created in the future", ErrBadTicket)
	}
	var expires time.Time
	if info.TTL > 0 {
		expires = info.Created.Add(info.TTL)
		if !expires.After(now) {
			return Info{}, false, ErrExpired
		}
	}
	if err := h.auditReady(ctx); err != nil {
		return Info{}, false, err
	}
	err = h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.Ticket(store.Ref{Instance: instance, ID: info.ID}); errors.Is(err, store.ErrNotFound) {
			n, err := tx.CountPending(instance)
			if err != nil {
				return err
			}
			if n >= h.c.MaxPending {
				return ErrTooMany
			}
		}
		created, err = tx.PutTicket(store.Ticket{
			ID: info.ID, Instance: instance, Risk: info.Risk, PlanHash: info.PlanHash,
			State: state.Pending, Raw: raw, Created: info.Created, Expires: expires, Updated: now,
		})
		if err != nil || !created {
			return err
		}
		return h.audit(tx, audit.Record{Event: "push", Ticket: info.ID, Instance: instance, Risk: info.Risk, State: string(state.Pending)})
	})
	if err == nil && created {
		h.flushAudit(ctx)
		h.notify(queueKey)
	}
	return info, created, err
}

// change applies ev to a ticket and audits it.
func (h *Hub) change(ctx context.Context, ref store.Ref, ev state.Event, rec audit.Record) error {
	if err := h.auditReady(ctx); err != nil {
		return err
	}
	err := h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		tk, err := tx.Ticket(ref)
		if err != nil {
			return err
		}
		to, err := state.Next(tk.State, ev)
		if err != nil {
			return err
		}
		if err := tx.SetState(ref, tk.State, to, h.c.Now()); err != nil {
			return err
		}
		rec.Event, rec.Ticket, rec.Instance, rec.Risk, rec.State = string(ev), ref.ID, ref.Instance, tk.Risk, string(to)
		return h.audit(tx, rec)
	})
	if err == nil {
		h.flushAudit(ctx)
		h.notify(queueKey)
	}
	return err
}

// queueKey wakes facades waiting for a change of the pending queue.
const queueKey = "\x00queue"

// Queue returns the pending tickets, oldest first, and the queue's
// version. With wait > 0 and the version still since, it first waits up
// to wait for a change, so a facade polling with its last version never
// misses one.
func (h *Hub) Queue(ctx context.Context, since uint64, wait time.Duration) ([]store.Ticket, uint64, error) {
	h.mu.Lock()
	ver := h.queueVer
	h.mu.Unlock()
	if wait > 0 && ver == since {
		ch := h.waiter(queueKey)
		h.mu.Lock()
		ver = h.queueVer
		h.mu.Unlock()
		if ver == since {
			t := time.NewTimer(wait)
			defer t.Stop()
			select {
			case <-ch:
			case <-t.C:
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
	}
	h.mu.Lock()
	ver = h.queueVer
	h.mu.Unlock()
	tks, err := h.c.Store.Tickets(ctx, state.Pending)
	return tks, ver, err
}

// Withdraw is a lock taking back one of its pending tickets.
func (h *Hub) Withdraw(ctx context.Context, instance, id, reason string) error {
	if len(reason) > MaxReason {
		return fmt.Errorf("%w: reason over %d bytes", ErrBadRequest, MaxReason)
	}
	return h.change(ctx, store.Ref{Instance: instance, ID: id}, state.Withdraw, audit.Record{Reason: reason})
}

// Consumed is a lock reporting it executed an approved ticket.
func (h *Hub) Consumed(ctx context.Context, instance, id string) error {
	return h.change(ctx, store.Ref{Instance: instance, ID: id}, state.Consume, audit.Record{})
}

// Decide records a human's verdict on a pending ticket and signs it.
// A ticket gets one decision: a second Decide fails.
func (h *Hub) Decide(ctx context.Context, ref store.Ref, v Verdict) ([]byte, error) {
	if v.ApproverID == "" || v.Facade == "" {
		return nil, fmt.Errorf("%w: a decision needs an approver and a facade", ErrBadRequest)
	}
	if len(v.Reason) > MaxReason || len(v.ApproverID) > MaxID || len(v.ApproverDisplay) > MaxID || len(v.Retype) > MaxID {
		return nil, fmt.Errorf("%w: field too long", ErrBadRequest)
	}
	if err := h.auditReady(ctx); err != nil {
		return nil, err
	}
	var raw []byte
	var instance string
	err := h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		tk, err := tx.Ticket(ref)
		if err != nil {
			return err
		}
		ev := state.Deny
		if v.Approved {
			ev = state.Approve
		}
		to, err := state.Next(tk.State, ev)
		if err != nil {
			return err
		}
		if err := h.c.Routes.Allowed(tk.Instance, v.Facade, tk.Risk); err != nil {
			return fmt.Errorf("%w: %v", ErrNotRouted, err)
		}
		now := h.c.Now()
		if !tk.Expires.IsZero() && !tk.Expires.After(now) {
			return ErrExpired
		}
		info, err := h.c.Codec.VerifyTicket(h.c.Locks[tk.Instance], tk.Raw)
		if err != nil {
			return fmt.Errorf("%w: stored ticket: %v", ErrBadTicket, err)
		}
		// Production tickets are answered where the human can see them:
		// never on a chat facade, whatever the facade itself checks.
		if info.Production && !route.CanReveal(v.Facade) {
			return fmt.Errorf("%w: production tickets are answered in the terminal or the deck", ErrNotRouted)
		}
		if v.Approved && info.Production && info.Retype != "" && v.Retype != info.Retype {
			return ErrRetype
		}
		raw, err = h.c.Codec.SignDecision(h.c.Key, info, v, now)
		if err != nil {
			return err
		}
		if err := tx.SetState(ref, tk.State, to, now); err != nil {
			return err
		}
		if _, err := tx.PutDecision(store.Decision{Ticket: ref.ID, Instance: tk.Instance, Raw: raw, At: now}); err != nil {
			return err
		}
		instance = tk.Instance
		return h.audit(tx, audit.Record{
			Event: string(ev), Ticket: ref.ID, Instance: tk.Instance, Risk: tk.Risk, State: string(to),
			Approver: v.ApproverID, Facade: v.Facade, Reason: v.Reason, Decision: hashBytes(raw),
		})
	})
	if err != nil {
		return nil, err
	}
	h.flushAudit(ctx)
	h.notify(instance)
	h.notify(queueKey)
	return raw, nil
}

func (h *Hub) notify(instance string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if instance == queueKey {
		h.queueVer++
	}
	if ch, ok := h.waiters[instance]; ok {
		close(ch)
		delete(h.waiters, instance)
	}
}

func (h *Hub) waiter(instance string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.waiters[instance]
	if !ok {
		ch = make(chan struct{})
		h.waiters[instance] = ch
	}
	return ch
}

// Decisions returns instance's decisions after seq since. With wait > 0
// and none yet, it waits up to wait for one (long poll).
func (h *Hub) Decisions(ctx context.Context, instance string, since int64, wait time.Duration) ([]store.Decision, error) {
	const limit = 100
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		ch := h.waiter(instance) // before the query: no lost wake-up
		ds, err := h.c.Store.Decisions(ctx, instance, since, limit)
		if err != nil || len(ds) > 0 || wait <= 0 {
			return ds, err
		}
		select {
		case <-ch:
		case <-deadline.C:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Sweep expires pending tickets past their TTL and drops old request
// nonces. Run it periodically.
func (h *Hub) Sweep(ctx context.Context) error {
	// Records of committed changes a failed flush left in the outbox; while
	// they cannot be logged, expiries are refused like any change (Decide
	// refuses an expired ticket by itself), and nonces are still purged.
	ferr := h.FlushAudit(ctx)
	now := h.c.Now()
	var errs []error
	if ferr == nil {
		ids, err := h.c.Store.DueForExpiry(ctx, now)
		if err != nil {
			errs = append(errs, err)
		}
		for _, ref := range ids {
			err := h.change(ctx, ref, state.Expire, audit.Record{})
			var te state.ErrTransition
			if err != nil && !errors.As(err, &te) && !errors.Is(err, store.ErrStale) {
				errs = append(errs, err)
				break
			}
		}
	} else {
		errs = append(errs, ferr)
	}
	errs = append(errs, h.c.Store.PurgeNonces(ctx, now.Add(-2*RequestWindow)))
	return errors.Join(errs...)
}

// Field limits: what a lock or a facade sends is bounded before it
// reaches the store or the audit log.
const (
	MaxID     = 128
	MaxReason = 1024
)

// validID accepts ticket ids of 1 to MaxID characters from [A-Za-z0-9._-].
func validID(id string) bool {
	if id == "" || len(id) > MaxID {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// RequestWindow is how far a lock request's time may be from the hub's.
const RequestWindow = time.Minute
