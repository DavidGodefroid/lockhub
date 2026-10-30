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
	// Renews, when set, makes this ticket the renewal of an expired one.
	Renews *Renewal
}

// Renewal is what the hub needs of a ticket's Renews (lockkit
// ticket.Renewal).
type Renewal struct {
	// Of is the expired ticket, of the same instance.
	Of string
	// Unchanged: the lock checked the plan-hash inputs and none moved
	// (lockkit Renewal.Unchanged).
	Unchanged bool
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
	// VerifyRequest checks a lock's request signature (Lock-Sig) over
	// the request's method, path and query, instance, time, nonce and body.
	VerifyRequest(lock ed25519.PublicKey, method, pathQuery, instance string, at time.Time, nonce string, body []byte, sig string) bool
	// NewID makes a hub request id.
	NewID(now time.Time) string
	// SignRequest builds and signs a hub request to a lock. A reveal
	// carries the facade's signed key verbatim; one for another ticket,
	// lock key or facade than q's is ErrForeignKey.
	SignRequest(hub ed25519.PrivateKey, q Request) ([]byte, error)
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
	// RequestWait is how long a facade waits for a lock's answer to a
	// hub request (default RequestWait).
	RequestWait time.Duration
	Now         func() time.Time
}

// Hub is safe for concurrent use.
type Hub struct {
	c Config

	mu       sync.Mutex
	waiters  map[string]chan struct{}       // instance → closed on a new decision or request
	queueVer uint64                         // bumped on every change of the pending queue
	reqs     map[string]map[string]*openReq // instance → id → open hub request
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
	if c.RequestWait == 0 {
		c.RequestWait = RequestWait
	}
	return &Hub{c: c, waiters: map[string]chan struct{}{}, reqs: map[string]map[string]*openReq{}}
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

// Store is the hub's store.
func (h *Hub) Store() *store.Store { return h.c.Store }

func hashBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// Every state change appends its audit record inside the store
// transaction, before the commit: if the audit write fails, the change is
// rolled back (fail closed). A commit that fails after a successful
// append leaves a record of an attempted change; lock audit verify
// reports it as a record the database does not have.

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
		rec := audit.Record{Event: "push", Ticket: info.ID, Instance: instance, Risk: info.Risk, State: string(state.Pending)}
		if info.Renews != nil {
			rec.Reason = "renews " + info.Renews.Of
		}
		if _, err := h.c.Audit.Append(rec); err != nil {
			return err
		}
		return h.linkRenewal(tx, instance, info, now)
	})
	if err == nil && created {
		h.notify(queueKey)
	}
	return info, created, err
}

// linkRenewal links a new ticket to the expired ticket it renews, and
// ends that one expired if it was still pending or approved (the lock
// asked again: the old approval can no longer be used). A renewal of a
// ticket the hub does not know, or of one renewed already, is kept as an
// ordinary ticket.
func (h *Hub) linkRenewal(tx *store.Tx, instance string, info Info, now time.Time) error {
	if info.Renews == nil || info.Renews.Of == info.ID || !validID(info.Renews.Of) {
		return nil
	}
	ref := store.Ref{Instance: instance, ID: info.Renews.Of}
	old, err := tx.Ticket(ref)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	linked, err := tx.LinkRenewal(instance, ref.ID, info.ID, now)
	if err != nil || !linked {
		return err
	}
	if old.State != state.Pending && old.State != state.Approved {
		return nil
	}
	to, err := state.Next(old.State, state.Expire)
	if err != nil {
		return err
	}
	if err := tx.SetState(ref, old.State, to, now); err != nil {
		return err
	}
	_, err = h.c.Audit.Append(audit.Record{Event: string(state.Expire), Ticket: ref.ID, Instance: instance, Risk: old.Risk,
		State: string(to), Reason: "renewed by " + info.ID})
	return err
}

// change applies ev to a ticket and audits it.
func (h *Hub) change(ctx context.Context, ref store.Ref, ev state.Event, rec audit.Record) error {
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
		_, err = h.c.Audit.Append(rec)
		return err
	})
	if err == nil {
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
		_, err = h.c.Audit.Append(audit.Record{
			Event: string(ev), Ticket: ref.ID, Instance: tk.Instance, Risk: tk.Risk, State: string(to),
			Approver: v.ApproverID, Facade: v.Facade, Reason: v.Reason, Decision: hashBytes(raw),
		})
		return err
	})
	if err != nil {
		return nil, err
	}
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
	ds, _, err := h.Poll(ctx, instance, since, wait)
	return ds, err
}

// Poll is Decisions with the hub requests open for instance (signed,
// verbatim). A request the lock has not been given yet ends the wait at
// once; one already given comes again with every answer until the lock
// answers it or it expires.
func (h *Hub) Poll(ctx context.Context, instance string, since int64, wait time.Duration) ([]store.Decision, [][]byte, error) {
	const limit = 100
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		ch := h.waiter(instance) // before the query: no lost wake-up
		ds, err := h.c.Store.Decisions(ctx, instance, since, limit)
		if err != nil {
			return nil, nil, err
		}
		reqs, fresh := h.openRequests(instance)
		if len(ds) > 0 || fresh || wait <= 0 {
			return ds, reqs, nil
		}
		select {
		case <-ch:
		case <-deadline.C:
			reqs, _ := h.openRequests(instance)
			return nil, reqs, nil
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

// Sweep expires pending tickets past their TTL and drops old request
// nonces and hub requests. Run it periodically.
func (h *Hub) Sweep(ctx context.Context) error {
	now := h.c.Now()
	ids, err := h.c.Store.DueForExpiry(ctx, now)
	if err != nil {
		return err
	}
	for _, ref := range ids {
		err := h.change(ctx, ref, state.Expire, audit.Record{})
		var te state.ErrTransition
		if err != nil && !errors.As(err, &te) && !errors.Is(err, store.ErrStale) {
			return err
		}
	}
	h.purgeRequests(now)
	return h.c.Store.PurgeNonces(ctx, now.Add(-2*RequestWindow))
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
