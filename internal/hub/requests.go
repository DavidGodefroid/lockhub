package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Hub requests: what a human at a local facade asks of a lock about one
// of its tickets, besides a decision. A reveal (Ctrl-O) asks the lock to
// seal a ticket's clear screen to the facade's ephemeral key; a renewal
// asks it again for an expired ticket (decision H1). The hub signs the
// request, hands it to the lock in its long poll, and relays the lock's
// answer to the waiting facade. It keeps requests in memory only: the
// answer of a reveal is ciphertext the hub relays without storing,
// logging or auditing it.

// Request kinds (lockkit ticket.RequestKind).
const (
	KindReveal = "reveal"
	KindRenew  = "renew"
)

// Request is a hub request before the codec signs it.
type Request struct {
	ID       string
	Kind     string
	Ticket   string
	Instance string
	KeyID    string // the lock's key
	Facade   string
	// ApproverID and ApproverDisplay name the human, as for a decision.
	ApproverID      string
	ApproverDisplay string
	At              time.Time
	// RevealKey is the facade's signed ephemeral key, verbatim (reveal
	// only).
	RevealKey json.RawMessage
}

// Limits of hub requests.
const (
	// MaxOpenRequests caps the open requests of one instance.
	MaxOpenRequests = 8
	// RequestTTL is how long a lock may act on a request (lockkit
	// ticket.RevealTTL).
	RequestTTL = 2 * time.Minute
	// RequestWait is how long a facade waits for the lock's answer.
	RequestWait = 30 * time.Second
	// MaxAnswer bounds a lock's answer (a sealed clear screen).
	MaxAnswer = 512 << 10
	// MaxRevealKey bounds a facade's reveal key.
	MaxRevealKey = 4 << 10
	// ExpiredWindow is how long an expired ticket is offered for
	// re-approval.
	ExpiredWindow = 24 * time.Hour
)

// AnswerCodes are the error codes a lock answers with (lockkit hubclient
// Code*): the only error text the hub accepts from a lock and passes on.
var AnswerCodes = []string{"facade_refused", "not_pending", "no_clear_screen", "not_renewable", "recheck_failed", "policy_changed", "rate_limited", "failed"}

// Errors of hub requests.
var (
	ErrTimeout    = errors.New("the lock did not answer in time")
	ErrBusy       = errors.New("too many open requests for this instance")
	ErrNoRequest  = errors.New("no such open request for this instance")
	ErrForeignKey = errors.New("the reveal key is for another facade, ticket or lock")
	ErrBadAnswer  = errors.New("the lock's answer is not one this request expects")
	ErrState      = errors.New("the ticket is not in a state this request applies to")
)

// LockError is a lock refusing a request, with its code (AnswerCodes).
type LockError struct{ Code string }

func (e *LockError) Error() string { return "the lock refused: " + e.Code }

// Answer is a lock's answer to a request: exactly one member is set.
type Answer struct {
	// Reveal is the lock's signed, sealed answer, verbatim.
	Reveal json.RawMessage
	// Ticket is the renewal's ticket id.
	Ticket string
	// Error is the lock's code.
	Error string
}

type openReq struct {
	id, kind, ticket string
	raw              []byte
	expires          time.Time
	delivered        bool
	seq              uint64      // Hub.reqSeq when opened
	done             chan Answer // buffered: one answer
}

// Asker is the human asking, as a local facade reports them.
type Asker struct {
	Facade          string
	ApproverID      string
	ApproverDisplay string
}

func (a Asker) check() error {
	switch {
	case a.ApproverID == "" || a.Facade == "":
		return fmt.Errorf("%w: a request needs an approver and a facade", ErrBadRequest)
	case len(a.ApproverID) > MaxID || len(a.ApproverDisplay) > MaxID:
		return fmt.Errorf("%w: field too long", ErrBadRequest)
	case !route.OnDemand(a.Facade):
		return fmt.Errorf("%w: clear values and renewals are asked from the terminal or the deck only, not %s", ErrNotRouted, a.Facade)
	}
	return nil
}

// openRequests lists instance's open requests, oldest first, and reports
// whether one is fresh for a poll that began at request sequence start:
// never given to a lock yet, or opened after that poll began. All are
// given now. The second rule is for two pollers of one instance (a lock
// restarted while its old process still polls, a product with two
// clients): the first to return takes the request, and the other, woken
// by the same notify, must return too rather than wait out its poll with
// it (a lost wake-up). A poll that begins after a request was given does
// not return early for it, so a lock that does not answer cannot spin.
func (h *Hub) openRequests(instance string, start uint64) ([][]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.c.Now()
	var rs []*openReq
	for _, r := range h.reqs[instance] {
		if now.Before(r.expires) {
			rs = append(rs, r)
		}
	}
	slices.SortFunc(rs, func(a, b *openReq) int { return a.expires.Compare(b.expires) })
	var out [][]byte
	fresh := false
	for _, r := range rs {
		fresh = fresh || !r.delivered || r.seq > start
		r.delivered = true
		out = append(out, r.raw)
	}
	return out, fresh
}

func (h *Hub) purgeRequests(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for inst, m := range h.reqs {
		for id, r := range m {
			if !now.Before(r.expires) {
				delete(m, id)
			}
		}
		if len(m) == 0 {
			delete(h.reqs, inst)
		}
	}
}

func (h *Hub) dropRequest(instance, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.reqs[instance], id)
	if len(h.reqs[instance]) == 0 {
		delete(h.reqs, instance)
	}
}

// ask signs q, opens it for its instance's long poll and waits for the
// lock's answer (RequestWait at most).
func (h *Hub) ask(ctx context.Context, q Request) (Answer, error) {
	raw, err := h.c.Codec.SignRequest(h.c.Key, q)
	if err != nil {
		if errors.Is(err, ErrForeignKey) {
			return Answer{}, err
		}
		return Answer{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	r := &openReq{id: q.ID, kind: q.Kind, ticket: q.Ticket, raw: raw, expires: q.At.Add(RequestTTL), done: make(chan Answer, 1)}
	h.mu.Lock()
	now := h.c.Now()
	m := h.reqs[q.Instance]
	if m == nil {
		m = map[string]*openReq{}
		h.reqs[q.Instance] = m
	}
	for id, o := range m {
		if !now.Before(o.expires) {
			delete(m, id)
		}
	}
	if len(m) >= MaxOpenRequests {
		h.mu.Unlock()
		return Answer{}, ErrBusy
	}
	h.reqSeq++
	r.seq = h.reqSeq
	m[q.ID] = r
	h.mu.Unlock()
	h.notify(q.Instance) // wakes the lock's long poll
	defer h.dropRequest(q.Instance, q.ID)
	t := time.NewTimer(h.c.RequestWait)
	defer t.Stop()
	select {
	case a := <-r.done:
		if a.Error != "" {
			return a, &LockError{Code: a.Error}
		}
		return a, nil
	case <-t.C:
		return Answer{}, ErrTimeout
	case <-ctx.Done():
		return Answer{}, ctx.Err()
	}
}

// AnswerRequest is a lock's answer to request id: accepted only from the
// instance the request is for, once. body is one JSON object with exactly
// one of reveal (the lock's signed answer), ticket (a renewal's id) or
// error (a code of AnswerCodes; any other text becomes "failed": a lock's
// error text is never passed on).
//
// The request is looked up first: an answer the hub cannot use (too
// large, not one member) ends it "failed" at once, so the facade is not
// left waiting for the request's timeout.
func (h *Hub) AnswerRequest(instance, id string, body []byte) error {
	h.mu.Lock()
	r := h.reqs[instance][id]
	if r == nil || !h.c.Now().Before(r.expires) {
		h.mu.Unlock()
		return ErrNoRequest
	}
	delete(h.reqs[instance], id)
	h.mu.Unlock()
	fail := func(err error) error {
		r.done <- Answer{Error: "failed"}
		return err
	}
	if len(body) > MaxAnswer {
		return fail(fmt.Errorf("%w: answer over %d bytes", ErrBadRequest, MaxAnswer))
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || len(m) != 1 {
		return fail(fmt.Errorf("%w: an answer is an object with one member", ErrBadRequest))
	}
	var a Answer
	bad := func(why string) error { return fail(fmt.Errorf("%w: %s", ErrBadAnswer, why)) }
	switch {
	case m["reveal"] != nil:
		v := bytes.TrimSpace(m["reveal"])
		if r.kind != KindReveal || len(v) == 0 || v[0] != '{' {
			return bad("a reveal answer to a " + r.kind + " request")
		}
		a.Reveal = append(json.RawMessage(nil), v...)
	case m["ticket"] != nil:
		if r.kind != KindRenew || json.Unmarshal(m["ticket"], &a.Ticket) != nil || !validID(a.Ticket) {
			return bad("a ticket answer to a " + r.kind + " request, or no ticket id")
		}
	case m["error"] != nil:
		if json.Unmarshal(m["error"], &a.Error) != nil || !slices.Contains(AnswerCodes, a.Error) {
			a.Error = "failed"
		}
	default:
		return bad("unknown member")
	}
	r.done <- a
	return nil
}

// auditRequest records a reveal or a renewal: who asked, on which
// facade, and how it ended. Never what the lock answered.
// Through the outbox like every record, so the log keeps commit order.
func (h *Hub) auditRequest(kind string, tk store.Ticket, a Asker, outcome string) error {
	ctx := context.Background()
	if err := h.auditReady(ctx); err != nil {
		return err
	}
	err := h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		return h.audit(tx, audit.Record{Event: kind, Ticket: tk.ID, Instance: tk.Instance, Risk: tk.Risk,
			State: string(tk.State), Approver: a.ApproverID, Facade: a.Facade, Reason: outcome})
	})
	if err != nil {
		return err
	}
	return h.FlushAudit(ctx)
}

func outcome(err error) string {
	var le *LockError
	switch {
	case err == nil:
		return "answered"
	case errors.As(err, &le):
		return "lock refused: " + le.Code
	case errors.Is(err, ErrTimeout):
		return "timed out"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "abandoned"
	case errors.Is(err, ErrForeignKey):
		return "refused: reveal key of another facade"
	case errors.Is(err, ErrBusy):
		return "refused: too many open requests"
	}
	return "failed"
}

// requestable reads ref for a request of a: the ticket must be in st and
// routed to a's facade.
func (h *Hub) requestable(ctx context.Context, ref store.Ref, a Asker, st state.State) (store.Ticket, Info, error) {
	if err := a.check(); err != nil {
		return store.Ticket{}, Info{}, err
	}
	var tk store.Ticket
	err := h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		var err error
		tk, err = tx.Ticket(ref)
		return err
	})
	if err != nil {
		return tk, Info{}, err
	}
	key, ok := h.c.Locks[tk.Instance]
	if !ok {
		return tk, Info{}, ErrUnknownLock
	}
	info, err := h.c.Codec.VerifyTicket(key, tk.Raw)
	if err != nil {
		return tk, Info{}, fmt.Errorf("%w: stored ticket: %v", ErrBadTicket, err)
	}
	if err := h.c.Routes.Allowed(tk.Instance, a.Facade, tk.Risk); err != nil {
		_ = h.auditRequest(map[state.State]string{state.Pending: KindReveal, state.Expired: KindRenew}[st], tk, a, "refused: not routed")
		return tk, info, fmt.Errorf("%w: %v", ErrNotRouted, err)
	}
	if tk.State != st {
		return tk, info, fmt.Errorf("%w: ticket is %s, not %s", ErrState, tk.State, st)
	}
	return tk, info, nil
}

// Reveal asks the lock of ref, for the human a on a local facade, to seal
// the ticket's clear screen to key (the facade's signed ephemeral key,
// lockkit ticket.RevealKey) and returns the lock's signed answer,
// verbatim. Only a pending ticket routed to a's facade, from tty or deck.
// The hub cannot open the answer, and does not keep it.
func (h *Hub) Reveal(ctx context.Context, ref store.Ref, a Asker, key json.RawMessage) ([]byte, error) {
	if len(key) > MaxRevealKey {
		return nil, fmt.Errorf("%w: reveal key over %d bytes", ErrBadRequest, MaxRevealKey)
	}
	tk, info, err := h.requestable(ctx, ref, a, state.Pending)
	if err != nil {
		return nil, err
	}
	now := h.c.Now()
	ans, err := h.ask(ctx, Request{ID: h.c.Codec.NewID(now), Kind: KindReveal, Ticket: tk.ID, Instance: tk.Instance, KeyID: info.KeyID,
		Facade: a.Facade, ApproverID: a.ApproverID, ApproverDisplay: a.ApproverDisplay, At: now, RevealKey: key})
	if aerr := h.auditRequest(KindReveal, tk, a, outcome(err)); aerr != nil && err == nil {
		// Fail closed: a reveal the audit log cannot record is not shown.
		return nil, aerr
	}
	if err != nil {
		return nil, err
	}
	return ans.Reveal, nil
}

// Renewed is the outcome of Renew.
type Renewed struct {
	// Ticket is the renewal's id.
	Ticket string
	// AutoApproved: the hub approved the renewal on the human's request,
	// as nothing changed since their approval (decision H1).
	AutoApproved bool
}

// Reasons of a one-click approval of a renewal: of a ticket approved
// before (its approval aged out), or of one that expired undecided.
const (
	ReapprovalReason = "re-approved: nothing changed since approval"
	RenewalReason    = "approved on renewal: nothing changed since the expired ticket"
)

// Renew asks the lock of ref, for the human a on a local facade, to ask
// again for the expired ticket ref (a ticket the lock renewed already
// gives its renewal, without asking). When the renewal is unchanged (the
// lock compared the plan-hash inputs: none moved), not for production,
// and routed to a's facade, the hub approves it at once in a's name: the
// human's request is the one click of decision H1. Otherwise it waits in
// the queue like any ticket, with its changes (production: retype).
func (h *Hub) Renew(ctx context.Context, ref store.Ref, a Asker) (Renewed, error) {
	tk, info, err := h.requestable(ctx, ref, a, state.Expired)
	if err != nil {
		return Renewed{}, err
	}
	// Only what the facades offer: an old expired ticket is planned
	// again by the agent, not renewed in one click.
	if tk.Updated.Before(h.c.Now().Add(-ExpiredWindow)) {
		return Renewed{}, fmt.Errorf("%w: expired more than %s ago", ErrState, ExpiredWindow)
	}
	var existing string
	var approved bool
	err = h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		var err error
		if existing, err = tx.RenewalOf(ref); err != nil {
			return err
		}
		approved, err = tx.HasDecision(ref)
		return err
	})
	if err != nil {
		return Renewed{}, err
	}
	res := Renewed{Ticket: existing}
	if existing == "" {
		now := h.c.Now()
		ans, err := h.ask(ctx, Request{ID: h.c.Codec.NewID(now), Kind: KindRenew, Ticket: tk.ID, Instance: tk.Instance, KeyID: info.KeyID,
			Facade: a.Facade, ApproverID: a.ApproverID, ApproverDisplay: a.ApproverDisplay, At: now})
		if err != nil {
			if aerr := h.auditRequest(KindRenew, tk, a, outcome(err)); aerr != nil {
				err = errors.Join(err, aerr)
			}
			return Renewed{}, err
		}
		res.Ticket = ans.Ticket
	}
	res.AutoApproved, err = h.reapprove(ctx, ref, info, res.Ticket, a, approved)
	out := "renewal " + res.Ticket + ": pending"
	if res.AutoApproved {
		out = "renewal " + res.Ticket + ": re-approved, nothing changed"
	}
	if err != nil {
		out = "renewal " + res.Ticket + ": " + outcome(err)
	}
	if aerr := h.auditRequest(KindRenew, tk, a, out); aerr != nil && err == nil {
		err = aerr
	}
	return res, err
}

// reapprove approves renewal id of old (oldInfo) at once when H1 allows
// it. A renewal not at the hub yet (the lock will send it again) waits.
func (h *Hub) reapprove(ctx context.Context, old store.Ref, oldInfo Info, id string, a Asker, wasApproved bool) (bool, error) {
	ref := store.Ref{Instance: old.Instance, ID: id}
	var tk store.Ticket
	err := h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		var err error
		tk, err = tx.Ticket(ref)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	info, err := h.c.Codec.VerifyTicket(h.c.Locks[tk.Instance], tk.Raw)
	if err != nil {
		return false, fmt.Errorf("%w: stored ticket: %v", ErrBadTicket, err)
	}
	if info.Renews == nil || info.Renews.Of != old.ID {
		return false, fmt.Errorf("%w: ticket %s does not renew %s", ErrBadAnswer, id, old.ID)
	}
	// One click only for the same request: the lock says nothing
	// changed, and the hub checks what it can itself (risk and flags as
	// the old ticket's), never for production or a never-auto ticket.
	if tk.State != state.Pending || !info.Renews.Unchanged || info.Production || info.NeverAuto ||
		info.Risk != oldInfo.Risk || info.Flags != oldInfo.Flags ||
		h.c.Routes.Allowed(tk.Instance, a.Facade, tk.Risk) != nil {
		return false, nil
	}
	reason := RenewalReason
	if wasApproved {
		reason = ReapprovalReason
	}
	_, err = h.Decide(ctx, ref, Verdict{Approved: true, Reason: reason, ApproverID: a.ApproverID,
		ApproverDisplay: a.ApproverDisplay, Facade: a.Facade})
	var te state.ErrTransition
	if errors.As(err, &te) || errors.Is(err, store.ErrStale) {
		return false, nil // decided meanwhile
	}
	return err == nil, err
}

// Expired lists the tickets that expired in the last ExpiredWindow and
// that no ticket renews yet, most recent first: the facades offer them
// for re-approval.
func (h *Hub) Expired(ctx context.Context) ([]store.Ticket, error) {
	return h.c.Store.Expired(ctx, h.c.Now().Add(-ExpiredWindow), 100)
}
