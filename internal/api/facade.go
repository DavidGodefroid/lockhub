package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// FacadeHandler returns the routes for local facades (`lox approve`, the
// lea deck). It is served only on the host facade socket, never on the
// hub network: whoever can open that socket is the human of this host.
// The approver is recorded from the socket peer's uid.
//
// extra adds routes of facades running in the hub (the mobile facade's
// pairing and device routes).
func FacadeHandler(h *hub.Hub, extra ...func(*http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	for _, x := range extra {
		x(mux)
	}
	f := &facades{h: h}
	mux.HandleFunc("GET /v1/hub", f.hubInfo)
	mux.HandleFunc("GET /v1/queue", f.queue)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/decide", f.decide)
	mux.HandleFunc("GET /v1/decided", f.decided)
	mux.HandleFunc("GET /v1/tickets/{instance}/{id}", f.ticket)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/reveal", f.reveal)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/renew", f.renew)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/withdraw", f.withdraw)
	return mux
}

type facades struct{ h *hub.Hub }

// HubInfo answers GET /v1/hub: which hub serves this facade socket. Two
// workspaces on one host share $XDG_RUNTIME_DIR/lockhub/facade.sock; lox
// run compares Key with its own workspace's hub key before serving
// decisions, so it never shows another workspace's tickets (#172).
type HubInfo struct {
	// Key is the hub's public signing key (base64, as hub.pub holds it).
	Key string `json:"key"`
}

func (f *facades) hubInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HubInfo{Key: keys.Public(f.h.PublicKey())})
}

// QueueItem is a pending ticket. Ticket is the lock's signed ticket,
// verbatim (its screen is masked by the lock).
type QueueItem struct {
	ID       string          `json:"id"`
	Instance string          `json:"instance"`
	Risk     string          `json:"risk"`
	Created  time.Time       `json:"created"`
	Expires  *time.Time      `json:"expires,omitempty"`
	Facades  []string        `json:"facades"`
	Ticket   json.RawMessage `json:"ticket"`
	// Retype is the name the human types to approve the ticket (its
	// instance name), "" when y approves it: the hub's rule, the one
	// decide enforces, so a facade never derives it from the ticket.
	Retype string `json:"retype,omitempty"`
}

// QueueResult answers GET /v1/queue. Version changes with every change
// of the queue: send it back as since to wait for the next one.
//
// Expired lists the tickets that expired in the last 24 hours and that no
// ticket renews yet, most recent first: a facade offers them for
// re-approval (POST …/renew). Facades of an expired item are the ones
// that may renew it.
type QueueResult struct {
	Tickets []QueueItem `json:"tickets"`
	Version uint64      `json:"version"`
	Expired []QueueItem `json:"expired"`
}

func waitParam(r *http.Request) (time.Duration, error) {
	v := r.URL.Query().Get("wait")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, errors.New("wait is a non-negative integer")
	}
	return min(time.Duration(n)*time.Second, MaxWait), nil
}

func (f *facades) queue(w http.ResponseWriter, r *http.Request) {
	wait, err := waitParam(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	var since uint64
	if v := r.URL.Query().Get("since"); v != "" {
		if since, err = strconv.ParseUint(v, 10, 64); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "since is the version of the last queue seen")
			return
		}
	}
	tks, ver, err := f.h.Queue(r.Context(), since, wait)
	if err != nil {
		if r.Context().Err() == nil {
			fail(w, err)
		}
		return
	}
	exp, err := f.h.Expired(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	res := QueueResult{Tickets: []QueueItem{}, Version: ver, Expired: []QueueItem{}}
	item := func(t store.Ticket, facades []string) QueueItem {
		it := QueueItem{ID: t.ID, Instance: t.Instance, Risk: t.Risk, Created: t.Created, Facades: facades, Ticket: t.Raw,
			Retype: f.h.RetypeName(t)}
		if !t.Expires.IsZero() {
			e := t.Expires
			it.Expires = &e
		}
		return it
	}
	for _, t := range tks {
		res.Tickets = append(res.Tickets, item(t, f.h.Routes().Facades(t.Instance, t.Risk)))
	}
	for _, t := range exp {
		fs := []string{}
		for _, x := range f.h.Routes().Facades(t.Instance, t.Risk) {
			if route.OnDemand(x) {
				fs = append(fs, x)
			}
		}
		res.Expired = append(res.Expired, item(t, fs))
	}
	writeJSON(w, http.StatusOK, res)
}

// DecideRequest is POST /v1/tickets/{instance}/{id}/decide.
type DecideRequest struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
	Retype   string `json:"retype,omitempty"`
	// Facade is tty or deck: the local facades.
	Facade string `json:"facade"`
	// Display is the human's name for screens (the facade's $USER).
	Display string `json:"display,omitempty"`
	// Rule, from lox run only (facade tty), is the id of the auto rule
	// that decided: no human answered (the decision names it). Absent:
	// the human at the facade decided.
	Rule string `json:"rule,omitempty"`
	// Asked, from lox run only with no Rule, is why the human was asked
	// (the auto mode's reason): the hub's audit record keeps it.
	Asked string `json:"asked,omitempty"`
	// Secret is the backend's secret sealed by lox run to the lock's
	// one-use key (lockkit ticket.Sealed), on the approval of a connect
	// ticket that asks for it. The hub cannot open it.
	Secret json.RawMessage `json:"secret,omitempty"`
}

// DecideResult answers it with the signed decision.
type DecideResult struct {
	Decision json.RawMessage `json:"decision"`
}

func (f *facades) decide(w http.ResponseWriter, r *http.Request) {
	var req DecideRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a decide request")
		return
	}
	if req.Facade != route.TTY && req.Facade != route.Deck {
		writeErr(w, http.StatusBadRequest, "bad_request", "facade must be tty or deck on this socket")
		return
	}
	// Every decision names its approver: a connection whose peer the
	// kernel cannot tell is refused.
	p := peer.From(r.Context())
	if !p.Known {
		writeErr(w, http.StatusForbidden, "unknown_peer", "the facade socket cannot identify this connection's user")
		return
	}
	approver := fmt.Sprintf("host:uid:%d", p.UID)
	ref := store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")}
	raw, err := f.h.Decide(r.Context(), ref, hub.Verdict{
		Approved: req.Approved, Reason: req.Reason, Retype: req.Retype,
		ApproverID: approver, ApproverDisplay: req.Display, Facade: req.Facade,
		Rule: req.Rule, Asked: req.Asked, Secret: req.Secret,
	})
	switch {
	case errors.Is(err, hub.ErrNotAuto):
		writeErr(w, http.StatusConflict, "needs_human", err.Error())
	case errors.Is(err, hub.ErrNotRouted):
		writeErr(w, http.StatusForbidden, "not_routed", err.Error())
	case errors.Is(err, hub.ErrRetype):
		writeErr(w, http.StatusUnprocessableEntity, "retype", err.Error())
	case err != nil:
		fail(w, err)
	default:
		writeJSON(w, http.StatusOK, DecideResult{Decision: raw})
	}
}

// RevealRequest is POST /v1/tickets/{instance}/{id}/reveal: Key is the
// facade's ephemeral key, signed by its pinned facade key (lockkit
// ticket.RevealKey), whose facade must be Facade.
type RevealRequest struct {
	Facade  string          `json:"facade"`
	Display string          `json:"display,omitempty"`
	Key     json.RawMessage `json:"key"`
}

// RevealResult answers it with the lock's signed answer, verbatim
// (lockkit ticket.RevealAnswer): the clear screen sealed to Key, which
// only the facade opens (ticket.OpenReveal).
type RevealResult struct {
	Answer json.RawMessage `json:"answer"`
}

// RenewRequest is POST /v1/tickets/{instance}/{id}/renew, on an expired
// ticket.
type RenewRequest struct {
	Facade  string `json:"facade"`
	Display string `json:"display,omitempty"`
}

// RenewResult answers it with the renewal's ticket. AutoApproved: the
// hub approved it at once, as nothing changed since the approval (not for
// production); otherwise it waits in the queue with its changes.
type RenewResult struct {
	Ticket       string `json:"ticket"`
	AutoApproved bool   `json:"auto_approved"`
}

// asker reads a facade request body and its human.
func asker(w http.ResponseWriter, r *http.Request, v any, facade, display func() string) (hub.Asker, bool) {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a request of this route")
		return hub.Asker{}, false
	}
	if f := facade(); f != route.TTY && f != route.Deck {
		writeErr(w, http.StatusBadRequest, "bad_request", "facade must be tty or deck on this socket")
		return hub.Asker{}, false
	}
	p := peer.From(r.Context())
	if !p.Known {
		writeErr(w, http.StatusForbidden, "unknown_peer", "the facade socket cannot identify this connection's user")
		return hub.Asker{}, false
	}
	return hub.Asker{Facade: facade(), ApproverID: fmt.Sprintf("host:uid:%d", p.UID), ApproverDisplay: display()}, true
}

func (f *facades) reveal(w http.ResponseWriter, r *http.Request) {
	var req RevealRequest
	a, ok := asker(w, r, &req, func() string { return req.Facade }, func() string { return req.Display })
	if !ok {
		return
	}
	ref := store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")}
	ans, err := f.h.Reveal(r.Context(), ref, a, req.Key)
	if err != nil {
		if r.Context().Err() == nil {
			fail(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, RevealResult{Answer: ans})
}

func (f *facades) renew(w http.ResponseWriter, r *http.Request) {
	var req RenewRequest
	a, ok := asker(w, r, &req, func() string { return req.Facade }, func() string { return req.Display })
	if !ok {
		return
	}
	ref := store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")}
	res, err := f.h.Renew(r.Context(), ref, a)
	if err != nil {
		if r.Context().Err() == nil {
			fail(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, RenewResult{Ticket: res.Ticket, AutoApproved: res.AutoApproved})
}

// WithdrawRequest is POST /v1/tickets/{instance}/{id}/withdraw: the human
// takes back a pending ticket (lox run, lox withdraw). Via is where:
// "lox run" or "lox withdraw".
type WithdrawRequest struct {
	Facade  string `json:"facade"`
	Display string `json:"display,omitempty"`
	Via     string `json:"via"`
}

// WithdrawResult answers it: the audited reason, and whether the lock
// was told (a signed denial naming the withdrawal; false for a ticket the
// hub cannot verify).
type WithdrawResult struct {
	Reason string `json:"reason"`
	Told   bool   `json:"told"`
}

func (f *facades) withdraw(w http.ResponseWriter, r *http.Request) {
	var req WithdrawRequest
	a, ok := asker(w, r, &req, func() string { return req.Facade }, func() string { return req.Display })
	if !ok {
		return
	}
	ref := store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")}
	res, err := f.h.WithdrawByHuman(r.Context(), ref, a, req.Via)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, WithdrawResult{Reason: res.Reason, Told: res.Told})
}

// TicketState answers GET /v1/tickets/{instance}/{id}: the ticket's state
// (pending, approved, denied, withdrawn, expired, consumed, lock_removed).
type TicketState struct {
	ID       string     `json:"id"`
	Instance string     `json:"instance"`
	Risk     string     `json:"risk"`
	State    string     `json:"state"`
	Updated  time.Time  `json:"updated"`
	Expires  *time.Time `json:"expires,omitempty"`
}

func (f *facades) ticket(w http.ResponseWriter, r *http.Request) {
	var tk store.Ticket
	err := f.h.Store().Tx(r.Context(), func(tx *store.Tx) error {
		var err error
		tk, err = tx.Ticket(store.Ref{Instance: r.PathValue("instance"), ID: r.PathValue("id")})
		return err
	})
	if err != nil {
		fail(w, err)
		return
	}
	res := TicketState{ID: tk.ID, Instance: tk.Instance, Risk: tk.Risk, State: string(tk.State), Updated: tk.Updated}
	if !tk.Expires.IsZero() {
		e := tk.Expires
		res.Expires = &e
	}
	writeJSON(w, http.StatusOK, res)
}

// DecidedItem is one decision in GET /v1/decided: the lock API's item,
// and Request, the decided ticket as its lock signed it (verbatim, as
// GET /v1/queue serves it). Its requester names the agent that waits on
// the decision: an auto rule decides a ticket in milliseconds, before any
// queue a facade reads shows it, and every decision, auto included,
// reaches the agent that asked (lockhub#200).
type DecidedItem struct {
	DecisionItem
	Request json.RawMessage `json:"request,omitempty"`
}

// DecidedResult answers GET /v1/decided. Cursor is the seq to send as
// since next time.
type DecidedResult struct {
	Decisions []DecidedItem `json:"decisions"`
	Cursor    int64         `json:"cursor"`
}

// decided lists every decision after a cursor (read-only, for lea).
func (f *facades) decided(w http.ResponseWriter, r *http.Request) {
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if r.URL.Query().Get("since") == "" {
		since, err = 0, nil
	}
	if err != nil || since < 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "since is a non-negative integer")
		return
	}
	ds, err := f.h.Store().AllDecisions(r.Context(), since, 500)
	if err != nil {
		fail(w, err)
		return
	}
	res := DecidedResult{Decisions: []DecidedItem{}, Cursor: since}
	for _, d := range ds {
		res.Decisions = append(res.Decisions, DecidedItem{DecisionItem: DecisionItem{Seq: d.Seq, Ticket: d.Ticket, Decision: d.Raw},
			Request: d.TicketRaw})
		res.Cursor = d.Seq
	}
	writeJSON(w, http.StatusOK, res)
}
