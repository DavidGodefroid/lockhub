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
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// FacadeHandler returns the routes for local facades (`lock approve`, the
// lea deck). It is served only on the host facade socket, never on the
// hub network: whoever can open that socket is the human of this host.
// The approver is recorded from the socket peer's uid.
func FacadeHandler(h *hub.Hub) http.Handler {
	mux := http.NewServeMux()
	f := &facades{h: h}
	mux.HandleFunc("GET /v1/queue", f.queue)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/decide", f.decide)
	mux.HandleFunc("GET /v1/decided", f.decided)
	mux.HandleFunc("GET /v1/tickets/{instance}/{id}", f.ticket)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/reveal", f.reveal)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/renew", f.renew)
	return mux
}

type facades struct{ h *hub.Hub }

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
		it := QueueItem{ID: t.ID, Instance: t.Instance, Risk: t.Risk, Created: t.Created, Facades: facades, Ticket: t.Raw}
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
	})
	switch {
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

// TicketState answers GET /v1/tickets/{instance}/{id}: the ticket's state
// (pending, approved, denied, withdrawn, expired, consumed).
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
	res := DecisionsResult{Decisions: []DecisionItem{}, Cursor: since}
	for _, d := range ds {
		res.Decisions = append(res.Decisions, DecisionItem{Seq: d.Seq, Ticket: d.Ticket, Decision: d.Raw})
		res.Cursor = d.Seq
	}
	writeJSON(w, http.StatusOK, res)
}
