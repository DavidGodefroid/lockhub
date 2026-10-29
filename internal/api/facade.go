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

// QueueResult answers GET /v1/queue.
type QueueResult struct {
	Tickets []QueueItem `json:"tickets"`
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
	tks, err := f.h.Queue(r.Context(), wait)
	if err != nil {
		if r.Context().Err() == nil {
			fail(w, err)
		}
		return
	}
	res := QueueResult{Tickets: []QueueItem{}}
	for _, t := range tks {
		it := QueueItem{ID: t.ID, Instance: t.Instance, Risk: t.Risk, Created: t.Created,
			Facades: f.h.Routes().Facades(t.Instance, t.Risk), Ticket: t.Raw}
		if !t.Expires.IsZero() {
			e := t.Expires
			it.Expires = &e
		}
		res.Tickets = append(res.Tickets, it)
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
	p := peer.From(r.Context())
	approver := "host"
	if p.Known {
		approver = fmt.Sprintf("host:uid:%d", p.UID)
	}
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
