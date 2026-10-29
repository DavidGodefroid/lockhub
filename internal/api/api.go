// Package api is lockhub's HTTP API, version 1, for the locks (on the
// internal hub network). Facades use a separate handler on a host socket.
//
// Every lock request but GET /v1/hello is signed with the lock
// instance's key:
//
//	Lock-Instance: <instance>
//	Lock-Time:     <unix seconds>       (within RequestWindow of the hub)
//	Lock-Nonce:    <nonce>              (single use; lockkit ticket.NewNonce)
//	Lock-Sig:      lockkit ticket.SignBytes(key, ContextRequest,
//	               ticket.RequestMessage(method, path?query, instance, time, nonce, body))
//
// so that only an instance can push, withdraw or read its own tickets
// and decisions.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Version is the API version this hub speaks.
const Version = 1

// MaxBody bounds a request body (a ticket with its masked screen).
const MaxBody = 1 << 20

// MaxWait bounds a long poll.
const MaxWait = 60 * time.Second

// Hello is the answer to GET /v1/hello.
type Hello struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	API     int    `json:"api"`
}

// Error is every error body.
type Error struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Handler returns the hello route only (no hub configured).
func Handler(version string) http.Handler { return LockHandler(nil, version) }

// LockHandler returns the routes for locks. h nil serves hello only.
func LockHandler(h *hub.Hub, version string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Hello{Name: "lockhub", Version: version, API: Version})
	})
	if h == nil {
		return mux
	}
	a := &locks{h: h}
	mux.HandleFunc("POST /v1/tickets", a.auth(a.push))
	mux.HandleFunc("POST /v1/tickets/{id}/withdraw", a.auth(a.withdraw))
	mux.HandleFunc("POST /v1/tickets/{id}/consumed", a.auth(a.consumed))
	mux.HandleFunc("GET /v1/decisions", a.auth(a.decisions))
	return mux
}

type locks struct{ h *hub.Hub }

// validNonce accepts 16 to 128 characters of base64url or hex.
func validNonce(n string) bool {
	if len(n) < 16 || len(n) > 128 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

type authed func(w http.ResponseWriter, r *http.Request, instance string, body []byte)

func (a *locks) auth(next authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return
		}
		inst, ts, nonce := r.Header.Get("Lock-Instance"), r.Header.Get("Lock-Time"), r.Header.Get("Lock-Nonce")
		sig := r.Header.Get("Lock-Sig")
		key, known := a.h.LockKey(inst)
		sec, terr := strconv.ParseInt(ts, 10, 64)
		switch {
		case sig == "" || !known || terr != nil || !validNonce(nonce):
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or malformed request signature")
			return
		case !a.h.Codec().VerifyRequest(key, r.Method, r.URL.RequestURI(), inst, time.Unix(sec, 0), nonce, body, sig):
			writeErr(w, http.StatusUnauthorized, "unauthorized", "request signature does not verify")
			return
		}
		if d := a.h.Now().Sub(time.Unix(sec, 0)); d > hub.RequestWindow || d < -hub.RequestWindow {
			writeErr(w, http.StatusUnauthorized, "clock_skew", "request time too far from the hub's clock")
			return
		}
		err = a.h.Store().Tx(r.Context(), func(tx *store.Tx) error { return tx.UseNonce(inst, nonce, a.h.Now()) })
		if errors.Is(err, store.ErrReplay) {
			writeErr(w, http.StatusUnauthorized, "replay", "request nonce already used")
			return
		} else if err != nil {
			fail(w, err)
			return
		}
		next(w, r, inst, body)
	}
}

// PushResult answers POST /v1/tickets.
type PushResult struct {
	Ticket  string `json:"ticket"`
	Created bool   `json:"created"`
}

func (a *locks) push(w http.ResponseWriter, r *http.Request, inst string, body []byte) {
	info, created, err := a.h.Push(r.Context(), inst, body)
	if err != nil {
		fail(w, err)
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, PushResult{Ticket: info.ID, Created: created})
}

func (a *locks) withdraw(w http.ResponseWriter, r *http.Request, inst string, body []byte) {
	var req struct {
		Reason string `json:"reason"`
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "body is not JSON")
			return
		}
	}
	if err := a.h.Withdraw(r.Context(), inst, r.PathValue("id"), req.Reason); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *locks) consumed(w http.ResponseWriter, r *http.Request, inst string, _ []byte) {
	if err := a.h.Consumed(r.Context(), inst, r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DecisionItem is one decision in GET /v1/decisions: Decision is the
// signed decision, verbatim.
type DecisionItem struct {
	Seq      int64           `json:"seq"`
	Ticket   string          `json:"ticket"`
	Decision json.RawMessage `json:"decision"`
}

// DecisionsResult answers GET /v1/decisions. Cursor is the seq to send as
// since next time.
type DecisionsResult struct {
	Decisions []DecisionItem `json:"decisions"`
	Cursor    int64          `json:"cursor"`
}

func (a *locks) decisions(w http.ResponseWriter, r *http.Request, inst string, _ []byte) {
	q := r.URL.Query()
	since, err := strconv.ParseInt(q.Get("since"), 10, 64)
	if q.Get("since") == "" {
		since, err = 0, nil
	}
	wait, werr := strconv.Atoi(q.Get("wait"))
	if q.Get("wait") == "" {
		wait, werr = 0, nil
	}
	if err != nil || werr != nil || since < 0 || wait < 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "since and wait are non-negative integers")
		return
	}
	d := min(time.Duration(wait)*time.Second, MaxWait)
	ds, err := a.h.Decisions(r.Context(), inst, since, d)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		fail(w, err)
		return
	}
	res := DecisionsResult{Decisions: []DecisionItem{}, Cursor: since}
	for _, x := range ds {
		res.Decisions = append(res.Decisions, DecisionItem{Seq: x.Seq, Ticket: x.Ticket, Decision: x.Raw})
		res.Cursor = x.Seq
	}
	writeJSON(w, http.StatusOK, res)
}

func fail(w http.ResponseWriter, err error) {
	var te state.ErrTransition
	switch {
	case errors.Is(err, hub.ErrBadTicket), errors.Is(err, hub.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, "bad_ticket", err.Error())
	case errors.Is(err, hub.ErrForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, hub.ErrUnknownLock):
		writeErr(w, http.StatusUnauthorized, "unauthorized", err.Error())
	case errors.Is(err, hub.ErrTooMany):
		writeErr(w, http.StatusTooManyRequests, "too_many_pending", err.Error())
	case errors.Is(err, hub.ErrExpired):
		writeErr(w, http.StatusGone, "expired", err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrStale), errors.As(err, &te):
		writeErr(w, http.StatusConflict, "conflict", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeErr(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, Error{Error: kind, Message: msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
