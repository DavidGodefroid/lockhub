package loxrun_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// decided is GET /v1/decided on the facade socket, as lea reads it to
// tell each agent the decisions on its tickets (lea's hub sync).
func (w *world) decided(since int64) api.DecidedResult {
	w.t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", w.sock)
	}}, Timeout: 5 * time.Second}
	res, err := c.Get("http://lockhub/v1/decided?since=" + strconv.FormatInt(since, 10))
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		w.t.Fatalf("GET /v1/decided: %s", res.Status)
	}
	var out api.DecidedResult
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		w.t.Fatal(err)
	}
	return out
}

// An auto decision that lands after the lock's short wait (lockkit
// hubclient.DecisionWait, lockhub#200): the agent heard pending, and no
// facade's queue showed the ticket, which an auto rule decides in
// milliseconds. The decisions lea reads carry the decision, its rule and
// the decided ticket, whose requester names the agent lea tells, as it
// tells a human's decision; the lock then runs the ticket.
func TestAutoDecisionAfterWaitReachesAgent(t *testing.T) {
	w := newWorldCfg(t, worldCfg{arm: -1, later: true})

	sel := w.submit(ticket.KindRead, ticket.RiskRead, "B", "SELECT id FROM customers WHERE email = ")
	start := time.Now()
	if w.lock.Await(context.Background(), sel, hubclient.DecisionWait) {
		t.Fatal("decided with no lox run: want the agent to hear pending")
	}
	if waited := time.Since(start); waited < hubclient.DecisionWait {
		t.Fatalf("the lock waited %v, want its whole window (%v)", waited, hubclient.DecisionWait)
	}
	if got := w.decided(0).Decisions; len(got) != 0 {
		t.Fatalf("decisions before lox run: %+v", got)
	}

	// lox run starts after the window: its auto rule decides the read.
	w.startRun()
	if e := w.wait(loxrun.EvDecided, sel); !e.Approved || e.Rule != "default:read" {
		t.Fatalf("decision %+v: want auto by default:read", e)
	}

	res := w.decided(0)
	if len(res.Decisions) != 1 || res.Decisions[0].Ticket != sel || res.Cursor != res.Decisions[0].Seq {
		t.Fatalf("decided %+v: want the one decision on %s", res, sel)
	}
	it := res.Decisions[0]
	dec, err := ticket.VerifyDecision(w.hubPub, it.Decision)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Decision != ticket.Approved || !dec.Auto() || dec.Rule.ID != "default:read" || dec.Instance != inst {
		t.Fatalf("signed decision %+v: want approved by default:read on %s", dec, inst)
	}
	var req struct {
		ID        string           `json:"id"`
		Requester ticket.Requester `json:"requester"`
	}
	if err := json.Unmarshal(it.Request, &req); err != nil {
		t.Fatalf("request %s: %v", it.Request, err)
	}
	if req.ID != sel || req.Requester != (ticket.Requester{Agent: "dev-1", Session: "s1"}) {
		t.Fatalf("decided ticket %s: want %s asked by dev-1 in session s1", it.Request, sel)
	}
	if got := w.decided(res.Cursor).Decisions; len(got) != 0 {
		t.Fatalf("decisions after the cursor: %+v", got)
	}

	// The lock has the decision: the agent's run of the ticket goes on.
	if !w.lock.Await(context.Background(), sel, hubclient.DecisionWait) {
		t.Fatal("the lock does not have the auto decision")
	}
}
