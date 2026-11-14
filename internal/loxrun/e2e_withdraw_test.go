package loxrun_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
)

// The stuck queue of lockhub#148, end to end: the lock's queue fills with
// tickets lox run cannot verify (its pinned key is not the lock's) and no
// facade watched here may answer (routed to the phone only), so the lock
// refuses every new request. In lox run, w lists them with their age, U
// and y withdraw them all: each ends withdrawn at the hub, audited with
// the human, its lock gets the hub's signed denial naming the withdrawal
// and ends the plan, its agent hears "withdrawn", and the lock takes a new
// request again.
func TestRunE2EWithdrawStuckQueue(t *testing.T) {
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	w := newWorldCfg(t, worldCfg{arm: -1, pinned: wrong, rateN: 100,
		routes: route.Rules{Only: map[string][]string{inst: {route.Mobile}}}})
	var stuck []string
	for i := 0; i < hubclient.MaxPending; i++ {
		id := w.submit(ticket.KindRead, ticket.RiskRead, "B", "SELECT id FROM orders WHERE id < 2")
		w.wait(loxrun.EvTicket, id)
		stuck = append(stuck, id)
	}
	if _, err := w.trySubmit(); !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("a request on a full queue: %v, want ErrRateLimited", err)
	}

	w.press(loxrun.R('w'), loxrun.R('U'))
	waitOut(t, w, fmt.Sprintf("withdraw all %d unverifiable tickets of shop? [y/N]", hubclient.MaxPending))
	w.press(loxrun.R('y'))
	// Withdrawn concurrently: in any order.
	left := map[string]bool{}
	for _, id := range stuck {
		left[id] = true
	}
	for len(left) > 0 {
		e := w.wait(loxrun.EvWithdrawn, "")
		if e.Err != nil || !left[e.ID] {
			t.Fatalf("withdraw %s: %v", e.ID, e.Err)
		}
		delete(left, e.ID)
	}
	waitOut(t, w, fmt.Sprintf("withdrew %d tickets", hubclient.MaxPending))
	for _, id := range stuck {
		if s := w.ticketState(id); s != state.Withdrawn {
			t.Errorf("%s is %s at the hub", id, s)
		}
		if d := w.decision(id); d.Decision != ticket.Denied || d.Reason != "withdrawn by david in lox run" || d.Facade != "tty" {
			t.Errorf("decision on %s: %+v", id, d)
		}
	}
	// The agent comes back for each: told it was withdrawn, its plan ended.
	for _, id := range stuck {
		_, err := w.begin(id)
		if !errors.Is(err, hubclient.ErrDenied) || !strings.Contains(err.Error(), "withdrawn by david in lox run") {
			t.Fatalf("the agent's run of %s: %v", id, err)
		}
	}
	if n := len(w.plans.Pending()); n != 0 {
		t.Errorf("%d plans still pending at the lock", n)
	}
	if _, err := w.trySubmit(); err != nil {
		t.Fatalf("a new request after the purge: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(w.dir, "tickets.jsonl"))
	if n := strings.Count(string(b), `"event":"withdraw"`); n != hubclient.MaxPending {
		t.Errorf("%d withdrawals in the hub's audit, want %d", n, hubclient.MaxPending)
	}
	// lox audit: each withdrawal with the human, the facade and the reason.
	xs, _, err := loxaudit.Load(context.Background(), loxaudit.Source{Data: w.dir, HubKeys: []ed25519.PublicKey{w.hubPub}})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range xs {
		if x.State == "withdrawn" {
			n++
			if x.Approver != "david" || x.Facade != "tty" || x.Reason != "withdrawn by david in lox run" || x.Result != loxrun.ResWithdrawn {
				t.Errorf("lox audit: %+v", x)
			}
		}
	}
	if n != hubclient.MaxPending {
		t.Errorf("lox audit lists %d withdrawn exchanges", n)
	}
}

// trySubmit plans a read at the lock and submits its ticket.
func (w *world) trySubmit() (string, error) {
	in := map[string]string{"sql": "sha256:" + strings.Repeat("c", 64), "n": ticket.NewNonce()}
	hash, _ := ticket.HashOf(in)
	p, err := w.plans.Create(plans.Binding{UID: caller.UID, Agent: "dev-1", TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: hash, Inputs: in}, []byte(`{}`), 0)
	if err != nil {
		return "", err
	}
	tk := ticket.NewKindTicket(ticket.Source{Lock: "locksql"}, ticket.KindRead, ticket.RiskRead, &ticket.Subject{Profile: "B"},
		hash, policyFP, time.Now(), time.Hour)
	masked := render.MaskScreen(render.ScreenSource{Header: inst + " / B · read", Body: []render.Line{{{Text: "SELECT 1"}}}}, render.Masking{})
	return w.lock.Submit(context.Background(), w.plans, p.ID, caller, tk, masked)
}

// begin is the agent's run of ticket id at the lock, once the lock has
// the hub's decision.
func (w *world) begin(id string) (*plans.Plan, error) {
	w.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		p, _, err := w.lock.Begin(w.plans, id, caller, func(p *plans.Plan) (string, string, error) {
			return p.Binding.PolicyFP, p.Binding.PlanHash, nil
		})
		if !errors.Is(err, hubclient.ErrPending) || time.Now().After(deadline) {
			return p, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitOut waits for lox run's terminal to show s.
func waitOut(t *testing.T, w *world, s string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(w.out.String(), s) {
		if time.Now().After(deadline) {
			t.Fatalf("lox run never showed %q; terminal:\n%s", s, w.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
