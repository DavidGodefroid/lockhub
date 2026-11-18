package api_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// facadeSocket serves e's facade API on a unix socket (the kernel names
// the peer) and returns a client of it.
func facadeSocket(t *testing.T, e hubtest.Env) *approve.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "facade")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: api.FacadeHandler(e.Hub), ConnContext: peer.ConnContext}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return approve.Dial(sock)
}

// On the facade socket, facade live decides by a rule and withdraws in
// lox live; a reveal and a renewal are refused to it by name, on tickets
// the terminal is answered for.
func TestFacadeSocketLive(t *testing.T) {
	a := hubtest.NewLock("shop")
	e := hubtest.New(t, 0, a)
	c := facadeSocket(t, e)
	ctx := context.Background()
	v2 := func(id, risk string, ttl time.Duration) {
		t.Helper()
		raw := a.TicketWith(id, risk, e.Clock.T, ttl, func(tk *hubtest.Ticket) { tk.V, tk.Kind = 2, "read" })
		if _, _, err := e.Hub.Push(ctx, "shop", raw); err != nil {
			t.Fatal(err)
		}
	}
	stateOf := func(id string) state.State {
		var tk store.Ticket
		e.Store.Tx(ctx, func(tx *store.Tx) error {
			var err error
			tk, err = tx.Ticket(store.Ref{Instance: "shop", ID: id})
			return err
		})
		return tk.State
	}
	refused := func(what string, err error, status int, kind, text string) {
		t.Helper()
		var he *approve.HubError
		if !errors.As(err, &he) || he.Status != status || he.Kind != kind || !strings.Contains(he.Message, text) {
			t.Errorf("%s: %v (%+v), want %d %s %q", what, err, he, status, kind, text)
		}
	}
	info, err := c.HubInfo(ctx)
	if err != nil || !info.Live || info.Key == "" {
		t.Fatalf("GET /v1/hub: %+v %v", info, err)
	}

	v2("R1", "read", time.Hour)
	// A reveal of a pending ticket the terminal could ask: not facade live's.
	_, err = c.Reveal(ctx, "shop", "R1", api.RevealRequest{Facade: route.Live, Key: []byte(`{"ticket":"R1","facade":"live"}`)})
	refused("reveal by facade live", err, 400, "bad_request", "facade must be tty or deck")
	// A decision by a rule is taken; one without is not.
	refused("an approval without a rule", c.Decide(ctx, "shop", "R1", api.DecideRequest{Approved: true, Facade: route.Live}), 400, "bad_ticket", "only by an auto rule")
	if err := c.Decide(ctx, "shop", "R1", api.DecideRequest{Approved: true, Facade: route.Live, Rule: "profile:read"}); err != nil {
		t.Fatalf("a rule's decision by facade live: %v", err)
	}
	if s := stateOf("R1"); s != state.Approved {
		t.Fatalf("R1 is %s", s)
	}

	// A renewal of an expired ticket the terminal is offered: not facade live's.
	v2("R2", "read", time.Hour)
	e.Clock.T = e.Clock.T.Add(2 * time.Hour)
	if err := e.Hub.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	q, err := c.QueueAll(ctx, 0, 0)
	if err != nil || len(q.Expired) != 1 || q.Expired[0].ID != "R2" {
		t.Fatalf("expired offered: %+v %v", q.Expired, err)
	}
	_, err = c.Renew(ctx, "shop", "R2", api.RenewRequest{Facade: route.Live})
	refused("renew by facade live", err, 400, "bad_request", "facade must be tty or deck")
	if s := stateOf("R2"); s != state.Expired {
		t.Fatalf("R2 is %s", s)
	}

	// A withdrawal: facade live in lox live only.
	v2("R3", "read", 0)
	_, err = c.Withdraw(ctx, "shop", "R3", api.WithdrawRequest{Facade: route.Live, Via: hub.ViaCLI})
	refused("facade live in lox withdraw", err, 400, "bad_ticket", "lox live")
	_, err = c.Withdraw(ctx, "shop", "R3", api.WithdrawRequest{Facade: route.TTY, Via: hub.ViaLive})
	refused("the terminal in lox live", err, 400, "bad_ticket", "lox live")
	if res, err := c.Withdraw(ctx, "shop", "R3", api.WithdrawRequest{Facade: route.Live, Display: "uid 991 (status socket)", Via: hub.ViaLive}); err != nil || !res.Told {
		t.Fatalf("a withdrawal in lox live: %+v %v", res, err)
	}
	if s := stateOf("R3"); s != state.Withdrawn {
		t.Fatalf("R3 is %s", s)
	}
}
