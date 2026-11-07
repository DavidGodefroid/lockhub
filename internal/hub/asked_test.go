package hub_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// A human's decision at lox run keeps why it was asked in the audit
// record (#149); an auto rule's decision asked nobody, so it carries none.
func TestDecideAskedReason(t *testing.T) {
	a := hubtest.NewLock("shop")
	e := hubtest.New(t, 0, a)
	push := func(id string) {
		t.Helper()
		raw := a.TicketWith(id, "read", e.Clock.T, time.Hour, func(tk *hubtest.Ticket) { tk.V, tk.Kind, tk.Production = 2, "read", true })
		if _, _, err := e.Hub.Push(ctx, "shop", raw); err != nil {
			t.Fatal(err)
		}
	}
	why := "the lock wants a human for this read: its profile's auto rule for it is not auto"

	push("Q1")
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "Q1"},
		hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty", Asked: why}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(e.Audit)
	if !strings.Contains(string(b), `"asked":"`+why+`"`) {
		t.Errorf("audit record lacks why it was asked:\n%s", b)
	}

	push("Q2")
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "Q2"},
		hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty", Rule: "default:read", Asked: why}); !errors.Is(err, hub.ErrBadRequest) {
		t.Errorf("auto rule with a reason asked: %v, want bad request", err)
	}

	push("Q3")
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "Q3"},
		hub.Verdict{Approved: true, ApproverID: "x", Facade: "tty", Asked: strings.Repeat("x", hub.MaxReason+1)}); !errors.Is(err, hub.ErrBadRequest) {
		t.Errorf("reason too long: %v, want bad request", err)
	}
}
