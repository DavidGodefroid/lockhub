package hub_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

var human = hub.Asker{Facade: "tty", ApproverID: "host:uid:1000", ApproverDisplay: "david"}

// A human withdrawing a pending ticket ends it withdrawn at the hub, frees
// the instance's pending slot, sends its lock a signed denial naming the
// withdrawal (the lock ends its plan and answers the agent), and audits
// who withdrew it.
func TestWithdrawByHuman(t *testing.T) {
	a := hubtest.NewLock("shop-prod")
	e := hubtest.New(t, 1, a)
	if _, _, err := e.Hub.Push(ctx, "shop-prod", a.Ticket("T1", "read", e.Clock.T, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Hub.Push(ctx, "shop-prod", a.Ticket("T2", "read", e.Clock.T, 0)); !errors.Is(err, hub.ErrTooMany) {
		t.Fatalf("second push with a full queue = %v, want ErrTooMany", err)
	}
	ref := store.Ref{Instance: "shop-prod", ID: "T1"}
	res, err := e.Hub.WithdrawByHuman(ctx, ref, human, hub.ViaRun)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Told || res.Reason != "withdrawn by david in lox run" {
		t.Errorf("result = %+v", res)
	}
	if ps, _ := e.Store.Tickets(ctx, state.Withdrawn); len(ps) != 1 || ps[0].ID != "T1" {
		t.Errorf("withdrawn = %v", ps)
	}
	ds, err := e.Hub.Decisions(ctx, "shop-prod", 0, 0)
	if err != nil || len(ds) != 1 {
		t.Fatalf("Decisions = %v, %v", ds, err)
	}
	var d hubtest.Decision
	json.Unmarshal(ds[0].Raw, &d)
	if d.Approved || d.Ticket != "T1" || d.Facade != "tty" || d.Approver != "host:uid:1000" || d.Reason != "withdrawn by david in lox run" {
		t.Errorf("decision = %+v", d)
	}
	if _, _, err := e.Hub.Push(ctx, "shop-prod", a.Ticket("T2", "read", e.Clock.T, 0)); err != nil {
		t.Errorf("push after the withdrawal = %v: the slot is not freed", err)
	}
	// The lock pushing the withdrawn ticket again (a restart's Sync)
	// does not bring it back.
	if _, created, err := e.Hub.Push(ctx, "shop-prod", a.Ticket("T1", "read", e.Clock.T, 0)); err != nil || created {
		t.Errorf("re-push = %v, %v", created, err)
	}
	if ps, _ := e.Store.Tickets(ctx, state.Withdrawn); len(ps) != 1 {
		t.Errorf("withdrawn after re-push = %v", ps)
	}
	if _, err := e.Hub.WithdrawByHuman(ctx, ref, human, hub.ViaRun); err == nil {
		t.Error("a withdrawn ticket withdrawn again")
	}
	b, _ := os.ReadFile(e.Audit)
	var rec audit.Record
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r audit.Record
		json.Unmarshal([]byte(l), &r)
		if r.Event == "withdraw" {
			rec = r
		}
	}
	if rec.Ticket != "T1" || rec.State != "withdrawn" || rec.Approver != "host:uid:1000" || rec.Facade != "tty" ||
		rec.Reason != "withdrawn by david in lox run" || rec.Decision == "" {
		t.Errorf("audit record = %+v", rec)
	}
	f, _ := os.Open(e.Audit)
	defer f.Close()
	if _, err := audit.Verify(f); err != nil {
		t.Errorf("audit: %v", err)
	}
}

// A ticket the hub cannot verify any more (its stored signature no longer
// checks) is still withdrawn: no decision can be signed for it, and the
// audit says so.
func TestWithdrawUnverifiable(t *testing.T) {
	a := hubtest.NewLock("shop-prod")
	e := hubtest.New(t, 0, a)
	raw := a.Ticket("T1", "read", e.Clock.T, 0)
	if _, _, err := e.Hub.Push(ctx, "shop-prod", raw); err != nil {
		t.Fatal(err)
	}
	// The lock's key changed since (lox run --rotate): the stored ticket
	// no longer verifies.
	ref := store.Ref{Instance: "shop-prod", ID: "T1"}
	rotated := hubtest.NewLock("shop-prod")
	e3 := reopen(t, e, rotated)
	res, err := e3.WithdrawByHuman(ctx, ref, human, hub.ViaCLI)
	if err != nil {
		t.Fatal(err)
	}
	if res.Told || !strings.HasPrefix(res.Reason, "withdrawn by david in lox withdraw") || !strings.Contains(res.Reason, "cannot verify") {
		t.Errorf("result = %+v", res)
	}
	if ds, _ := e3.Decisions(ctx, "shop-prod", 0, 0); len(ds) != 0 {
		t.Errorf("a decision on an unverifiable ticket: %v", ds)
	}
	if ps, _ := e.Store.Tickets(ctx, state.Withdrawn); len(ps) != 1 {
		t.Errorf("withdrawn = %v", ps)
	}
}

// reopen is a hub on e's storage whose only lock is l.
func reopen(t *testing.T, e hubtest.Env, l hubtest.Lock) *hub.Hub {
	t.Helper()
	return hub.New(hub.Config{Store: e.Store, Audit: e.Log, Codec: hubtest.Codec{}, Key: e.Key,
		Locks: map[string]ed25519.PublicKey{l.Instance: l.Pub}, Now: e.Clock.Now})
}

func TestWithdrawRefusals(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "a", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	ref := store.Ref{Instance: "a", ID: "T1"}
	for _, c := range []struct {
		name string
		a    hub.Asker
		via  string
	}{
		{"no approver", hub.Asker{Facade: "tty"}, hub.ViaRun},
		{"chat facade", hub.Asker{Facade: "slack", ApproverID: "U1"}, hub.ViaRun},
		{"unknown via", human, "a chat"},
	} {
		if _, err := e.Hub.WithdrawByHuman(ctx, ref, c.a, c.via); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	if _, err := e.Hub.WithdrawByHuman(ctx, store.Ref{Instance: "a", ID: "nope"}, human, hub.ViaRun); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown ticket: %v", err)
	}
	if _, err := e.Hub.Decide(ctx, ref, approve("T1")); err != nil {
		t.Fatal(err)
	}
	var te state.ErrTransition
	if _, err := e.Hub.WithdrawByHuman(ctx, ref, human, hub.ViaRun); !errors.As(err, &te) {
		t.Errorf("approved ticket: %v, want a transition error", err)
	}
}
