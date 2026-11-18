package hub_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// lox live decides under its own facade name, by a rule only: the audit
// tells its rule decisions from the terminal's, and it never approves
// what a human must (never-auto, a typed name, typed values, a version-1
// ticket), nor anything without a rule.
func TestDecideFacadeLive(t *testing.T) {
	a := hubtest.NewLock("shop")
	e := hubtest.New(t, 0, a)
	v2 := func(id, risk string, mod func(*hubtest.Ticket)) []byte {
		return a.TicketWith(id, risk, e.Clock.T, time.Hour, func(tk *hubtest.Ticket) {
			tk.V, tk.Kind = 2, "read"
			if mod != nil {
				mod(tk)
			}
		})
	}
	push := func(raw []byte) {
		t.Helper()
		if _, _, err := e.Hub.Push(ctx, "shop", raw); err != nil {
			t.Fatal(err)
		}
	}
	live := hub.Verdict{Approved: true, ApproverID: "host:uid:990", Facade: route.Live, Rule: "profile:read"}

	// A read of a production profile, by a rule: signed and audited as live.
	push(v2("L1", "read", func(tk *hubtest.Ticket) { tk.Production = true }))
	raw, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "L1"}, live)
	if err != nil {
		t.Fatal(err)
	}
	var d hubtest.Decision
	json.Unmarshal(raw, &d)
	if d.Facade != "live" || d.Rule != "profile:read" || !d.Approved {
		t.Errorf("decision %+v: want facade live and the rule", d)
	}
	b, _ := os.ReadFile(e.Audit)
	if !strings.Contains(string(b), `"facade":"live"`) || !strings.Contains(string(b), `"rule":"profile:read"`) {
		t.Errorf("the audit does not name facade live and its rule:\n%s", b)
	}

	human := live
	human.Rule = ""
	for _, c := range []struct {
		name string
		raw  []byte
		v    hub.Verdict
		want error
	}{
		{"an approval without a rule", v2("L2", "read", nil), human, hub.ErrBadRequest},
		{"never auto", v2("L3", "read", func(tk *hubtest.Ticket) { tk.NeverAuto = true }), live, hub.ErrNotAuto},
		{"a grant", v2("L4", "grant", func(tk *hubtest.Ticket) { tk.NeverAuto = true }), live, hub.ErrNotAuto},
		{"a typed name", v2("L5", "prod-write", func(tk *hubtest.Ticket) { tk.Production, tk.Retype, tk.Kind = true, "r", "write" }), live, hub.ErrNotAuto},
		{"typed values", v2("L6", "write", func(tk *hubtest.Ticket) { tk.AskInputs, tk.Kind = true, "write" }), live, hub.ErrNotAuto},
		{"version 1", a.Ticket("L7", "read", e.Clock.T, time.Hour), live, hub.ErrBadRequest},
		{"a policy loosening it is not routed for", v2("L8", "policy-loosen", func(tk *hubtest.Ticket) { tk.NeverAuto, tk.Kind = true, "policy" }), live, hub.ErrNotAuto},
	} {
		push(c.raw)
		var tk hubtest.Ticket
		json.Unmarshal(c.raw, &tk)
		ref := store.Ref{Instance: "shop", ID: tk.ID}
		if _, err := e.Hub.Decide(ctx, ref, c.v); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if got, _ := e.Store.Tickets(ctx, state.Pending); !pendingHas(got, tk.ID) {
			t.Errorf("%s: the ticket no longer waits for a human", c.name)
		}
	}
	// A denial needs no rule (a ticket lox live cannot verify): it only narrows.
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "L2"}, hub.Verdict{ApproverID: "host:uid:990", Facade: route.Live, Reason: "ticket rejected"}); err != nil {
		t.Errorf("a denial by lox live: %v", err)
	}
}

func pendingHas(tks []store.Ticket, id string) bool {
	for _, tk := range tks {
		if tk.ID == id {
			return true
		}
	}
	return false
}

// lox live follows the terminal's routing: an instance the terminal does
// not answer is not lox live's either.
func TestLiveFollowsTheTerminalsRouting(t *testing.T) {
	a := hubtest.NewLock("shop")
	e := hubtest.NewWith(t, func(c *hub.Config) {
		c.Routes = route.Rules{Enabled: []string{route.TTY, route.Mobile}, Only: map[string][]string{"shop": {route.Mobile}}}
	}, a)
	raw := a.TicketWith("R1", "read", e.Clock.T, time.Hour, func(tk *hubtest.Ticket) { tk.V, tk.Kind = 2, "read" })
	if _, _, err := e.Hub.Push(ctx, "shop", raw); err != nil {
		t.Fatal(err)
	}
	_, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "R1"}, hub.Verdict{Approved: true, ApproverID: "x", Facade: route.Live, Rule: "default:read"})
	if !errors.Is(err, hub.ErrNotRouted) {
		t.Errorf("err = %v, want not routed", err)
	}
}

// A withdrawal through lox live's status socket is audited as such, and
// facade live withdraws nowhere else.
func TestWithdrawViaLive(t *testing.T) {
	a := hubtest.NewLock("shop")
	e := hubtest.New(t, 0, a)
	for _, id := range []string{"W1", "W2"} {
		if _, _, err := e.Hub.Push(ctx, "shop", a.Ticket(id, "write", e.Clock.T, time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	asker := hub.Asker{Facade: route.Live, ApproverID: "host:uid:990", ApproverDisplay: "uid 991 (status socket)"}
	res, err := e.Hub.WithdrawByHuman(ctx, store.Ref{Instance: "shop", ID: "W1"}, asker, hub.ViaLive)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Told || res.Reason != "withdrawn by uid 991 (status socket) in lox live" {
		t.Errorf("result = %+v", res)
	}
	b, _ := os.ReadFile(e.Audit)
	if !strings.Contains(string(b), `"event":"withdraw"`) || !strings.Contains(string(b), `"facade":"live"`) {
		t.Errorf("the audit does not record the withdrawal by facade live:\n%s", b)
	}
	ref := store.Ref{Instance: "shop", ID: "W2"}
	if _, err := e.Hub.WithdrawByHuman(ctx, ref, asker, hub.ViaCLI); !errors.Is(err, hub.ErrBadRequest) {
		t.Errorf("facade live in lox withdraw: %v", err)
	}
	if _, err := e.Hub.WithdrawByHuman(ctx, ref, human, hub.ViaLive); !errors.Is(err, hub.ErrBadRequest) {
		t.Errorf("the terminal in lox live: %v", err)
	}
	// Clear values and renewals stay the human's facades'.
	if _, err := e.Hub.Renew(ctx, ref, asker); err == nil {
		t.Error("facade live renewed a ticket")
	}
}
