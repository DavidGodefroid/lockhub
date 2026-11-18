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
	plain := func(kind string) func(*hubtest.Ticket) { return func(tk *hubtest.Ticket) { tk.Kind = kind } }
	prod := func(kind string) func(*hubtest.Ticket) {
		return func(tk *hubtest.Ticket) { tk.Kind, tk.Production = kind, true }
	}
	for _, c := range []struct {
		name string
		raw  []byte
		v    hub.Verdict
		want error
	}{
		{"an approval without a rule", v2("L2", "read", nil), human, hub.ErrBadRequest},
		{"never auto", v2("L3", "read", func(tk *hubtest.Ticket) { tk.NeverAuto = true }), live, hub.ErrNotAuto},
		{"a typed name", v2("L5", "prod-write", func(tk *hubtest.Ticket) { tk.Production, tk.Retype, tk.Kind = true, "r", "write" }), live, hub.ErrNotAuto},
		{"typed values", v2("L6", "write", func(tk *hubtest.Ticket) { tk.AskInputs, tk.Kind = true, "write" }), live, hub.ErrNotAuto},
		{"version 1", a.Ticket("L7", "read", e.Clock.T, time.Hour), live, hub.ErrBadRequest},
		// The hub's own floor, whatever the lock flagged (none of these
		// is never-auto): a rule never approves these classes.
		{"a grant, not flagged never-auto", v2("L4", "grant", nil), live, hub.ErrNotAuto},
		{"a policy loosening, not flagged", v2("L8", "policy-loosen", plain("policy")), live, hub.ErrNotAuto},
		{"a policy ticket of another risk", v2("L9", "write", plain("policy")), live, hub.ErrNotAuto},
		{"a production write", v2("L10", "prod-write", prod("write")), live, hub.ErrNotAuto},
		{"a production write, flag only", v2("L11", "write", prod("write")), live, hub.ErrNotAuto},
		{"a prod-write risk, not flagged", v2("L12", "prod-write", plain("write")), live, hub.ErrNotAuto},
		{"a production ddl", v2("L13", "write", prod("ddl")), live, hub.ErrNotAuto},
		{"a production action that writes", v2("L14", "write", prod("action")), live, hub.ErrNotAuto},
		{"a production read of a write risk", v2("L15", "write", prod("read")), live, hub.ErrNotAuto},
		{"a production endpoint, by lox live", v2("L16", "read", prod("endpoint")), live, hub.ErrNotAuto},
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
	// The floor holds for the terminal's rules too; a human there decides.
	tty := hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: route.TTY, Rule: "profile:write"}
	for _, id := range []string{"L4", "L8", "L10", "L13", "L14"} {
		if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: id}, tty); !errors.Is(err, hub.ErrNotAuto) {
			t.Errorf("%s by a rule at the terminal: %v", id, err)
		}
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "L10"}, hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: route.TTY}); err != nil {
		t.Errorf("a human's approval of the production write at the terminal: %v", err)
	}
	// What a rule may approve on production: a connect, a read, an action
	// that reads; at the terminal, an endpoint the human approved once.
	for _, c := range []struct {
		id, risk string
		mod      func(*hubtest.Ticket)
		v        hub.Verdict
	}{
		{"P1", "prod-write", prod("connect"), live},
		{"P2", "read-pii", prod("read"), live},
		{"P3", "read", prod("action"), live},
		{"P4", "read", prod("endpoint"), hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: route.TTY, Rule: "session:endpoint"}},
		{"P5", "write", plain("write"), live}, // off production: its rule decides
	} {
		push(v2(c.id, c.risk, c.mod))
		if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: c.id}, c.v); err != nil {
			t.Errorf("%s (%s): %v", c.id, c.risk, err)
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
	// Clear values and renewals stay the human's facades': refused to
	// facade live as not routed, on a ticket the terminal may ask them for.
	if _, err := e.Hub.Reveal(ctx, ref, asker, []byte(`{"ticket":"W2","facade":"live"}`)); !errors.Is(err, hub.ErrNotRouted) {
		t.Errorf("facade live asked a clear value: %v", err)
	}
	e.Clock.T = e.Clock.T.Add(2 * time.Hour)
	if err := e.Hub.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if exp, _ := e.Hub.Expired(ctx); len(exp) != 1 || exp[0].ID != "W2" {
		t.Fatalf("expired = %v", exp)
	}
	if _, err := e.Hub.Renew(ctx, ref, asker); !errors.Is(err, hub.ErrNotRouted) {
		t.Errorf("facade live renewed an expired ticket: %v", err)
	}
	if exp, _ := e.Hub.Expired(ctx); len(exp) != 1 {
		t.Errorf("the expired ticket is no longer offered: %v", exp)
	}
}
