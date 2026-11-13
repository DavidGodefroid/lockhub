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
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// lox run's auto rules: the hub signs a decision that names the rule, and
// never lets one stand in for a human where the ticket wants one.
func TestDecideAutoRule(t *testing.T) {
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
	auto := hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty", Rule: "default:read"}

	push(v2("R1", "read", nil))
	raw, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "R1"}, auto)
	if err != nil {
		t.Fatal(err)
	}
	var d hubtest.Decision
	json.Unmarshal(raw, &d)
	if d.Rule != "default:read" || !d.Approved {
		t.Errorf("decision %+v: want the rule named", d)
	}
	b, _ := os.ReadFile(e.Audit)
	if !strings.Contains(string(b), `"rule":"default:read"`) {
		t.Errorf("audit log does not name the rule:\n%s", b)
	}

	for _, c := range []struct {
		name string
		raw  []byte
		v    hub.Verdict
		want error
	}{
		{"version 1", a.Ticket("R2", "read", e.Clock.T, time.Hour), auto, hub.ErrBadRequest},
		{"never auto", v2("R3", "grant", func(tk *hubtest.Ticket) { tk.NeverAuto = true }), auto, hub.ErrNotAuto},
		{"retype", v2("R4", "prod-write", func(tk *hubtest.Ticket) { tk.Production, tk.Retype, tk.Kind = true, "r", "write" }), auto, hub.ErrNotAuto},
		{"other facade", v2("R5", "read", nil), hub.Verdict{Approved: true, ApproverID: "x", Facade: "deck", Rule: "r"}, hub.ErrBadRequest},
		{"secret not asked", v2("R6", "read", nil), hub.Verdict{Approved: true, ApproverID: "x", Facade: "tty", Secret: []byte(`{}`)}, hub.ErrBadRequest},
		{"secret on a denial", v2("R7", "read", func(tk *hubtest.Ticket) { tk.Kind, tk.AskSecret = "connect", true }),
			hub.Verdict{ApproverID: "x", Facade: "tty", Secret: []byte(`{}`)}, hub.ErrBadRequest},
	} {
		push(c.raw)
		var tk hubtest.Ticket
		json.Unmarshal(c.raw, &tk)
		if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: tk.ID}, c.v); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}

	// An auto denial of a never-auto ticket is fine: it only narrows.
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "R3"}, hub.Verdict{ApproverID: "x", Facade: "tty", Rule: "deny:ddl"}); err != nil {
		t.Errorf("auto denial of a never-auto ticket: %v", err)
	}
	// The secret a connect ticket asked for is relayed as given.
	raw, err = e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "R7"}, hub.Verdict{Approved: true, ApproverID: "x", Facade: "tty", Secret: []byte(`{"box":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &d)
	if d.Secret != `{"box":1}` {
		t.Errorf("secret %q not relayed", d.Secret)
	}
}

// A ticket that asks for typed values is answered in lox run only: the
// approval it seals the values in is relayed as given; another facade's
// approval, which cannot carry them, denies it so its lock stops waiting.
func TestDecideInputs(t *testing.T) {
	a := hubtest.NewLock("shop")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.Routes = route.Rules{Enabled: []string{"tty", "deck", "slack"}} }, a)
	push := func(id string) {
		t.Helper()
		raw := a.TicketWith(id, "read", e.Clock.T, time.Hour, func(tk *hubtest.Ticket) {
			tk.V, tk.Kind, tk.AskSecret, tk.AskInputs, tk.NeverAuto = 2, "read", true, true, true
		})
		if _, _, err := e.Hub.Push(ctx, "shop", raw); err != nil {
			t.Fatal(err)
		}
	}
	decide := func(id string, v hub.Verdict) hubtest.Decision {
		t.Helper()
		raw, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: id}, v)
		if err != nil {
			t.Fatal(err)
		}
		var d hubtest.Decision
		json.Unmarshal(raw, &d)
		return d
	}

	push("I1")
	if d := decide("I1", hub.Verdict{Approved: true, ApproverID: "x", Facade: "tty", Secret: []byte(`{"box":1}`)}); !d.Approved || d.Secret != `{"box":1}` {
		t.Errorf("lox run's sealed approval: %+v", d)
	}
	for id, f := range map[string]string{"I2": "slack", "I3": "deck"} {
		push(id)
		if d := decide(id, hub.Verdict{Approved: true, ApproverID: "x", Facade: f}); d.Approved || d.Reason != hub.InputsElsewhereReason {
			t.Errorf("%s approval without values: %+v, want a denial", f, d)
		}
	}
	// An auto rule never approves one, never-auto flag or not.
	raw := a.TicketWith("I4", "read", e.Clock.T, time.Hour, func(tk *hubtest.Ticket) {
		tk.V, tk.Kind, tk.AskSecret, tk.AskInputs = 2, "read", true, true
	})
	if _, _, err := e.Hub.Push(ctx, "shop", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "shop", ID: "I4"}, hub.Verdict{Approved: true, ApproverID: "x", Facade: "tty", Rule: "default:read"}); !errors.Is(err, hub.ErrNotAuto) {
		t.Errorf("auto approval: %v", err)
	}
}
