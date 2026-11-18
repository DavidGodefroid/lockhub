package loxrun_test

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
)

// lox live against the real hub and a real lockkit lock: a rule's
// decision is signed under facade live and the lock takes it; what a
// human decides stays pending, and a human's facade (lox approve's
// decide, on the same socket) answers it next to lox live.
func TestLiveE2E(t *testing.T) {
	rules := loxrun.ProfileRules{loxrun.ActConnect: loxrun.Allow, loxrun.ActRead: loxrun.Allow, loxrun.ActWrite: loxrun.Allow}
	w := newWorldCfg(t, worldCfg{arm: -1, session: func(s *loxrun.Session) {
		s.Unattended, s.Facade, s.Keys, s.Size, s.Display = true, route.Live, nil, nil, "lox live"
		s.Style = loxrun.Style{}
		s.Rules = func(lock, instance, profile string) loxrun.ProfileRules { return rules }
	}})

	// The production profile's connection: its rule is auto, no question.
	done := w.acquire(prodProfile)
	conn := w.wait(loxrun.EvDecided, "")
	if !conn.Approved || conn.Rule != "profile:connect" {
		t.Fatalf("connect %+v", conn)
	}
	if err := <-done; err != nil {
		t.Fatalf("the lock did not connect on lox live's decision: %v", err)
	}
	if d := w.decision(conn.ID); !d.Auto() || d.Facade != route.Live || d.Rule.ID != "profile:connect" {
		t.Fatalf("signed connect decision: facade %q rule %+v", d.Facade, d.Rule)
	}

	// A production read: by the rule, under facade live.
	sel := w.submitFlags(ticket.KindRead, ticket.RiskRead, prodProfile, "SELECT id FROM customers WHERE email = ", ticket.Flags{Production: true}, nil)
	if d := w.wait(loxrun.EvDecided, sel); !d.Approved || d.Rule != "profile:read" {
		t.Fatalf("read %+v", d)
	}
	if d := w.decision(sel); !d.Auto() || d.Facade != route.Live {
		t.Fatalf("signed read decision: facade %q rule %+v", d.Facade, d.Rule)
	}

	// A production write, whatever its rule says: left to a human.
	upd := w.submitFlags(ticket.KindWrite, ticket.RiskProdWrite, prodProfile, "UPDATE customers SET email = ", ticket.Flags{Production: true}, nil)
	if e := w.wait(loxrun.EvLeft, upd); e.Why == "" {
		t.Fatalf("left %+v", e)
	}
	// A never-auto read (the lock's profile asks its reads): left too.
	na := w.submitFlags(ticket.KindRead, ticket.RiskRead, prodProfile, "SELECT 2 FROM customers WHERE email = ", ticket.Flags{Production: true, NeverAuto: true}, nil)
	w.wait(loxrun.EvLeft, na)
	time.Sleep(200 * time.Millisecond)
	for _, id := range []string{upd, na} {
		if s := w.ticketState(id); s != state.Pending {
			t.Fatalf("%s is %s: lox live decided it", id, s)
		}
	}
	// The hub refuses what lox live must not do, whatever a client of the
	// socket sends under its name: an approval without a rule, a rule on
	// the never-auto ticket.
	c := approve.Dial(w.sock)
	ctx := context.Background()
	if err := c.Decide(ctx, inst, upd, api.DecideRequest{Approved: true, Facade: route.Live}); err == nil {
		t.Fatal("the hub took an approval of facade live without a rule")
	}
	if err := c.Decide(ctx, inst, na, api.DecideRequest{Approved: true, Facade: route.Live, Rule: "profile:read"}); err == nil {
		t.Fatal("the hub took a rule's approval of a never-auto ticket")
	}
	// lox approve (facade tty) answers next to lox live.
	if err := c.Decide(ctx, inst, upd, api.DecideRequest{Approved: true, Facade: route.TTY, Display: "david"}); err != nil {
		t.Fatalf("a human's decision next to lox live: %v", err)
	}
	if d := w.decision(upd); d.Auto() || d.Facade != route.TTY {
		t.Fatalf("the write's decision: facade %q rule %+v", d.Facade, d.Rule)
	}

	// lox audit tells lox live's decisions from the terminal's.
	xs, _, err := loxaudit.Load(ctx, loxaudit.Source{Data: w.dir, HubKeys: []ed25519.PublicKey{w.hubPub}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]loxrun.Exchange{}
	for _, x := range xs {
		seen[x.ID] = x
	}
	if x := seen[sel]; x.Rule != "profile:read" || x.Facade != route.Live {
		t.Errorf("audit of the read: rule %q facade %q", x.Rule, x.Facade)
	}
	if x := seen[upd]; x.Rule != "" || x.Facade != route.TTY {
		t.Errorf("audit of the write: rule %q facade %q", x.Rule, x.Facade)
	}
	panel := strings.Join(loxrun.AuditDetail(seen[sel], time.UTC, 100, loxrun.Style{}), "\n")
	if !strings.Contains(panel, "by the auto rule profile:read in lox live") {
		t.Errorf("lox audit show does not say lox live:\n%s", panel)
	}
	if out := w.out.String(); strings.Contains(out, "\x1b[") || strings.Contains(out, "\a") || !strings.Contains(out, "lox live: serving") {
		t.Errorf("lox live's log is not plain lines:\n%s", out)
	}
}
