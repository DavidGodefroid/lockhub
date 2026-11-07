package loxrun_test

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// A production profile in auto mode (#149): its connection is asked once
// per session; a plain masked SELECT, with an OK or a WARN verdict, is
// approved by default:read with no question; an UPDATE, an unmasked read
// and a read its profile asks (never-auto) are asked; lox audit keeps
// why each question was asked.
func TestRunE2EProductionAuto(t *testing.T) {
	w := newWorld(t)
	prod := ticket.Flags{Production: true}

	// The connection: asked, once.
	done := w.acquire(prodProfile)
	conn := w.wait(loxrun.EvQuestion, "").ID
	w.press(loxrun.R('y'))
	if d := w.wait(loxrun.EvDecided, conn); !d.Approved || d.Rule != "" {
		t.Fatalf("production connect %+v: want the human's approval", d)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	w.wait(loxrun.EvResult, conn)

	// SELECTs, verdict OK and WARN: auto, no question.
	sel := w.submitFlags(ticket.KindRead, ticket.RiskRead, prodProfile, "SELECT id FROM customers WHERE email = ", prod, nil)
	if d := w.wait(loxrun.EvDecided, sel); !d.Approved || d.Rule != "default:read" {
		t.Fatalf("production SELECT %+v: want auto by default:read", d)
	}
	warn := w.submitFlags(ticket.KindRead, ticket.RiskReadPII, prodProfile, "SELECT email FROM customers WHERE id = ", prod,
		[]string{"no LIMIT: the result may be large"})
	if d := w.wait(loxrun.EvDecided, warn); !d.Approved || d.Rule != "default:read" {
		t.Fatalf("production SELECT with a warning %+v: want auto by default:read", d)
	}
	for _, id := range []string{sel, warn} {
		if d := w.decision(id); !d.Auto() || d.Rule.ID != "default:read" {
			t.Errorf("signed decision on %s: rule %+v", id, d.Rule)
		}
	}

	// An UPDATE, an unmasked read, a read its profile asks: each asked.
	asked := map[string]string{}
	for _, c := range []struct {
		kind  ticket.Kind
		risk  ticket.Risk
		sql   string
		flags ticket.Flags
		why   string
	}{
		{ticket.KindWrite, ticket.RiskProdWrite, "UPDATE customers SET email = ", prod, "write is always asked"},
		{ticket.KindRead, ticket.RiskReadPII, "SELECT email FROM customers -- :unmask ", ticket.Flags{Production: true, NeverAuto: true},
			"the lock wants a human for this read"},
		{ticket.KindRead, ticket.RiskRead, "SELECT id FROM customers -- read = ask ", ticket.Flags{Production: true, NeverAuto: true},
			"its profile's auto rule for it is not auto"},
	} {
		id := w.submitFlags(c.kind, c.risk, prodProfile, c.sql, c.flags, nil)
		w.wait(loxrun.EvQuestion, id)
		w.press(loxrun.R('y'))
		if d := w.wait(loxrun.EvDecided, id); !d.Approved || d.Rule != "" {
			t.Fatalf("%s: %+v, want the human's approval", c.sql, d)
		}
		asked[id] = c.why
	}

	// After an idle close, the connection comes back on the session's
	// approval: no second question.
	(<-w.idle)()
	done = w.acquire(prodProfile)
	if again := w.wait(loxrun.EvDecided, ""); again.Rule != "session:connect" || !again.Approved {
		t.Fatalf("production reconnect %+v: want session:connect", again)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	w.bells(4) // the connection and the three questions

	// lox audit: the reason of every question, none on auto decisions.
	asked[conn] = "first connection to this profile in this session"
	xs, _, err := loxaudit.Load(context.Background(), loxaudit.Source{Data: w.dir, HubKeys: []ed25519.PublicKey{w.hubPub}})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range xs {
		want, human := asked[x.ID]
		switch {
		case human && !strings.Contains(x.Asked, want):
			t.Errorf("%s (%s): asked %q, want ~%q", x.ID, x.Summary, x.Asked, want)
		case !human && x.Asked != "":
			t.Errorf("%s (%s, rule %s): asked %q on an auto decision", x.ID, x.Summary, x.Rule, x.Asked)
		case !x.Production:
			t.Errorf("%s: not flagged production", x.ID)
		}
	}
	x, _ := loxaudit.Find(xs, inst+"/"+conn)
	detail := strings.Join(loxrun.AuditDetail(x, time.Local, 120, loxrun.Style{Unicode: true}), "\n")
	if !strings.Contains(detail, "why asked") || !strings.Contains(detail, asked[conn]) {
		t.Errorf("detail lacks why it was asked:\n%s", detail)
	}
}
