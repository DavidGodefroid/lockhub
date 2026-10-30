package mobile_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"

	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/verify"
)

// The phase-6 exit criterion, end to end without a real phone: a phone
// pairs (confirmed at the host's terminal), a real lockkit lock pins it,
// the phone opens the clear screen sealed to it, approves with its
// device signature, and the lock runs the plan once; nothing in the
// clear reaches the hub. Then a compromised hub (its key, its store) tries
// to make decisions pass as the device's: the lock refuses every one.
func TestPhaseSixExitCriterion(t *testing.T) {
	e := newEnv(t, route.Rules{})
	phone := e.phone("phone")
	dev := e.pair(phone)
	l := e.lock(dev)
	if err := phone.Login(); err != nil {
		t.Fatal(err)
	}

	// Approval from the phone, with the sealed clear screen shown.
	planID, id := l.submit(t, ticket.RiskWrite, false, "UPDATE customers")
	it := item(t, phone, id)
	if strings.Contains(it.Ticket, pii) {
		t.Fatal("the clear value reached the hub")
	}
	clear, err := phone.Clear(it)
	if err != nil || !strings.Contains(strings.Join(clear.Body, "\n"), pii) {
		t.Fatalf("clear screen on the phone: %+v %v", clear, err)
	}
	if err := phone.Answer(it, true, "looks right", ""); err != nil {
		t.Fatal(err)
	}
	p, d, err := l.run(t, id)
	if err != nil || p.ID != planID {
		t.Fatalf("the lock did not run the device's approval: %v", err)
	}
	if d.Facade != ticket.FacadeMobile || d.Device == nil || d.Approver.ID != dev.ID || d.Approver.Display != "phone" {
		t.Fatalf("decision %+v", d)
	}
	if err := l.c.Finish(context.Background(), l.st, planID, l.calls, true, ""); err != nil {
		t.Fatal(err)
	}

	// PII capture: nothing the phone received, nothing the hub stored or
	// audited, holds the clear value.
	for i, b := range phone.Seen {
		if bytes.Contains(b, []byte(pii)) {
			t.Fatalf("answer %d to the phone holds the clear value", i)
		}
	}
	for _, f := range []string{"tickets.jsonl", "hub.db", "hub.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(e.dir, f))
		if bytes.Contains(b, []byte(pii)) {
			t.Fatalf("%s holds the clear value", f)
		}
	}
	// The audit chain verifies and records the device.
	rep, err := verify.Hub(context.Background(), e.dir, e.hubKey.Public().(ed25519.PublicKey))
	if err != nil || !rep.OK() {
		t.Fatalf("audit verify: %+v %v", rep, err)
	}
	logb, _ := os.ReadFile(filepath.Join(e.dir, "tickets.jsonl"))
	if !bytes.Contains(logb, []byte(`"device":"`+dev.ID+`"`)) || !bytes.Contains(logb, []byte(`"event":"device-pair"`)) {
		t.Fatal("the audit log does not record the device")
	}

	// A compromised hub: it holds the hub key and writes decisions to its
	// own store, which the lock polls.
	forge := func(id string, mod func(d *ticket.Decision)) {
		var raw []byte
		e.hub.Store().Tx(context.Background(), func(tx *store.Tx) error {
			tk, _ := tx.Ticket(store.Ref{Instance: inst, ID: id})
			raw = tk.Raw
			return nil
		})
		var t2 ticket.Ticket
		json.Unmarshal(raw, &t2)
		d := &ticket.Decision{V: 1, Ticket: t2.ID, Instance: inst, KeyID: t2.Source.KeyID, PlanHash: t2.PlanHash,
			Decision: ticket.Approved, Approver: ticket.Approver{ID: dev.ID, Display: "phone"}, Facade: ticket.FacadeMobile,
			At: time.Now().UTC().Truncate(time.Millisecond), Nonce: ticket.NewNonce(), HubKeyID: ticket.KeyID(e.hubKey.Public().(ed25519.PublicKey))}
		mod(d)
		if err := d.Sign(e.hubKey); err != nil {
			t.Fatal(err)
		}
		b, _ := d.Marshal()
		err := e.hub.Store().Tx(context.Background(), func(tx *store.Tx) error {
			if err := tx.SetState(store.Ref{Instance: inst, ID: id}, "pending", "approved", time.Now()); err != nil {
				return err
			}
			_, err := tx.PutDecision(store.Decision{Ticket: id, Instance: inst, Raw: b, At: time.Now()})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	stolen := devicetest.New(rpID, origin, "phone")
	stolen.Cred = phone.Auth.Cred // the device's id, the hub's own key
	cases := map[string]func(d *ticket.Decision){
		"mobile facade, no device signature": func(d *ticket.Decision) {},
		"device signature of a key the hub made": func(d *ticket.Decision) {
			raw := ticketRaw(t, e, d.Ticket)
			stolen.Decide(d, raw)
		},
		"the device's real signature of another ticket": func(d *ticket.Decision) {
			// The phone approved ticket `id` above; its assertion is reused.
			d.Device = deviceOf(t, e, id)
		},
		"a terminal approval with the device's name": func(d *ticket.Decision) { d.Facade = "tty" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			_, fid := l.submit(t, ticket.RiskWrite, false, "UPDATE "+name)
			forge(fid, mod)
			_, _, perr, err := l.run2(t, fid)
			if name == "a terminal approval with the device's name" {
				// Not a device decision: a lock that does not require one
				// runs it (the control: forged decisions do reach the
				// lock), one that requires a device's signature does not.
				if err != nil {
					t.Fatalf("control: a hub-signed tty approval did not run: %v %v", perr, err)
				}
				l2 := e.lockRequire(dev)
				_, fid2 := l2.submit(t, ticket.RiskWrite, false, "UPDATE "+name+" 2")
				forge(fid2, mod)
				_, _, err = l2.run(t, fid2)
				if !errors.Is(err, ticket.ErrDevice) {
					t.Fatalf("a tty approval of a device-only risk ran: %v", err)
				}
				return
			}
			// Refused: dropped at Poll (then nothing to run), or at Begin.
			dropped := errors.Is(perr, hubclient.ErrBadDecision) && errors.Is(err, hubclient.ErrPending)
			if !dropped && !errors.Is(err, hubclient.ErrBadDecision) {
				t.Fatalf("the forged device decision was not refused: poll %v, begin %v", perr, err)
			}
		})
	}
}

func ticketRaw(t *testing.T, e *env, id string) []byte {
	t.Helper()
	var raw []byte
	e.hub.Store().Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: inst, ID: id})
		raw = tk.Raw
		return err
	})
	return raw
}

// deviceOf is the device assertion of the decision the hub recorded on id.
func deviceOf(t *testing.T, e *env, id string) *ticket.DeviceAssertion {
	t.Helper()
	ds, err := e.hub.Store().AllDecisions(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.Ticket == id {
			var dd ticket.Decision
			json.Unmarshal(d.Raw, &dd)
			return dd.Device
		}
	}
	t.Fatalf("no decision on %s", id)
	return nil
}
