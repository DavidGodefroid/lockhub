package hub_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

var ctx = context.Background()

func approve(id string) hub.Verdict {
	return hub.Verdict{Approved: true, ApproverID: "host:david", Facade: "tty"}
}

func TestPushDecideConsume(t *testing.T) {
	a := hubtest.NewLock("crm-prod")
	e := hubtest.New(t, 0, a)
	raw := a.Ticket("T1", "write", e.Clock.T, 24*time.Hour)

	info, created, err := e.Hub.Push(ctx, "crm-prod", raw)
	if err != nil || !created || info.ID != "T1" {
		t.Fatalf("Push = %+v, %v, %v", info, created, err)
	}
	if _, created, err := e.Hub.Push(ctx, "crm-prod", raw); err != nil || created {
		t.Fatalf("re-Push = %v, %v (want idempotent)", created, err)
	}
	other := a.Ticket("T1", "read", e.Clock.T, 0)
	if _, _, err := e.Hub.Push(ctx, "crm-prod", other); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same id, other ticket: %v", err)
	}

	d, err := e.Hub.Decide(ctx, store.Ref{Instance: "crm-prod", ID: "T1"}, approve("T1"))
	if err != nil {
		t.Fatal(err)
	}
	var dec hubtest.Decision
	json.Unmarshal(d, &dec)
	if !dec.Approved || dec.Ticket != "T1" || dec.Instance != "crm-prod" || dec.PlanHash != "sha256:T1" || dec.Approver != "host:david" {
		t.Errorf("decision %+v", dec)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "crm-prod", ID: "T1"}, hub.Verdict{ApproverID: "x", Facade: "tty"}); err == nil {
		t.Error("second decision accepted")
	}
	ds, err := e.Hub.Decisions(ctx, "crm-prod", 0, 0)
	if err != nil || len(ds) != 1 || string(ds[0].Raw) != string(d) {
		t.Fatalf("Decisions = %v, %v", ds, err)
	}
	if err := e.Hub.Consumed(ctx, "crm-prod", "T1"); err != nil {
		t.Fatal(err)
	}
	if err := e.Hub.Consumed(ctx, "crm-prod", "T1"); err == nil {
		t.Error("consumed twice")
	}

	f, _ := os.Open(e.Audit)
	defer f.Close()
	if n, err := audit.Verify(f); err != nil || n != 3 {
		t.Errorf("audit: %d records, %v (want push, approve, consume)", n, err)
	}
}

func TestPushRefusals(t *testing.T) {
	a, b := hubtest.NewLock("a"), hubtest.NewLock("b")
	e := hubtest.New(t, 2, a, b)
	now := e.Clock.T
	stranger := hubtest.NewLock("a") // same name, other key

	cases := []struct {
		name     string
		instance string
		raw      []byte
		want     error
	}{
		{"unknown instance", "zz", a.Ticket("X", "read", now, 0), hub.ErrUnknownLock},
		{"other instance's ticket", "b", a.Ticket("X", "read", now, 0), hub.ErrBadTicket},
		{"wrong key", "a", stranger.Ticket("X", "read", now, 0), hub.ErrBadTicket},
		{"garbage", "a", []byte("{"), hub.ErrBadTicket},
		{"future", "a", a.Ticket("X", "read", now.Add(time.Hour), 0), hub.ErrBadTicket},
		{"already expired", "a", a.Ticket("X", "write", now.Add(-25*time.Hour), 24*time.Hour), hub.ErrExpired},
	}
	for _, c := range cases {
		if _, _, err := e.Hub.Push(ctx, c.instance, c.raw); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// A ticket signed by a's key but naming instance b, pushed by a.
	forged := hubtest.Lock{Instance: "b", Pub: a.Pub, Priv: a.Priv}.Ticket("Y", "read", now, 0)
	if _, _, err := e.Hub.Push(ctx, "a", forged); !errors.Is(err, hub.ErrForbidden) {
		t.Errorf("instance mismatch: %v", err)
	}

	// Pending cap per instance; another instance is not affected.
	for _, id := range []string{"P1", "P2"} {
		if _, _, err := e.Hub.Push(ctx, "a", a.Ticket(id, "read", now, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.Hub.Push(ctx, "a", a.Ticket("P3", "read", now, 0)); !errors.Is(err, hub.ErrTooMany) {
		t.Errorf("cap: %v", err)
	}
	if _, _, err := e.Hub.Push(ctx, "a", a.Ticket("P1", "read", now, 0)); err != nil {
		t.Errorf("re-push at the cap must stay idempotent: %v", err)
	}
	if _, _, err := e.Hub.Push(ctx, "b", b.Ticket("Q1", "read", now, 0)); err != nil {
		t.Errorf("other instance: %v", err)
	}
}

func TestInstanceIsolation(t *testing.T) {
	a, b := hubtest.NewLock("a"), hubtest.NewLock("b")
	e := hubtest.New(t, 0, a, b)
	e.Hub.Push(ctx, "a", a.Ticket("A1", "read", e.Clock.T, 0))
	if err := e.Hub.Withdraw(ctx, "b", "A1", ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("b withdrew a's ticket: %v", err)
	}
	e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "A1"}, approve("A1"))
	if ds, _ := e.Hub.Decisions(ctx, "b", 0, 0); len(ds) != 0 {
		t.Errorf("b sees a's decisions: %v", ds)
	}
	if err := e.Hub.Consumed(ctx, "b", "A1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("b consumed a's ticket: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	now := e.Clock.T
	e.Hub.Push(ctx, "a", a.Ticket("W", "prod-write", now, 4*time.Hour))
	e.Hub.Push(ctx, "a", a.Ticket("R", "read", now, 0))
	e.Clock.T = now.Add(4*time.Hour + time.Second)
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "W"}, approve("W")); !errors.Is(err, hub.ErrExpired) {
		t.Errorf("decide after TTL: %v", err)
	}
	if err := e.Hub.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if ps, _ := e.Store.Tickets(ctx, state.Expired); len(ps) != 1 || ps[0].ID != "W" {
		t.Errorf("expired = %v", ps)
	}
	if ps, _ := e.Store.Tickets(ctx, state.Pending); len(ps) != 1 || ps[0].ID != "R" {
		t.Errorf("read ticket must not expire: %v", ps)
	}
}

func TestLongPoll(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "a", a.Ticket("L", "read", e.Clock.T, 0))
	var wg sync.WaitGroup
	wg.Add(1)
	var got []store.Decision
	go func() {
		defer wg.Done()
		got, _ = e.Hub.Decisions(ctx, "a", 0, 10*time.Second)
	}()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "L"}, approve("L"))
	wg.Wait()
	if len(got) != 1 || time.Since(start) > 5*time.Second {
		t.Errorf("long poll returned %v after %v", got, time.Since(start))
	}
	// Timeout with nothing new.
	if ds, err := e.Hub.Decisions(ctx, "a", got[0].Seq, 50*time.Millisecond); err != nil || len(ds) != 0 {
		t.Errorf("idle poll = %v, %v", ds, err)
	}
}

func TestDecideNeedsApproverAndFacade(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "a", a.Ticket("N", "read", e.Clock.T, 0))
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "N"}, hub.Verdict{Approved: true}); err == nil {
		t.Error("anonymous decision accepted")
	}
}

func TestRouting(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "a", a.Ticket("PW", "prod-write", e.Clock.T, 4*time.Hour))
	e.Hub.Push(ctx, "a", a.Ticket("R", "read", e.Clock.T, 0))
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "PW"}, hub.Verdict{Approved: true, ApproverID: "slack:U1", Facade: "slack"}); !errors.Is(err, hub.ErrNotRouted) {
		t.Errorf("prod-write on slack: %v", err)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "R"}, hub.Verdict{Approved: true, ApproverID: "slack:U1", Facade: "slack"}); err != nil {
		t.Errorf("read on slack: %v", err)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "PW"}, hub.Verdict{Approved: true, ApproverID: "host:u", Facade: "tty"}); err != nil {
		t.Errorf("prod-write on tty: %v", err)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "R"}, hub.Verdict{ApproverID: "x", Facade: "fax"}); err == nil {
		t.Error("unknown facade accepted")
	}
}

// Every production approval needs the instance name typed, on every
// facade that may answer it (hub plan H1, #64): lockkit's Retype flag (the
// console's "retype values" answer) is not what the human types, and a
// production ticket without it is no exception. Denying needs nothing;
// a chat facade never answers production.
func TestProductionNeedsTheInstanceName(t *testing.T) {
	for name, flag := range map[string]string{"no retype flag": "", "lockkit retype flag": "r", "flag is the name": "crm-prod"} {
		t.Run(name, func(t *testing.T) {
			a := hubtest.NewLock("crm-prod")
			e := hubtest.New(t, 0, a)
			prod := func(t *hubtest.Ticket) { t.Production, t.Retype = true, flag }
			for _, id := range []string{"P", "D", "S", "M"} {
				if _, _, err := e.Hub.Push(ctx, "crm-prod", a.TicketWith(id, "write", e.Clock.T, time.Hour, prod)); err != nil {
					t.Fatal(err)
				}
			}
			ref := func(id string) store.Ref { return store.Ref{Instance: "crm-prod", ID: id} }
			for _, typed := range []string{"", "r", "crm", "CRM-PROD", "crm-prod "} {
				for _, f := range []string{"tty", "deck"} {
					v := hub.Verdict{Approved: true, ApproverID: "host:david", Facade: f, Retype: typed}
					if _, err := e.Hub.Decide(ctx, ref("P"), v); !errors.Is(err, hub.ErrRetype) {
						t.Errorf("%s approved with %q typed: %v", f, typed, err)
					}
				}
			}
			for _, f := range []string{"slack", "telegram"} {
				v := hub.Verdict{Approved: true, ApproverID: f + ":U1", Facade: f, Retype: "crm-prod"}
				if _, err := e.Hub.Decide(ctx, ref("S"), v); !errors.Is(err, hub.ErrNotRouted) {
					t.Errorf("production on %s: %v", f, err)
				}
				v.Approved = false
				if _, err := e.Hub.Decide(ctx, ref("S"), v); !errors.Is(err, hub.ErrNotRouted) {
					t.Errorf("production denied on %s: %v", f, err)
				}
			}
			if _, err := e.Hub.Decide(ctx, ref("D"), hub.Verdict{ApproverID: "host:david", Facade: "tty"}); err != nil {
				t.Errorf("deny: %v", err)
			}
			for id, f := range map[string]string{"P": "tty", "M": "deck"} {
				v := hub.Verdict{Approved: true, ApproverID: "host:david", Facade: f, Retype: "crm-prod"}
				if _, err := e.Hub.Decide(ctx, ref(id), v); err != nil {
					t.Errorf("%s with the name typed: %v", f, err)
				}
			}
		})
	}
}

func TestIDsArePerInstance(t *testing.T) {
	a, b := hubtest.NewLock("a"), hubtest.NewLock("b")
	e := hubtest.New(t, 0, a, b)
	if _, _, err := e.Hub.Push(ctx, "a", a.Ticket("SAME", "read", e.Clock.T, 0)); err != nil {
		t.Fatal(err)
	}
	// b may use the same id: no squatting across instances.
	if _, created, err := e.Hub.Push(ctx, "b", b.Ticket("SAME", "write", e.Clock.T, time.Hour)); err != nil || !created {
		t.Fatalf("b's ticket with a's id: %v, %v", created, err)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "b", ID: "SAME"}, approve("SAME")); err != nil {
		t.Fatal(err)
	}
	if ds, _ := e.Hub.Decisions(ctx, "a", 0, 0); len(ds) != 0 {
		t.Errorf("deciding b's ticket decided a's: %v", ds)
	}
}

func TestFieldLimits(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	long := strings.Repeat("x", hub.MaxID+1)
	for name, raw := range map[string][]byte{
		"long id":      a.Ticket(long, "read", e.Clock.T, 0),
		"bad id chars": a.Ticket("a/b", "read", e.Clock.T, 0),
		"unknown risk": a.Ticket("R1", "delete-all", e.Clock.T, 0),
	} {
		if _, _, err := e.Hub.Push(ctx, "a", raw); !errors.Is(err, hub.ErrBadTicket) {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.Hub.Push(ctx, "a", a.Ticket("OK", "read", e.Clock.T, 0))
	if err := e.Hub.Withdraw(ctx, "a", "OK", strings.Repeat("r", hub.MaxReason+1)); !errors.Is(err, hub.ErrBadRequest) {
		t.Errorf("long reason: %v", err)
	}
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "a", ID: "OK"}, hub.Verdict{ApproverID: "x", Facade: "tty", Reason: strings.Repeat("r", hub.MaxReason+1)}); !errors.Is(err, hub.ErrBadRequest) {
		t.Errorf("long decision reason: %v", err)
	}
}

func TestQueueVersionNoGap(t *testing.T) {
	a := hubtest.NewLock("a")
	e := hubtest.New(t, 0, a)
	_, v0, _ := e.Hub.Queue(ctx, 0, 0)
	// A change between two polls is not lost: polling with the last
	// version returns at once.
	e.Hub.Push(ctx, "a", a.Ticket("Q1", "read", e.Clock.T, 0))
	start := time.Now()
	tks, v1, err := e.Hub.Queue(ctx, v0, 5*time.Second)
	if err != nil || len(tks) != 1 || v1 == v0 || time.Since(start) > time.Second {
		t.Fatalf("Queue after a missed change: %d tickets, v %d→%d, %v, %v", len(tks), v0, v1, time.Since(start), err)
	}
	// Up to date: waits until the timeout.
	start = time.Now()
	if _, v2, _ := e.Hub.Queue(ctx, v1, 100*time.Millisecond); v2 != v1 || time.Since(start) < 90*time.Millisecond {
		t.Errorf("up-to-date poll returned early (v %d)", v2)
	}
}

// Only the mobile facade carries a device's assertion, and it always
// does; the device must be active at the hub.
func TestDeviceVerdicts(t *testing.T) {
	a := hubtest.NewLock("crm-prod")
	e := hubtest.New(t, 0, a)
	if _, _, err := e.Hub.Push(ctx, "crm-prod", a.Ticket("T1", "write", e.Clock.T, 24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ref := store.Ref{Instance: "crm-prod", ID: "T1"}
	dev := hub.Verdict{Approved: true, ApproverID: "webauthn:x", Facade: "mobile", Nonce: "n", At: e.Clock.T,
		Device: []byte(`{}`), DeviceID: "webauthn:x", DeviceRecord: []byte(`{}`)}
	for name, v := range map[string]hub.Verdict{
		"mobile without assertion": {Approved: true, ApproverID: "webauthn:x", Facade: "mobile"},
		"tty with an assertion":    func() hub.Verdict { v := dev; v.Facade = "tty"; return v }(),
		"mobile, partial":          func() hub.Verdict { v := dev; v.DeviceRecord = nil; return v }(),
	} {
		if _, err := e.Hub.Decide(ctx, ref, v); !errors.Is(err, hub.ErrBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.Hub.Decide(ctx, ref, dev); !errors.Is(err, hub.ErrDevice) {
		t.Errorf("unknown device: %v", err)
	}
	old := dev
	old.At = e.Clock.T.Add(-hub.DeviceWindow - time.Second)
	if _, err := e.Hub.Decide(ctx, ref, old); !errors.Is(err, hub.ErrDevice) {
		t.Errorf("stale device time: %v", err)
	}
	if err := e.Hub.AddDevice(ctx, "webauthn:x", []byte(`{"r":1}`), "fp", "host:uid:1", 5); err != nil {
		t.Fatal(err)
	}
	if err := e.Hub.UseCounter(ctx, "webauthn:x", 5); !errors.Is(err, hub.ErrDevice) {
		t.Errorf("counter not growing: %v", err)
	}
	if err := e.Hub.UseCounter(ctx, "webauthn:x", 6); err != nil {
		t.Error(err)
	}
	if err := e.Hub.RevokeDevice(ctx, "webauthn:x", "host:uid:1"); err != nil {
		t.Fatal(err)
	}
	if err := e.Hub.UseCounter(ctx, "webauthn:x", 7); !errors.Is(err, hub.ErrDevice) {
		t.Errorf("revoked device: %v", err)
	}
}

func TestOnPendingOnNewTicketsOnly(t *testing.T) {
	a := hubtest.NewLock("crm-prod")
	e := hubtest.New(t, 0, a)
	var got []hub.Pending
	e.Hub.OnPending(func(p hub.Pending) { got = append(got, p) })
	raw := a.Ticket("T1", "write", e.Clock.T, 24*time.Hour)
	for range 2 {
		if _, _, err := e.Hub.Push(ctx, "crm-prod", raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.Hub.Push(ctx, "crm-prod", a.Ticket("T1", "read", e.Clock.T, 0)); err == nil {
		t.Fatal("conflict accepted")
	}
	if len(got) != 1 || got[0] != (hub.Pending{Instance: "crm-prod", ID: "T1", Risk: "write"}) {
		t.Fatalf("OnPending calls %+v, want one for T1", got)
	}
}
