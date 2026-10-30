package hub_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

var tty = hub.Asker{Facade: "tty", ApproverID: "host:uid:1000", ApproverDisplay: "david"}

func revealKey(ticket, facade string) json.RawMessage {
	b, _ := json.Marshal(hubtest.RevealKey{Ticket: ticket, Facade: facade})
	return b
}

// lockAnswers plays the lock: it long-polls instance and answers each
// request it gets with answer(request).
func lockAnswers(t *testing.T, e hubtest.Env, instance string, answer func(hubtest.Request) string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		seen := map[string]bool{}
		for ctx.Err() == nil {
			_, reqs, err := e.Hub.Poll(ctx, instance, 0, time.Second)
			if err != nil {
				return
			}
			for _, raw := range reqs {
				var q hubtest.Request
				json.Unmarshal(raw, &q)
				if seen[q.ID] {
					continue
				}
				seen[q.ID] = true
				if err := e.Hub.AnswerRequest(instance, q.ID, []byte(answer(q))); err != nil {
					t.Errorf("answer: %v", err)
				}
			}
		}
	}()
}

func TestRevealRelaysTheLocksAnswer(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.New(t, 0, a)
	if _, _, err := e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour)); err != nil {
		t.Fatal(err)
	}
	const sealed = `{"box":"ciphertext"}`
	lockAnswers(t, e, "crm", func(q hubtest.Request) string {
		if q.Kind != "reveal" || q.Ticket != "T1" || q.Facade != "tty" || q.ApproverID != "host:uid:1000" {
			t.Errorf("request %+v", q)
		}
		return `{"reveal":` + sealed + `}`
	})
	ans, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
	if err != nil || string(ans) != sealed {
		t.Fatalf("Reveal = %s, %v", ans, err)
	}
	log, _ := os.ReadFile(e.Audit)
	if !strings.Contains(string(log), `"event":"reveal"`) || !strings.Contains(string(log), `"reason":"answered"`) || strings.Contains(string(log), "ciphertext") {
		t.Errorf("audit: %s", log)
	}
}

// The long poll of the instance wakes at once on a new request; another
// instance's poll does not see it, and cannot answer it.
func TestRequestOnlyForItsInstance(t *testing.T) {
	a, b := hubtest.NewLock("crm"), hubtest.NewLock("billing")
	e := hubtest.New(t, 0, a, b)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	got := make(chan []byte, 1)
	go func() {
		start := time.Now()
		_, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 20*time.Second)
		if time.Since(start) > 10*time.Second || len(reqs) != 1 {
			t.Errorf("poll: %d requests after %s", len(reqs), time.Since(start))
		}
		got <- reqs[0]
	}()
	done := make(chan error, 1)
	go func() {
		_, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
		done <- err
	}()
	var q hubtest.Request
	json.Unmarshal(<-got, &q)
	if _, reqs, _ := e.Hub.Poll(ctx, "billing", 0, 0); len(reqs) != 0 {
		t.Errorf("billing sees crm's request")
	}
	if err := e.Hub.AnswerRequest("billing", q.ID, []byte(`{"reveal":{}}`)); !errors.Is(err, hub.ErrNoRequest) {
		t.Errorf("billing answered crm's request: %v", err)
	}
	if err := e.Hub.AnswerRequest("crm", q.ID, []byte(`{"error":"no_clear_screen"}`)); err != nil {
		t.Fatal(err)
	}
	var le *hub.LockError
	if err := <-done; !errors.As(err, &le) || le.Code != "no_clear_screen" {
		t.Errorf("facade got %v", err)
	}
	if err := e.Hub.AnswerRequest("crm", q.ID, []byte(`{"error":"failed"}`)); !errors.Is(err, hub.ErrNoRequest) {
		t.Errorf("second answer: %v", err)
	}
}

func TestRevealTimesOut(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 50 * time.Millisecond }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	if _, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty")); !errors.Is(err, hub.ErrTimeout) {
		t.Fatalf("got %v", err)
	}
	// Given up: the request is gone, a late answer is refused.
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 0); len(reqs) != 0 {
		t.Errorf("request still open after the timeout")
	}
}

func TestAnswerValidation(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	for name, c := range map[string]struct {
		body string
		want string // the facade's error code, "" for success
		bad  bool   // the lock's answer is refused
	}{
		"free text error":   {body: `{"error":"SELECT secret FROM t failed"}`, want: "failed"},
		"two members":       {body: `{"reveal":{},"error":"failed"}`, want: "failed", bad: true},
		"ticket to reveal":  {body: `{"ticket":"X1"}`, want: "failed", bad: true},
		"not an object":     {body: `{"reveal":"text"}`, want: "failed", bad: true},
		"oversized":         {body: `{"reveal":{"x":"` + strings.Repeat("a", hub.MaxAnswer) + `"}}`, want: "failed", bad: true},
		"policy_changed ok": {body: `{"error":"policy_changed"}`, want: "policy_changed"},
	} {
		t.Run(name, func(t *testing.T) {
			// A refused answer ends the request at once: the facade hears
			// "failed" well before RequestWait.
			e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = time.Minute }, a)
			e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
			done := make(chan error, 1)
			go func() {
				_, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
				done <- err
			}()
			_, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 5*time.Second)
			var q hubtest.Request
			json.Unmarshal(reqs[0], &q)
			err := e.Hub.AnswerRequest("crm", q.ID, []byte(c.body))
			if (err != nil) != c.bad {
				t.Errorf("AnswerRequest: %v", err)
			}
			ferr := <-done
			var le *hub.LockError
			switch {
			case c.want == "" && ferr != nil && !c.bad:
				t.Errorf("facade: %v", ferr)
			case c.want != "" && (!errors.As(ferr, &le) || le.Code != c.want):
				t.Errorf("facade: %v, want code %s", ferr, c.want)
			}
		})
	}
}

// I8 and B.7: clear values on demand and renewals go to the terminal
// and the deck only, and only where the routing lets that facade see
// the ticket. The hub refuses before asking any lock.
func TestRevealAndRenewRouting(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 5 * time.Millisecond }, a)
	risks := []string{"read", "read-pii", "write", "prod-write", "policy-loosen", "unlock"}
	for _, risk := range risks {
		for _, f := range []string{"tty", "deck", "mobile", "slack", "telegram"} {
			id := "T-" + risk + "-" + f
			e.Hub.Push(ctx, "crm", a.Ticket(id, risk, e.Clock.T, time.Hour))
			as := hub.Asker{Facade: f, ApproverID: "x"}
			_, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: id}, as, revealKey(id, f))
			if route.OnDemand(f) {
				// Asked of the lock, which does not answer here.
				if !errors.Is(err, hub.ErrTimeout) {
					t.Errorf("%s on %s: %v, want the lock asked", risk, f, err)
				}
				continue
			}
			if !errors.Is(err, hub.ErrNotRouted) {
				t.Errorf("reveal of %s on %s: %v, want not routed", risk, f, err)
			}
			if _, err := e.Hub.Renew(ctx, store.Ref{Instance: "crm", ID: id}, as); !errors.Is(err, hub.ErrNotRouted) {
				t.Errorf("renew of %s on %s: %v, want not routed", risk, f, err)
			}
		}
	}
}

func TestRevealNotRoutedOrForeignKey(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) {
		c.Routes = route.Rules{Only: map[string][]string{"crm": {"deck"}}}
		c.RequestWait = 50 * time.Millisecond
	}, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	ref := store.Ref{Instance: "crm", ID: "T1"}
	if _, err := e.Hub.Reveal(ctx, ref, tty, revealKey("T1", "tty")); !errors.Is(err, hub.ErrNotRouted) {
		t.Errorf("tty not routed for crm: %v", err)
	}
	deck := hub.Asker{Facade: "deck", ApproverID: "host:uid:1000"}
	if _, err := e.Hub.Reveal(ctx, ref, deck, revealKey("T1", "tty")); !errors.Is(err, hub.ErrForeignKey) {
		t.Errorf("a tty key from the deck: %v", err)
	}
	if _, err := e.Hub.Reveal(ctx, ref, deck, revealKey("T2", "deck")); !errors.Is(err, hub.ErrForeignKey) {
		t.Errorf("a key for another ticket: %v", err)
	}
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 0); len(reqs) != 0 {
		t.Errorf("a refused reveal reached the lock")
	}
}

func TestRequestCap(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 3 * time.Second }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	errs := make(chan error, hub.MaxOpenRequests+1)
	for range hub.MaxOpenRequests {
		go func() {
			_, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
			errs <- err
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, r, _ := e.Hub.Poll(ctx, "crm", 0, 0); len(r) == hub.MaxOpenRequests {
			break
		}
	}
	if _, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty")); !errors.Is(err, hub.ErrBusy) {
		t.Errorf("request over the cap: %v", err)
	}
}

func TestRevealOnlyPending(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	e.Hub.Decide(ctx, store.Ref{Instance: "crm", ID: "T1"}, approve("T1"))
	if _, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty")); !errors.Is(err, hub.ErrState) {
		t.Errorf("reveal of a decided ticket: %v", err)
	}
	if _, err := e.Hub.Renew(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty); !errors.Is(err, hub.ErrState) {
		t.Errorf("renew of an approved ticket: %v", err)
	}
}

// A renewal pushed by the lock ends the old ticket expired (pending or
// approved but not run), links them, and the expired list drops it.
func TestRenewalPushExpiresTheOld(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.New(t, 0, a)
	for _, approved := range []bool{false, true} {
		old := fmt.Sprintf("OLD-%v", approved)
		e.Hub.Push(ctx, "crm", a.Ticket(old, "write", e.Clock.T, time.Hour))
		if approved {
			e.Hub.Decide(ctx, store.Ref{Instance: "crm", ID: old}, approve(old))
		}
		nw := "NEW-" + old
		if _, _, err := e.Hub.Push(ctx, "crm", a.TicketWith(nw, "write", e.Clock.T, time.Hour, func(t *hubtest.Ticket) { t.RenewsOf = old })); err != nil {
			t.Fatal(err)
		}
		if st := ticketState(t, e, old); st != state.Expired {
			t.Errorf("%s is %s after its renewal", old, st)
		}
		if err := e.Hub.Consumed(ctx, "crm", old); err == nil {
			t.Errorf("an expired approval was consumed")
		}
	}
	exp, err := e.Hub.Expired(ctx)
	if err != nil || len(exp) != 0 {
		t.Errorf("renewed tickets still offered: %v %v", exp, err)
	}
}

func ticketState(t *testing.T, e hubtest.Env, id string) state.State {
	t.Helper()
	var tk store.Ticket
	e.Store.Tx(ctx, func(tx *store.Tx) error {
		var err error
		tk, err = tx.Ticket(store.Ref{Instance: "crm", ID: id})
		return err
	})
	return tk.State
}

// A pending ticket past its TTL is offered for re-approval, for 24 hours.
func TestExpiredOffered(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	e.Clock.T = e.Clock.T.Add(2 * time.Hour)
	e.Hub.Sweep(ctx)
	if exp, _ := e.Hub.Expired(ctx); len(exp) != 1 || exp[0].ID != "T1" {
		t.Errorf("expired list %v", exp)
	}
	e.Clock.T = e.Clock.T.Add(hub.ExpiredWindow + time.Minute)
	if exp, _ := e.Hub.Expired(ctx); len(exp) != 0 {
		t.Errorf("offered after the window: %v", exp)
	}
}

// H1: an unchanged, non-production renewal asked from the terminal is
// approved at once; changed or production, it waits. A ticket the lock
// renewed already (its approval aged out) gives its renewal.
func TestRenewOneClick(t *testing.T) {
	for name, c := range map[string]struct {
		approved, unchanged, production bool
		auto                            bool
		reason                          string
	}{
		"unchanged":          {unchanged: true, auto: true, reason: hub.RenewalReason},
		"unchanged approval": {approved: true, unchanged: true, auto: true, reason: hub.ReapprovalReason},
		"changed":            {},
		"changed approval":   {approved: true},
		"production":         {unchanged: true, production: true},
	} {
		t.Run(name, func(t *testing.T) {
			a := hubtest.NewLock("crm")
			e := hubtest.New(t, 0, a)
			e.Hub.Push(ctx, "crm", a.TicketWith("OLD", "write", e.Clock.T, time.Hour, func(t *hubtest.Ticket) {
				t.Production, t.Retype = c.production, "r"
			}))
			old := store.Ref{Instance: "crm", ID: "OLD"}
			renewal := func() {
				e.Hub.Push(ctx, "crm", a.TicketWith("NEW", "write", e.Clock.T, time.Hour, func(t *hubtest.Ticket) {
					t.RenewsOf, t.Unchanged, t.Production, t.Retype = "OLD", c.unchanged, c.production, "r"
				}))
			}
			var asked atomic.Int32
			lockAnswers(t, e, "crm", func(q hubtest.Request) string {
				asked.Add(1)
				if q.Kind != "renew" || q.Ticket != "OLD" {
					t.Errorf("request %+v", q.Request)
				}
				renewal()
				return `{"ticket":"NEW"}`
			})
			if c.approved {
				// The approval aged out at the lock, which renewed it.
				v := approve("OLD")
				v.Retype = "crm"
				if _, err := e.Hub.Decide(ctx, old, v); err != nil {
					t.Fatal(err)
				}
				renewal()
			} else {
				e.Clock.T = e.Clock.T.Add(2 * time.Hour)
				e.Hub.Sweep(ctx)
			}
			if st := ticketState(t, e, "OLD"); st != state.Expired {
				t.Fatalf("old ticket is %s", st)
			}
			res, err := e.Hub.Renew(ctx, old, tty)
			if err != nil || res.Ticket != "NEW" || res.AutoApproved != c.auto {
				t.Fatalf("Renew = %+v, %v", res, err)
			}
			if wantAsked := map[bool]int{true: 0, false: 1}[c.approved]; int(asked.Load()) != wantAsked {
				t.Errorf("lock asked %d times, want %d", asked.Load(), wantAsked)
			}
			want := state.Pending
			if c.auto {
				want = state.Approved
			}
			if st := ticketState(t, e, "NEW"); st != want {
				t.Errorf("renewal is %s, want %s", st, want)
			}
			log, _ := os.ReadFile(e.Audit)
			if c.auto && !strings.Contains(string(log), c.reason) {
				t.Errorf("audit: %s", log)
			}
			if !strings.Contains(string(log), `"event":"renew"`) {
				t.Errorf("no renew event: %s", log)
			}
			// Asked again: the same renewal, no new request.
			if res2, err := e.Hub.Renew(ctx, old, tty); err != nil || res2.Ticket != "NEW" || res2.AutoApproved {
				t.Errorf("renew twice: %+v %v", res2, err)
			}
		})
	}
}

// The sweeper lists due tickets, then expires each: a Decide that gets
// in between leaves the ticket approved, its signed decision usable.
func TestSweeperNeverEndsAnApproval(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.New(t, 0, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	ref := store.Ref{Instance: "crm", ID: "T1"}
	if _, err := e.Hub.Decide(ctx, ref, approve("T1")); err != nil {
		t.Fatal(err)
	}
	e.Clock.T = e.Clock.T.Add(2 * time.Hour)
	var te state.ErrTransition
	if err := e.Hub.SweepOne(ctx, ref); !errors.As(err, &te) {
		t.Errorf("sweep of an approved ticket: %v", err)
	}
	if err := e.Hub.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if st := ticketState(t, e, "T1"); st != state.Approved {
		t.Fatalf("approved ticket is %s after the sweep", st)
	}
	if err := e.Hub.Consumed(ctx, "crm", "T1"); err != nil {
		t.Errorf("consumed: %v", err)
	}
}

// A delivered request does not wake the poll again: a lock that does not
// answer it cannot spin; it still comes with the poll's answer.
func TestPollDoesNotSpinOnDeliveredRequest(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 5 * time.Second }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	go e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 5*time.Second); len(reqs) != 1 {
		t.Fatalf("first poll: %d requests", len(reqs))
	}
	start := time.Now()
	_, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 300*time.Millisecond)
	if d := time.Since(start); d < 250*time.Millisecond || len(reqs) != 1 {
		t.Errorf("second poll returned after %s with %d requests", d, len(reqs))
	}
}

func TestRenewOutsideTheWindow(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 50 * time.Millisecond }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	e.Clock.T = e.Clock.T.Add(2 * time.Hour)
	e.Hub.Sweep(ctx)
	e.Clock.T = e.Clock.T.Add(hub.ExpiredWindow + time.Minute)
	if _, err := e.Hub.Renew(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty); !errors.Is(err, hub.ErrState) {
		t.Errorf("renew after the window: %v", err)
	}
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 0); len(reqs) != 0 {
		t.Error("the lock was asked")
	}
}

func TestRenewNotRouted(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.Routes = route.Rules{Only: map[string][]string{"crm": {"deck"}}} }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	e.Clock.T = e.Clock.T.Add(2 * time.Hour)
	e.Hub.Sweep(ctx)
	if _, err := e.Hub.Renew(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty); !errors.Is(err, hub.ErrNotRouted) {
		t.Errorf("tty renew, crm routed to deck only: %v", err)
	}
}

// No one click when the renewal is not the same request as far as the
// hub can tell (other risk, other flags), and an error when the lock
// answers a ticket that renews another one.
func TestRenewNoOneClickForAnotherRequest(t *testing.T) {
	for name, c := range map[string]struct {
		mod    func(*hubtest.Ticket)
		badAns bool
	}{
		"other risk":   {mod: func(t *hubtest.Ticket) { t.Risk = "policy-loosen" }},
		"other flags":  {mod: func(t *hubtest.Ticket) { t.Retype = "other" }},
		"renews other": {mod: func(t *hubtest.Ticket) { t.RenewsOf = "OTHER" }, badAns: true},
	} {
		t.Run(name, func(t *testing.T) {
			a := hubtest.NewLock("crm")
			e := hubtest.New(t, 0, a)
			e.Hub.Push(ctx, "crm", a.Ticket("OTHER", "write", e.Clock.T, 48*time.Hour))
			e.Hub.Push(ctx, "crm", a.Ticket("OLD", "write", e.Clock.T, time.Hour))
			e.Clock.T = e.Clock.T.Add(2 * time.Hour)
			e.Hub.Sweep(ctx)
			lockAnswers(t, e, "crm", func(q hubtest.Request) string {
				e.Hub.Push(ctx, "crm", a.TicketWith("NEW", "write", e.Clock.T, time.Hour, func(t *hubtest.Ticket) {
					t.RenewsOf, t.Unchanged = "OLD", true
					c.mod(t)
				}))
				return `{"ticket":"NEW"}`
			})
			res, err := e.Hub.Renew(ctx, store.Ref{Instance: "crm", ID: "OLD"}, tty)
			if c.badAns {
				if !errors.Is(err, hub.ErrBadAnswer) {
					t.Errorf("renewal of another ticket: %+v %v", res, err)
				}
			} else if err != nil || res.AutoApproved {
				t.Errorf("Renew = %+v, %v; want pending", res, err)
			}
			if st := ticketState(t, e, "NEW"); st != state.Pending {
				t.Errorf("NEW is %s", st)
			}
		})
	}
}

// Two pollers of one instance (a restarted lock whose old process still
// polls): a new request wakes both, and both return with it, instead of
// the second going back to sleep for the rest of its poll because the
// first was given it. A poll that begins after the request was given
// waits with it open (no spin).
func TestTwoPollersBothGetANewRequest(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 5 * time.Second }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	got := make(chan int, 2)
	for range 2 {
		go func() {
			_, reqs, err := e.Hub.Poll(ctx, "crm", 0, 20*time.Second)
			if err != nil {
				t.Error(err)
			}
			got <- len(reqs)
		}()
	}
	time.Sleep(100 * time.Millisecond) // both polls are waiting
	go e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
	for range 2 {
		select {
		case n := <-got:
			if n != 1 {
				t.Errorf("a poller got %d request(s)", n)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a poller lost the wake-up: it is still waiting")
		}
	}
	// Given to both, still open: a new poll waits its full time with it.
	start := time.Now()
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 300*time.Millisecond); len(reqs) != 1 || time.Since(start) < 250*time.Millisecond {
		t.Errorf("a request already given ended a new poll early, or is gone (%v, %d)", time.Since(start), len(reqs))
	}
}

// The window between a poll's start and its first look: a request opened
// before poller B began, but first given to poller A after B began, is
// fresh for B (freshness counts from the first give, not the opening).
func TestRequestGivenAfterAPollBeganIsFreshForIt(t *testing.T) {
	a := hubtest.NewLock("crm")
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 5 * time.Second }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	go e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
	for deadline := time.Now().Add(5 * time.Second); e.Hub.OpenCount("crm") == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no request opened")
		}
	}
	startA := e.Hub.GiveStart()
	startB := e.Hub.GiveStart() // B begins after the opening, before A looks
	if reqs, fresh := e.Hub.OpenRequestsFor("crm", startA); len(reqs) != 1 || !fresh {
		t.Fatalf("poller A: %d %v", len(reqs), fresh)
	}
	if reqs, fresh := e.Hub.OpenRequestsFor("crm", startB); len(reqs) != 1 || !fresh {
		t.Fatalf("poller B lost the request A was given after B began: %d %v", len(reqs), fresh)
	}
	// A poll that begins after the give: not fresh.
	if _, fresh := e.Hub.OpenRequestsFor("crm", e.Hub.GiveStart()); fresh {
		t.Fatal("a request given before the poll began is fresh: a lock could spin")
	}
}

// An old lock process takes a request while the live one is between
// polls, and never answers: the live one's next poll began after the
// give, yet it is offered the request again after ReofferAfter, well
// before the facade gives up; a lock that does not answer is woken once
// per ReofferAfter, not in a loop.
func TestUnansweredRequestReofferedToTheNextPoll(t *testing.T) {
	a := hubtest.NewLock("crm")
	const reoffer = 300 * time.Millisecond
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 5 * time.Second; c.ReofferAfter = reoffer }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	const sealed = `{"box":"ciphertext"}`
	type res struct {
		ans []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		ans, err := e.Hub.Reveal(ctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
		done <- res{ans, err}
	}()
	// The old process takes it, and goes away without answering.
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 5*time.Second); len(reqs) != 1 {
		t.Fatalf("old process: %d requests", len(reqs))
	}
	// The live lock's poll begins after the give.
	start := time.Now()
	_, reqs, err := e.Hub.Poll(ctx, "crm", 0, 20*time.Second)
	d := time.Since(start)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("live lock: %d requests, %v", len(reqs), err)
	}
	if d < reoffer/2 || d > 3*time.Second {
		t.Fatalf("the live lock got the request after %s, want about %s", d, reoffer)
	}
	// Not answered yet: the next poll is not woken before ReofferAfter.
	start = time.Now()
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 20*time.Second); len(reqs) != 1 || time.Since(start) < reoffer/2 {
		t.Fatalf("a poll woke after %s for a request it was just offered (%d)", time.Since(start), len(reqs))
	}
	var q hubtest.Request
	json.Unmarshal(reqs[0], &q)
	if err := e.Hub.AnswerRequest("crm", q.ID, []byte(`{"reveal":`+sealed+`}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || string(r.ans) != sealed {
			t.Fatalf("Reveal = %s, %v", r.ans, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the facade is still waiting")
	}
}

// A re-offer wakes every waiting poller, not only the one whose timer
// fired first.
func TestReofferWakesEveryPoller(t *testing.T) {
	a := hubtest.NewLock("crm")
	const reoffer = 300 * time.Millisecond
	e := hubtest.NewWith(t, func(c *hub.Config) { c.RequestWait = 5 * time.Second; c.ReofferAfter = reoffer }, a)
	e.Hub.Push(ctx, "crm", a.Ticket("T1", "write", e.Clock.T, time.Hour))
	rctx, cancel := context.WithCancel(ctx)
	revealed := make(chan struct{})
	go func() {
		defer close(revealed)
		e.Hub.Reveal(rctx, store.Ref{Instance: "crm", ID: "T1"}, tty, revealKey("T1", "tty"))
	}()
	t.Cleanup(func() { cancel(); <-revealed })
	if _, reqs, _ := e.Hub.Poll(ctx, "crm", 0, 5*time.Second); len(reqs) != 1 {
		t.Fatalf("first give: %d requests", len(reqs))
	}
	got := make(chan time.Duration, 2)
	start := time.Now()
	for range 2 {
		go func() {
			e.Hub.Poll(ctx, "crm", 0, 20*time.Second)
			got <- time.Since(start)
		}()
	}
	for range 2 {
		select {
		case d := <-got:
			if d > 3*time.Second {
				t.Errorf("a poller returned after %s", d)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a poller was not woken by the re-offer")
		}
	}
}
