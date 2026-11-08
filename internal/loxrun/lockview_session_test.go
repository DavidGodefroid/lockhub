package loxrun

import (
	"strings"
	"testing"
	"time"
)

// commandConsoles are fake consoles that take commands (:review,
// :status) typed from lox run.
type commandConsoles struct {
	*fakeConsoles
	commands chan string
}

func (c commandConsoles) Command(instance, line string) error {
	c.commands <- instance + " " + line
	return nil
}

// print makes instance's console print lines.
func (f *fakeConsoles) print(instance string, lines ...string) {
	f.ch <- ConsoleEvent{Instance: instance, Lock: "locksql", Feed: &ConsoleFeed{Lines: lines}}
}

func frameSince(h *harness, from int) string { return h.output()[from:] }

// waitFrame waits until a frame drawn after from shows want.
func waitFrame(t *testing.T, h *harness, from int, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(frameSince(h, from), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q on screen; last output:\n%s", want, tail(frameSince(h, from)))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func tail(s string) string {
	if len(s) > 4000 {
		return s[len(s)-4000:]
	}
	return s
}

// The e2e of the per-lock view (#146): an agent hits E_COST twice and
// the lock's tab shows one refusal with a counter; a third raises the
// loop's alert in the global feed; a loosening refused at the console's
// start shows in the tab, is reviewed from lox run (r types :review at
// the console, its question is a card here, y answers it there) and
// shows approved once the console applied it. The lock tab shows the
// limits in force and the session's time left.
func TestLockTabSession(t *testing.T) {
	cons := commandConsoles{newFakeConsoles(), make(chan string, 8)}
	h := start(t, newFakeHub(), nil, func(s *Session) {
		s.Consoles = cons
		s.Size = func() (int, int) { return 120, 40 }
		s.Style = Style{Unicode: true}
	})
	cons.state("shop", ConsoleServing, "")
	cons.print("shop",
		"The policy of profile shop-prod changed since it was approved:",
		"  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)",
		"changes refused: the last approved policy applies",
		"▸ Requests are decided on lockhub at https://hub:8443 as shop",
		// A :status opens on its profile row.
		"  profile        shop-prod · mysql 10.0.0.5 · tier read · production true",
		"  session        ends in 58 min (max_session 1h0m0s) · idle_timeout 10m0s",
	)
	h.wait(EvPolicy, "")
	from := len(h.output())
	waitFrame(t, h, from, "1 shop ◆ policy refused")

	box := planBox("SELECT * FROM book WHERE supplier = 'ACME'", "REFUSE")
	box = box[:len(box)-1] // refused before any ticket: no pending line
	cons.print("shop", box...)
	cons.print("shop", "✗ refused [E_COST]: weight check: estimated rows examined 1 943 473 > 200 000")
	cons.print("shop", "✗ refused [E_COST]: weight check: estimated rows examined 1 943 473 > 200 000")

	from = len(h.output())
	h.keys <- R('1')
	waitFrame(t, h, from, "refused [E_COST] ×2 weight check")
	waitFrame(t, h, from, "REFUSED: the last approved policy applies")
	waitFrame(t, h, from, "~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)")
	waitFrame(t, h, from, "of idle_timeout 10m (")
	waitFrame(t, h, from, "(max_session 1h)")
	if strings.Contains(h.output(), "ACME") {
		t.Fatal("a literal of the agent's statement is on screen")
	}

	// A third: a loop, alerted in the global feed.
	cons.print("shop", "✗ refused [E_COST]: weight check: estimated rows examined 1 943 473 > 200 000")
	h.wait(EvAlert, "")
	from = len(h.output())
	h.keys <- R('0')
	waitFrame(t, h, from, "lock-side refusal loop: E_COST ×3")

	// o shows the statement in clear, on this screen only.
	from = len(h.output())
	h.keys <- R('1')
	h.keys <- R('o')
	waitFrame(t, h, from, "supplier = 'ACME'")
	h.keys <- R('o')

	// r: the review, at the console, answered here.
	h.keys <- R('r')
	select {
	case c := <-cons.commands:
		if c != "shop :review" {
			t.Fatalf("typed %q", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("r typed no :review")
	}
	cons.print("shop", "pending policy change for profile shop-prod:", "  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)")
	cons.ask("shop", `Type the profile name "shop-prod" to apply it:`, "pending policy change for profile shop-prod:",
		"  ~ limits.idle_timeout: 10m0s → 1h0m0s  (loosens)")
	h.wait(EvQuestion, "")
	typeIn(h, "shop-prod")
	if a := h.typedAt(cons.fakeConsoles); a != "shop-prod" {
		t.Fatalf("typed %q", a)
	}
	cons.state("shop", ConsoleServing, "")
	cons.print("shop", "policy change applied")
	h.wait(EvPolicy, "")
	from = len(h.output())
	waitFrame(t, h, from, "approved: the files hold the policy in force")

	// i: the console's :status again, for the limits now in force.
	h.keys <- R('i')
	select {
	case c := <-cons.commands:
		if c != "shop :status" {
			t.Fatalf("typed %q", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("i typed no :status")
	}
	cons.print("shop",
		"  profile        shop-prod · mysql 10.0.0.5 · tier read · production true",
		"  session        ends in 50 min (max_session 1h0m0s) · idle_timeout 1h0m0s")
	from = len(h.output())
	waitFrame(t, h, from, "of idle_timeout 1h (")
}

// slowConsoles take a command only once released: a console's terminal
// slow to answer.
type slowConsoles struct {
	*fakeConsoles
	release chan struct{}
	typed   chan string
}

func (c slowConsoles) Command(instance, line string) error {
	<-c.release
	c.typed <- instance + " " + line
	return nil
}

// r (and i) type at the console without freezing the screen: keys are
// read while the command waits; its outcome shows once it is typed.
func TestLockTabCommandAsync(t *testing.T) {
	cons := slowConsoles{newFakeConsoles(), make(chan struct{}), make(chan string, 1)}
	h := start(t, newFakeHub(), nil, func(s *Session) {
		s.Consoles = cons
		s.Size = func() (int, int) { return 120, 40 }
		s.Style = Style{Unicode: true}
	})
	cons.state("shop", ConsoleServing, "")
	from := len(h.output())
	cons.print("shop", "▸ Requests are decided on lockhub at https://hub:8443 as shop")
	waitFrame(t, h, from, "1 shop")
	from = len(h.output())
	h.keys <- R('1')
	waitFrame(t, h, from, "console serving")
	from = len(h.output())
	h.keys <- R('r')
	h.keys <- R('o')
	waitFrame(t, h, from, "statements in clear on this screen")
	close(cons.release)
	select {
	case c := <-cons.typed:
		if c != "shop :review" {
			t.Fatalf("typed %q", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("r typed no :review")
	}
	waitFrame(t, h, from, "review asked")
}
