package loxrun

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// The w overlay lists the hub's pending tickets with their age; U
// withdraws, after a y, every ticket of the selected lock that lox run
// cannot verify (left pending: routed to a facade nobody watches), x
// the selected one; anything but y withdraws nothing. A question
// withdrawn leaves its card.
func TestSessionWithdraw(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	var frames []string
	var mu sync.Mutex
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		s.Size = func() (int, int) { return 120, 30 }
		s.Style = Style{Unicode: true}
		s.Out = writerFunc(func(p []byte) {
			mu.Lock()
			frames = append(frames, string(p))
			mu.Unlock()
		})
	})
	last := func(want string) string {
		h.t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			for i := len(frames) - 1; i >= 0; i-- {
				if strings.Contains(frames[i], want) {
					f := frames[i]
					mu.Unlock()
					return f
				}
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("no frame with %q; last:\n%s", want, frames[len(frames)-1])
		return ""
	}
	var stuck []string
	for i := 0; i < 3; i++ {
		it := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT id FROM orders WHERE id < 2", nil)
		it.Ticket = json.RawMessage(strings.ReplaceAll(string(it.Ticket), "<", "\\u003c")) // does not verify
		it.Facades = []string{"mobile"}
		it.Created = time.Now().Add(-time.Duration(10-i) * time.Minute)
		hub.push(it)
		h.wait(EvTicket, it.ID)
		stuck = append(stuck, it.ID)
	}
	upd := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE orders SET paid = true", nil)
	hub.push(upd)
	h.wait(EvQuestion, upd.ID)

	h.keys <- R('w')
	f := last("pending at the hub")
	for _, want := range []string{"4 tickets", "shop 4", "(3 unverifiable)", "10m", "unverifiable", "asked", "UPDATE orders"} {
		if !strings.Contains(f, want) {
			t.Errorf("overlay lacks %q:\n%s", want, f)
		}
	}
	h.keys <- R('U')
	last("withdraw all 3 unverifiable tickets of shop? [y/N]")
	h.keys <- R('y')
	left := map[string]bool{stuck[0]: true, stuck[1]: true, stuck[2]: true}
	for len(left) > 0 { // withdrawn concurrently: in any order
		e := h.wait(EvWithdrawn, "")
		if e.Err != nil || !left[e.ID] {
			t.Fatalf("withdraw %s: %v", e.ID, e.Err)
		}
		delete(left, e.ID)
	}
	w := hub.withdrawals()
	if len(w) != 3 {
		t.Fatalf("withdrawn %v", w)
	}
	for _, id := range stuck {
		if r := w[id]; r.Facade != "tty" || r.Display != "david" || r.Via != "lox run" {
			t.Errorf("withdrawal of %s: %+v", id, r)
		}
	}
	last("withdrew 3 tickets")

	h.keys <- R('x')
	last("withdraw ticket " + upd.ID + " of shop (asked")
	h.keys <- R('n')
	last("nothing withdrawn")
	if _, ok := hub.withdrawals()[upd.ID]; ok {
		t.Fatal("n withdrew the ticket")
	}
	h.keys <- R('x')
	last("withdraw ticket " + upd.ID)
	h.keys <- R('y')
	h.wait(EvWithdrawn, upd.ID)
	if _, ok := hub.decision(upd.ID); ok {
		t.Error("a withdrawn question was decided too")
	}
	f = last("withdrew 1 ticket")
	if strings.Contains(f, "UPDATE orders SET paid = true\n") {
		t.Errorf("the question's card is still up:\n%s", f)
	}
	h.keys <- Key{Code: KeyEsc}
	last("(withdrawn by you)")
}

// The w overlay with nothing pending says so, and shows its keys.
func TestWithdrawOverlayEmpty(t *testing.T) {
	v := View{Overlay: overlayWithdraw, Withdraw: &WithdrawView{}, Now: time.Now()}
	out := strings.Join(Frame(v, 80, 12, Style{}), "\n")
	if !strings.Contains(out, "nothing pending") || !strings.Contains(out, "x withdraw") {
		t.Errorf("frame:\n%s", out)
	}
}

func TestParseArrows(t *testing.T) {
	ks := ParseKeys([]byte("\x1b[A\x1b[B\x1bOA\x1b[C"))
	if len(ks) != 4 || ks[0].Code != KeyUp || ks[1].Code != KeyDown || ks[2].Code != KeyUp || ks[3].Code != KeyUnknown {
		t.Errorf("keys %+v", ks)
	}
}
