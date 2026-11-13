package loxrun

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
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
	var sc *screen
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) { sc = newScreen(t, s, 120, 30) })
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

	f := sc.press(R('w'))
	sc.want(f, "pending at the hub")
	for _, want := range []string{"4 tickets", "shop 4", "(3 unverifiable)", "10m", "unverifiable", "asked", "UPDATE orders"} {
		if !strings.Contains(f, want) {
			t.Errorf("overlay lacks %q:\n%s", want, f)
		}
	}
	sc.want(sc.press(R('U')), "withdraw all 3 unverifiable tickets of shop? [y/N]")
	sc.keys <- R('y')
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
	sc.want(sc.now(), "withdrew 3 tickets")

	sc.want(sc.press(R('x')), "withdraw ticket "+upd.ID+" of shop (asked")
	sc.want(sc.press(R('n')), "nothing withdrawn")
	if _, ok := hub.withdrawals()[upd.ID]; ok {
		t.Fatal("n withdrew the ticket")
	}
	sc.want(sc.press(R('x')), "withdraw ticket "+upd.ID)
	sc.keys <- R('y')
	h.wait(EvWithdrawn, upd.ID)
	if _, ok := hub.decision(upd.ID); ok {
		t.Error("a withdrawn question was decided too")
	}
	f = sc.now()
	sc.want(f, "withdrew 1 ticket")
	if strings.Contains(f, "UPDATE orders SET paid = true\n") {
		t.Errorf("the question's card is still up:\n%s", f)
	}
	sc.want(sc.press(Key{Code: KeyEsc}), "(withdrawn by you)")
}

// A queue the hub listed before a withdrawal, read by the loop after
// it (the long poll answered while the withdrawals were in flight),
// does not bring the withdrawn ticket back into the w overlay (#171).
func TestWithdrawStaleQueue(t *testing.T) {
	lk := newLockKey()
	st := newState(&Session{Size: func() (int, int) { return 120, 30 }, Out: io.Discard, Display: "david",
		LockKeys: map[string]ed25519.PublicKey{"shop": lk.pub}})
	var items []api.QueueItem
	for i := 0; i < 2; i++ {
		it := lk.item(t, ticket.KindRead, ticket.RiskRead, "dev", "SELECT id FROM orders", nil)
		it.Facades = []string{"mobile"}
		items = append(items, it)
	}
	st.onQueue(api.QueueResult{Tickets: slices.Clone(items), Version: 2}, nil)
	st.onWithdrawn(withdrawEffect{"shop", items[0].ID}, api.WithdrawResult{Told: true}, nil)
	st.onQueue(api.QueueResult{Tickets: slices.Clone(items), Version: 2}, nil) // listed before the withdrawal
	if rows := st.withdrawRows(); len(rows) != 1 || rows[0].ID != items[1].ID {
		t.Fatalf("rows after a stale queue: %+v", rows)
	}
	st.onQueue(api.QueueResult{Tickets: items[1:], Version: 3}, nil)
	if len(st.withdraw.gone) != 0 {
		t.Errorf("gone kept after the hub listed without it: %v", st.withdraw.gone)
	}
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
