package loxrun

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// The w overlay lists every ticket pending at the hub, oldest first, with
// its age, and withdraws the ones the human picks: one (x), all of its
// lock (X), or all of its lock that lox run cannot verify (U), each after
// a y/N confirmation. A withdrawn ticket ends at the hub and in its lock
// (the hub sends it a denial naming the withdrawal), which frees the
// lock's queue: the way out for tickets nothing else will decide (a
// burst of retries, tickets that do not verify, tickets routed to a
// facade nobody watches).

// overlayWithdraw is the w overlay.
const overlayWithdraw = "withdraw"

// withdrawState is the overlay's state, owned by Run's loop.
type withdrawState struct {
	queue    []api.QueueItem // the hub's pending tickets, as last listed
	sel      int             // the selected row
	confirm  *withdrawAsk    // the y/N question open, nil none
	inFlight map[string]bool // instance/id being withdrawn
	pending  []withdrawEffect
	// done and failed count the current batch's outcomes; untold its
	// tickets whose lock the hub could not tell.
	done, failed, untold int
	lastErr              string
}

type withdrawAsk struct {
	prompt string
	refs   []withdrawEffect
}

// withdrawEffect is a withdrawal the loop sends to the hub.
type withdrawEffect struct{ instance, id string }

// WithdrawRow is one pending ticket of the w overlay.
type WithdrawRow struct {
	Instance, ID, Lock string
	Age                time.Duration
	// Tag is where lox run stands on it: asked, unverifiable, not
	// answerable here, deciding, withdrawing, pending.
	Tag        string
	Unreadable bool
	Summary    string
}

// WithdrawView is the w overlay as one frame shows it.
type WithdrawView struct {
	Rows    []WithdrawRow
	Sel     int
	Confirm string
}

// Tags of a WithdrawRow.
const (
	tagAsked       = "asked"
	tagUnreadable  = "unverifiable"
	tagElsewhere   = "not answerable here"
	tagSending     = "deciding"
	tagWithdrawing = "withdrawing"
	tagPending     = "pending"
)

func (st *state) withdrawRows() []WithdrawRow {
	now := st.s.now()
	var rows []WithdrawRow
	for _, it := range st.withdraw.queue {
		k := key(it.Instance, it.ID)
		r := WithdrawRow{Instance: clean(it.Instance), ID: it.ID, Age: now.Sub(it.Created), Tag: tagPending}
		t := st.seen[k]
		switch {
		case st.withdraw.inFlight[k]:
			r.Tag = tagWithdrawing
		case t != nil && t.unreadable, t != nil && t.tk == nil && t.cq == nil:
			r.Tag, r.Unreadable = tagUnreadable, true
		case t != nil && t.card != nil:
			r.Tag = tagAsked
		case !local(it.Facades):
			r.Tag = tagElsewhere
		case t != nil && t.sending:
			r.Tag = tagSending
		}
		if t != nil && t.entry != nil {
			r.Summary, r.Lock = t.entry.Summary, t.entry.Lock
		}
		if t == nil {
			if tk, _, err := parseTicket(it, st.s.LockKeys); err != nil {
				r.Tag, r.Unreadable, r.Summary = tagUnreadable, true, unreadableSummary
			} else {
				r.Summary, r.Lock = summary(tk), clean(tk.Source.Lock)
			}
		}
		rows = append(rows, r)
	}
	slices.SortStableFunc(rows, func(a, b WithdrawRow) int { return int((b.Age - a.Age) / time.Millisecond) })
	return rows
}

func (st *state) withdrawView() *WithdrawView {
	rows := st.withdrawRows()
	st.withdraw.sel = min(max(st.withdraw.sel, 0), max(len(rows)-1, 0))
	v := &WithdrawView{Rows: rows, Sel: st.withdraw.sel}
	if st.withdraw.confirm != nil {
		v.Confirm = st.withdraw.confirm.prompt
	}
	return v
}

// withdrawKey handles a key while the w overlay is open.
func (st *state) withdrawKey(k Key) {
	w := &st.withdraw
	if w.confirm != nil {
		ask := w.confirm
		w.confirm = nil
		if k.Code == KeyRune && (k.Rune == 'y' || k.Rune == 'Y') {
			st.startWithdraw(ask.refs)
		} else {
			st.setFlash("nothing withdrawn")
		}
		return
	}
	rows := st.withdrawRows()
	switch k.Code {
	case KeyEsc:
		st.overlay = ""
		return
	case KeyUp:
		w.sel--
		return
	case KeyDown:
		w.sel++
		return
	case KeyEnter:
		k = R('x')
	case KeyRune:
	default:
		return
	}
	if w.sel >= len(rows) {
		w.sel = len(rows) - 1
	}
	var sel *WithdrawRow
	if w.sel >= 0 && w.sel < len(rows) {
		sel = &rows[w.sel]
	}
	switch k.Rune {
	case 'w', 'W', 'q', 'Q':
		st.overlay = ""
	case 'k':
		w.sel--
	case 'j':
		w.sel++
	case 'x':
		if sel == nil || sel.Tag == tagWithdrawing {
			return
		}
		w.confirm = &withdrawAsk{prompt: fmt.Sprintf("withdraw ticket %s of %s (%s, waiting %s)? [y/N]", sel.ID, sel.Instance, sel.Tag, age(sel.Age)),
			refs: []withdrawEffect{{sel.Instance, sel.ID}}}
	case 'X', 'U':
		if sel == nil {
			return
		}
		unreadable := k.Rune == 'U'
		var refs []withdrawEffect
		for _, r := range rows {
			if r.Instance == sel.Instance && r.Tag != tagWithdrawing && (!unreadable || r.Unreadable) {
				refs = append(refs, withdrawEffect{r.Instance, r.ID})
			}
		}
		what := "pending"
		if unreadable {
			what = "unverifiable"
		}
		if len(refs) == 0 {
			st.setFlash("no " + what + " ticket of " + sel.Instance + " to withdraw")
			return
		}
		w.confirm = &withdrawAsk{prompt: fmt.Sprintf("withdraw all %d %s ticket%s of %s? [y/N]", len(refs), what, plural(len(refs)), sel.Instance),
			refs: refs}
	}
}

// startWithdraw queues the withdrawal of refs for the loop.
func (st *state) startWithdraw(refs []withdrawEffect) {
	w := &st.withdraw
	if w.inFlight == nil {
		w.inFlight = map[string]bool{}
	}
	if len(w.inFlight) == 0 {
		w.done, w.failed, w.untold, w.lastErr = 0, 0, 0, ""
	}
	for _, r := range refs {
		k := key(r.instance, r.id)
		if w.inFlight[k] {
			continue
		}
		w.inFlight[k] = true
		w.pending = append(w.pending, r)
	}
	st.dirty = true
}

// withdrawReq is lox run's withdrawal request.
func (st *state) withdrawReq() api.WithdrawRequest {
	return api.WithdrawRequest{Facade: route.TTY, Display: st.s.Display, Via: "lox run"}
}

// onWithdrawn is the hub's answer to a withdrawal.
func (st *state) onWithdrawn(ef withdrawEffect, res api.WithdrawResult, err error) {
	w := &st.withdraw
	k := key(ef.instance, ef.id)
	delete(w.inFlight, k)
	st.dirty = true
	if err != nil {
		w.failed++
		w.lastErr = approve.Explain(err)
	} else {
		w.done++
		if !res.Told {
			w.untold++
		}
		w.queue = slices.DeleteFunc(w.queue, func(it api.QueueItem) bool { return it.Instance == ef.instance && it.ID == ef.id })
		if t, ok := st.seen[k]; ok {
			st.removeCard(t)
			st.detach(t)
			t.decided = true
			delete(st.results, k)
			if t.entry != nil {
				t.entry.Status, t.entry.Result, t.entry.Note = Undecided, ResWithdrawn, "(withdrawn by you)"
				st.printEntry(t.entry)
			}
		}
	}
	st.s.observe(Event{Kind: EvWithdrawn, Instance: ef.instance, ID: ef.id, Err: err})
	if len(w.inFlight) > 0 {
		return
	}
	msg := "withdrew " + strconv.Itoa(w.done) + " ticket" + plural(w.done)
	if w.untold > 0 {
		msg += " (" + strconv.Itoa(w.untold) + " the hub could not verify: their lock ends them with their TTL)"
	}
	if w.failed > 0 {
		msg += "; " + strconv.Itoa(w.failed) + " could not be withdrawn: " + w.lastErr
	}
	st.setFlash(msg)
}

// PendingTicket is a ticket pending at the hub as lox tickets lists it:
// what lox run would show of it, masked.
type PendingTicket struct {
	Instance, ID, Lock, Risk string
	Created                  time.Time
	Expires                  *time.Time
	// Unverifiable: it does not verify under its pinned lock key (Error
	// says why); Summary is then not read from it.
	Unverifiable bool
	Error        string
	// Answerable: routed to the terminal (lox run may decide it).
	Answerable bool
	Summary    string
}

// Pending reads the hub's pending tickets as lox run does, oldest first.
func Pending(items []api.QueueItem, keys map[string]ed25519.PublicKey) []PendingTicket {
	out := make([]PendingTicket, 0, len(items))
	for _, it := range items {
		p := PendingTicket{Instance: clean(it.Instance), ID: clean(it.ID), Risk: clean(it.Risk), Created: it.Created, Expires: it.Expires,
			Answerable: local(it.Facades)}
		if tk, _, err := parseTicket(it, keys); err != nil {
			p.Unverifiable, p.Error, p.Summary = true, shortNote(err.Error()), unreadableSummary
		} else {
			p.Lock, p.Summary = clean(tk.Source.Lock), summary(tk)
		}
		out = append(out, p)
	}
	slices.SortStableFunc(out, func(a, b PendingTicket) int { return a.Created.Compare(b.Created) })
	return out
}

// withdrawLines is the w overlay.
func withdrawLines(v View, w, room int, st Style) []line {
	wv := v.Withdraw
	out := []line{{{" pending at the hub", sgrBold}, {" · " + strconv.Itoa(len(wv.Rows)) + " ticket" + plural(len(wv.Rows)) + " · oldest first", sgrDim}}}
	if wv.Confirm != "" {
		out = append(out, line{{"   " + wv.Confirm, st.asked()}})
	} else {
		out = append(out, line{{"   x", sgrBold}, {" withdraw  ", sgrDim}, {"X", sgrBold}, {" all of its lock  ", sgrDim},
			{"U", sgrBold}, {" its unverifiable  ", sgrDim}, {st.g("↑↓", "j/k"), sgrBold}, {" move  ", sgrDim}, {"Esc", sgrBold}, {" close", sgrDim}})
	}
	// Per lock: how many wait, how many lox run cannot verify.
	counts, bad := map[string]int{}, map[string]int{}
	var order []string
	for _, r := range wv.Rows {
		if counts[r.Instance] == 0 {
			order = append(order, r.Instance)
		}
		counts[r.Instance]++
		if r.Unreadable {
			bad[r.Instance]++
		}
	}
	if len(order) > 0 {
		l := line{{"  ", ""}}
		for _, in := range order {
			l = l.add(" "+in+" "+strconv.Itoa(counts[in]), sgrBold)
			if bad[in] > 0 {
				l = l.add(" ("+strconv.Itoa(bad[in])+" unverifiable)", st.errored())
			}
		}
		out = append(out, l)
	}
	if len(wv.Rows) == 0 {
		return append(out, line{{"   nothing pending", sgrDim}})
	}
	rows := make([]line, 0, len(wv.Rows))
	for i, r := range wv.Rows {
		mark, sgr := "   ", ""
		if i == wv.Sel {
			mark, sgr = " "+st.g("▶", ">")+" ", sgrBold
		}
		tagSGR := sgrDim
		switch r.Tag {
		case tagUnreadable:
			tagSGR = st.errored()
		case tagAsked:
			tagSGR = st.asked()
		}
		l := line{{mark, sgr}}.add(age(r.Age), sgr).pad(11, "").
			add(r.Instance, sgr).pad(11+16, st.ellipsis()).
			add(" "+r.Tag, tagSGR).pad(11+16+21, st.ellipsis()).
			add(" "+r.Summary, "")
		rows = append(rows, l)
	}
	// Keep the selection in the room left.
	n := max(room-len(out), 1)
	first := 0
	if wv.Sel >= n {
		first = wv.Sel - n + 1
	}
	return append(out, rows[first:min(len(rows), first+n)]...)
}
