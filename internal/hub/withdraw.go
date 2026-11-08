package hub

import (
	"context"
	"fmt"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Where a human withdraws a ticket: the reason names it.
const (
	ViaRun = "lox run"
	ViaCLI = "lox withdraw"
)

// WithdrawPrefix starts the reason of every withdrawal by a human: the
// lock tells it from a human's denial (lockkit ends the plan withdrawn).
const WithdrawPrefix = "withdrawn by "

// Withdrawal is the outcome of WithdrawByHuman.
type Withdrawal struct {
	// Reason is the audited reason, as the lock and its agent get it.
	Reason string
	// Told: the lock was sent a signed denial with Reason, so it ends its
	// plan and answers the agent. False when the hub cannot verify the
	// stored ticket (no decision can be signed for it): the lock's plan
	// ends with its TTL.
	Told bool
}

// WithdrawByHuman is a human at a local facade (lox run, lox withdraw)
// taking back a pending ticket its lock or agent left waiting: the ticket
// ends withdrawn, frees its instance's pending slot, and is audited with
// the human and the reason. Its lock gets a denial signed by the hub that
// names the withdrawal, so it ends the plan and its agent hears that the
// human withdrew it rather than waiting. A ticket the hub can no longer
// verify (its lock's key changed) is withdrawn all the same, without a
// decision, and audited as such.
func (h *Hub) WithdrawByHuman(ctx context.Context, ref store.Ref, a Asker, via string) (Withdrawal, error) {
	if err := a.check(); err != nil {
		return Withdrawal{}, err
	}
	if via != ViaRun && via != ViaCLI {
		return Withdrawal{}, fmt.Errorf("%w: a withdrawal is made in %q or %q", ErrBadRequest, ViaRun, ViaCLI)
	}
	who := a.ApproverDisplay
	if who == "" {
		who = a.ApproverID
	}
	var out Withdrawal
	if err := h.auditReady(ctx); err != nil {
		return out, err
	}
	err := h.c.Store.Tx(ctx, func(tx *store.Tx) error {
		tk, err := tx.Ticket(ref)
		if err != nil {
			return err
		}
		to, err := state.Next(tk.State, state.Withdraw)
		if err != nil {
			return err
		}
		now := h.c.Now()
		reason := WithdrawPrefix + who + " in " + via
		var raw []byte
		info, verr := h.verifyStored(tk)
		if verr == nil {
			info.Raw = tk.Raw
			raw, verr = h.c.Codec.SignDecision(h.c.Key, info, Verdict{Reason: reason, ApproverID: a.ApproverID,
				ApproverDisplay: a.ApproverDisplay, Facade: a.Facade}, now)
		}
		if verr != nil {
			raw = nil
			reason += " (the hub cannot verify the ticket: " + verr.Error() + "; its lock is not told)"
			if len(reason) > MaxReason {
				reason = reason[:MaxReason]
			}
		}
		if err := tx.SetState(ref, tk.State, to, now); err != nil {
			return err
		}
		rec := audit.Record{Event: string(state.Withdraw), Ticket: ref.ID, Instance: ref.Instance, Risk: tk.Risk, State: string(to),
			Approver: a.ApproverID, Facade: a.Facade, Reason: reason}
		if raw != nil {
			if _, err := tx.PutDecision(store.Decision{Ticket: ref.ID, Instance: tk.Instance, Raw: raw, At: now}); err != nil {
				return err
			}
			rec.Decision = hashBytes(raw)
		}
		out = Withdrawal{Reason: reason, Told: raw != nil}
		return h.audit(tx, rec)
	})
	if err != nil {
		return Withdrawal{}, err
	}
	h.flushAudit(ctx)
	if out.Told {
		h.notify(ref.Instance)
	}
	h.notify(queueKey)
	return out, nil
}

// verifyStored verifies a stored ticket under its lock's declared key.
func (h *Hub) verifyStored(tk store.Ticket) (Info, error) {
	key, ok := h.c.Locks[tk.Instance]
	if !ok {
		return Info{}, ErrLockRemoved
	}
	info, err := h.c.Codec.VerifyTicket(key, tk.Raw)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", ErrBadTicket, err)
	}
	return info, nil
}
