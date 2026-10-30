package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// ErrAuditDown is a change refused because the audit log cannot take the
// records of the changes already committed: the hub fails closed.
var ErrAuditDown = errors.New("the audit log is not writable")

// audit stores rec in tx's outbox, timestamped now and signed with the
// hub key: it reaches the audit log only if tx commits (flushAudit).
func (h *Hub) audit(tx *store.Tx, rec audit.Record) error {
	rec.At = h.c.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return tx.QueueAudit(b, audit.SignOutbox(h.c.Key, b))
}

// auditReady is checked before every change: the records of earlier
// changes must be in the log first. So at most one committed change (the
// one whose own flush failed) waits in the outbox while the log is down,
// and no further change commits until it is up again.
func (h *Hub) auditReady(ctx context.Context) error {
	if err := h.FlushAudit(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditDown, err)
	}
	return nil
}

// flushAudit is FlushAudit after a commit. The change is committed and
// its record durable in the outbox whatever happens here: on an error,
// the record goes to the log at the next flush (the next change, which
// is refused until then, Sweep, which reports the error, or the hub's
// start).
func (h *Hub) flushAudit(ctx context.Context) {
	_ = h.FlushAudit(context.WithoutCancel(ctx))
}

// FlushAudit appends the outbox's records to the audit log, in commit
// order, dropping each once it is in the log. A record found as the
// log's last one was appended before a crash that left it in the outbox:
// it is dropped, not appended twice. A record not signed by the hub key
// was not written by the hub: it stops the flush (and so every change)
// for a human to look at, rather than be signed into the log.
func (h *Hub) FlushAudit(ctx context.Context) error {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	rows, err := h.c.Store.AuditOutbox(ctx)
	if err != nil {
		return fmt.Errorf("audit outbox: %w", err)
	}
	pub := h.c.Key.Public().(ed25519.PublicKey)
	for _, o := range rows {
		if !audit.VerifyOutbox(pub, o.Record, o.Sig) {
			return fmt.Errorf("audit outbox record %d is not signed by the hub key: the database was written by someone else", o.ID)
		}
		var rec audit.Record
		if err := json.Unmarshal(o.Record, &rec); err != nil {
			return fmt.Errorf("audit outbox record %d: %w", o.ID, err)
		}
		if !h.c.Audit.IsLast(rec) {
			if _, err := h.c.Audit.Append(rec); err != nil {
				return fmt.Errorf("audit log: %w", err)
			}
		}
		if err := h.c.Store.DropAudit(ctx, o.ID); err != nil {
			return fmt.Errorf("audit outbox: %w", err)
		}
	}
	return nil
}
