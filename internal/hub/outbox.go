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
	// The log refuses a line of MaxLine: refuse the change now, while it
	// can still roll back (room left for seq, prev, hash, sig and outbox).
	if len(b) > audit.MaxLine-1024 {
		return fmt.Errorf("%w: audit record of %d bytes", ErrBadRequest, len(b))
	}
	return tx.QueueAudit(b, func(id int64) string { return audit.SignOutbox(h.c.Key, id, b) })
}

// auditReady is checked before every change: the records of earlier
// changes must be in the log first. So while the log is down, only the
// changes already in flight when it failed commit (their records wait,
// durable and signed, in the outbox); no change starting after commits
// until it is up again.
func (h *Hub) auditReady(ctx context.Context) error {
	// Not the request's context: a client leaving is not the log down.
	if err := h.FlushAudit(context.WithoutCancel(ctx)); err != nil {
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
// order, dropping each once it is in the log. Each logged record carries
// its outbox id, and ids only grow along the log: a row whose id is the
// log's last was logged before a crash that left it in the outbox, and is
// dropped; a row below it is a replay. A replay, or a row not signed by
// the hub key for its id, was not written by the hub: it stops the flush
// (and so every change) for a human to look at, rather than be signed
// into the log.
func (h *Hub) FlushAudit(ctx context.Context) error {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	rows, err := h.c.Store.AuditOutbox(ctx)
	if err != nil {
		return fmt.Errorf("audit outbox: %w", err)
	}
	pub := h.c.Key.Public().(ed25519.PublicKey)
	for _, o := range rows {
		if !audit.VerifyOutbox(pub, o.ID, o.Record, o.Sig) {
			return fmt.Errorf("audit outbox record %d is not signed by the hub key: the database was written by someone else", o.ID)
		}
		var rec audit.Record
		if err := json.Unmarshal(o.Record, &rec); err != nil {
			return fmt.Errorf("audit outbox record %d: %w", o.ID, err)
		}
		switch last := h.c.Audit.LastOutbox(); {
		case o.ID < last:
			return fmt.Errorf("audit outbox record %d replayed: the log is at outbox record %d", o.ID, last)
		case o.ID == last:
			// Logged before a crash left the row: the same record, or a
			// row of another database (a restored backup).
			if !h.c.Audit.IsLastOutbox(rec) {
				return fmt.Errorf("audit outbox record %d differs from the record logged for it", o.ID)
			}
		case o.ID > last:
			rec.Outbox = o.ID
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
