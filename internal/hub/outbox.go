package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// audit stores rec in tx's outbox, timestamped now: it reaches the audit
// log only if tx commits (flushAudit).
func (h *Hub) audit(tx *store.Tx, rec audit.Record) error {
	rec.At = h.c.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return tx.QueueAudit(b)
}

// flushAudit is FlushAudit after a commit. The change is committed and
// its record durable in the outbox whatever happens here: on an error,
// the record goes to the log at the next flush (the next change, Sweep,
// which reports the error, or the hub's start).
func (h *Hub) flushAudit(ctx context.Context) {
	_ = h.FlushAudit(context.WithoutCancel(ctx))
}

// FlushAudit appends the outbox's records to the audit log, in commit
// order, dropping each once it is in the log. A record found as the
// log's last one was appended before a crash that left it in the outbox:
// it is dropped, not appended twice.
func (h *Hub) FlushAudit(ctx context.Context) error {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	rows, err := h.c.Store.AuditOutbox(ctx)
	if err != nil {
		return fmt.Errorf("audit outbox: %w", err)
	}
	for _, o := range rows {
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
