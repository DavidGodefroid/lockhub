package hub_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

func records(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, err := audit.Verify(f)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The hub stops between a decision's commit and its audit record: the
// record waits in the outbox, and the next start logs it, once.
func TestCommittedDecisionAuditedAfterCrash(t *testing.T) {
	a := hubtest.NewLock("crm-prod")
	e := hubtest.New(t, 0, a)
	if _, _, err := e.Hub.Push(ctx, "crm-prod", a.Ticket("T1", "write", e.Clock.T, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := records(t, e.Audit); n != 1 {
		t.Fatalf("%d records after push", n)
	}
	// The log can no longer be written (a crash right after the commit).
	e.Log.Close()
	if _, err := e.Hub.Decide(ctx, store.Ref{Instance: "crm-prod", ID: "T1"}, approve("T1")); err != nil {
		t.Fatalf("committed decision reported as failed: %v", err)
	}
	if n := records(t, e.Audit); n != 1 {
		t.Fatalf("%d records: the decision reached the log", n)
	}
	if out, err := e.Store.AuditOutbox(ctx); err != nil || len(out) != 1 {
		t.Fatalf("outbox before restart: %v %v", out, err)
	}

	// Restart: a new log and hub on the same data.
	al, err := audit.OpenSigned(e.Audit, e.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	h := hub.New(hub.Config{Store: e.Store, Audit: al, Codec: hubtest.Codec{}, Key: e.Key, Locks: map[string]ed25519.PublicKey{"crm-prod": a.Pub}, Now: e.Clock.Now})
	if err := h.FlushAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if n := records(t, e.Audit); n != 2 {
		t.Fatalf("%d records after restart, want push and approve", n)
	}
	if out, err := e.Store.AuditOutbox(ctx); err != nil || len(out) != 0 {
		t.Fatalf("outbox after restart: %v %v", out, err)
	}
	// Flushing again appends nothing.
	if err := h.FlushAudit(ctx); err != nil || records(t, e.Audit) != 2 {
		t.Fatalf("second flush: %v", err)
	}
}

// The hub stops after appending a record and before dropping it from the
// outbox: the next flush drops it without logging it twice.
func TestOutboxedRecordNotLoggedTwice(t *testing.T) {
	a := hubtest.NewLock("crm-prod")
	e := hubtest.New(t, 0, a)
	e.Log.Close()
	if _, _, err := e.Hub.Push(ctx, "crm-prod", a.Ticket("T1", "write", e.Clock.T, time.Hour)); err != nil {
		t.Fatal(err)
	}
	out, err := e.Store.AuditOutbox(ctx)
	if err != nil || len(out) != 1 {
		t.Fatalf("outbox %v %v", out, err)
	}
	al, err := audit.OpenSigned(e.Audit, e.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	var rec audit.Record
	if err := json.Unmarshal(out[0].Record, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := al.Append(rec); err != nil { // appended, then the crash
		t.Fatal(err)
	}
	h := hub.New(hub.Config{Store: e.Store, Audit: al, Codec: hubtest.Codec{}, Key: e.Key, Locks: map[string]ed25519.PublicKey{"crm-prod": a.Pub}, Now: e.Clock.Now})
	if err := h.FlushAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if n := records(t, e.Audit); n != 1 {
		t.Fatalf("%d records, want the push once", n)
	}
	if out, _ := e.Store.AuditOutbox(ctx); len(out) != 0 {
		t.Errorf("outbox not drained: %v", out)
	}
}

// Sweep logs what a failed flush left behind, and says why it cannot.
func TestSweepFlushesOutbox(t *testing.T) {
	a := hubtest.NewLock("crm-prod")
	e := hubtest.New(t, 0, a)
	e.Log.Close()
	if _, _, err := e.Hub.Push(ctx, "crm-prod", a.Ticket("T1", "write", e.Clock.T, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := e.Hub.Sweep(ctx); err == nil {
		t.Error("sweep silent about an unwritable audit log")
	}
}
