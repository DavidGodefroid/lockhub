package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// A change whose transaction rolls back leaves no audit record.
func TestRolledBackChangeNotAudited(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ap := filepath.Join(dir, "tickets.jsonl")
	al, err := audit.Open(ap)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	h := New(Config{Store: st, Audit: al, Key: key})
	ctx := context.Background()
	boom := errors.New("commit refused")
	err = st.Tx(ctx, func(tx *store.Tx) error {
		if err := h.audit(tx, audit.Record{Event: "approve", Ticket: "T1", Instance: "a", State: "approved"}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := h.FlushAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(ap); len(b) != 0 {
		t.Errorf("rolled-back change audited:\n%s", b)
	}
	if out, _ := st.AuditOutbox(ctx); len(out) != 0 {
		t.Errorf("outbox %v", out)
	}
}

// A record the log would refuse is refused while the change can roll back.
func TestOversizedAuditRecordRefused(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	defer st.Close()
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	defer al.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	h := New(Config{Store: st, Audit: al, Key: key})
	err := st.Tx(context.Background(), func(tx *store.Tx) error {
		return h.audit(tx, audit.Record{Event: "deny", Ticket: "T1", Instance: "a", Reason: strings.Repeat("x", audit.MaxLine)})
	})
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("%v", err)
	}
	if out, _ := st.AuditOutbox(context.Background()); len(out) != 0 {
		t.Errorf("outbox %d", len(out))
	}
}
