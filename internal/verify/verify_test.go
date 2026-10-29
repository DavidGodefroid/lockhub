package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// build makes a hub data dir with n decided tickets.
func build(t *testing.T, n int) (string, ed25519.PublicKey) {
	dir := t.TempDir()
	lpub, lpriv, _ := ed25519.GenerateKey(rand.Reader)
	hpub, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hpriv, Locks: map[string]ed25519.PublicKey{"crm": lpub}})
	for i := 0; i < n; i++ {
		tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, ticket.RiskRead,
			"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
		tk.Workspace, tk.Requester, tk.Screen = "ws", ticket.Requester{Agent: "a", Session: "s"}, ticket.Screen{Header: "h"}
		tk.Sign(lpriv)
		raw, _ := tk.Marshal()
		if _, _, err := h.Push(context.Background(), "crm", raw); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Decide(context.Background(), store.Ref{Instance: "crm", ID: tk.ID}, hub.Verdict{Approved: i%2 == 0, ApproverID: "host:uid:1", Facade: "tty"}); err != nil {
			t.Fatal(err)
		}
	}
	al.Close()
	st.Close()
	return dir, hpub
}

func TestHealthy(t *testing.T) {
	dir, pub := build(t, 3)
	r, err := Hub(context.Background(), dir, pub)
	if err != nil || !r.OK() || r.Decisions != 3 || r.Records != 6 {
		t.Fatalf("report %+v, %v", r, err)
	}
}

func TestWrongHubKey(t *testing.T) {
	dir, _ := build(t, 1)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	r, _ := Hub(context.Background(), dir, other)
	if r.OK() || !strings.Contains(r.Problems[0], "signature") {
		t.Errorf("report %+v", r)
	}
}

func TestCutTail(t *testing.T) {
	dir, pub := build(t, 2)
	p := filepath.Join(dir, "tickets.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:len(lines)-1], "")), 0o600) // drop the last decision
	r, _ := Hub(context.Background(), dir, pub)
	if r.OK() || !strings.Contains(strings.Join(r.Problems, ";"), "not in the audit log") {
		t.Errorf("cut tail not seen: %+v", r)
	}
}

func TestEditedLog(t *testing.T) {
	dir, pub := build(t, 1)
	p := filepath.Join(dir, "tickets.jsonl")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), `"approver":"host:uid:1"`, `"approver":"host:uid:2"`, 1)), 0o600)
	r, _ := Hub(context.Background(), dir, pub)
	if r.OK() || !strings.Contains(r.Problems[0], "audit chain") {
		t.Errorf("edit not seen: %+v", r)
	}
}
