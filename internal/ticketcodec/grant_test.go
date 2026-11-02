package ticketcodec_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// TestLockkitGrantEndToEnd: a production grant (lockhub#99) is queued
// like any ticket, refused on a chat facade even where the hub runs one,
// approved in the terminal with the instance name typed, and its signed
// decision binds the scope's hash at the lock. The audit marks it.
func TestLockkitGrantEndToEnd(t *testing.T) {
	// No ticket.RiskGrant: the compat job builds on the lockkit before it.
	grant := ticket.Risk(route.Grant)
	if !grant.Valid() {
		t.Skip("lockkit before v0.12.0 has no grant (compat build)")
	}
	lockPub, lockPriv, _ := ed25519.GenerateKey(rand.Reader)
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	defer st.Close()
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	defer al.Close()
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubPriv,
		Locks: map[string]ed25519.PublicKey{"crm-prod": lockPub}, Routes: route.Rules{Enabled: route.Facades()}})

	scope := "sha256:" + strings.Repeat("3", 64)
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm-prod"}, grant,
		scope, "sha256:"+strings.Repeat("2", 64), time.Now(), grant.TTL())
	tk.Workspace, tk.Requester = "~/Documents", ticket.Requester{Agent: "dev-1", Session: "s1"}
	tk.Flags.Production, tk.Flags.Retype = true, "r"
	tk.Screen = ticket.Screen{Header: "grant on crm-prod", Body: []string{"tables: orders, customers", "duration: 1h", "budget: 50 statements, 10000 rows"}}
	if err := tk.Sign(lockPriv); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	info, created, err := h.Push(context.Background(), "crm-prod", raw)
	if err != nil || !created || info.Risk != route.Grant || !info.NeverAuto {
		t.Fatalf("push: %v %v %+v", created, err, info)
	}

	ref := store.Ref{Instance: "crm-prod", ID: tk.ID}
	for _, f := range []string{route.Slack, route.Telegram} {
		v := hub.Verdict{Approved: true, ApproverID: f + ":U1", Facade: f, Retype: "crm-prod"}
		if _, err := h.Decide(context.Background(), ref, v); !errors.Is(err, hub.ErrNotRouted) {
			t.Fatalf("grant decided on %s: %v", f, err)
		}
	}
	tty := hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: route.TTY}
	if _, err := h.Decide(context.Background(), ref, tty); !errors.Is(err, hub.ErrRetype) {
		t.Fatalf("production grant approved without the retype: %v", err)
	}
	tty.Retype = "crm-prod"
	if _, err := h.Decide(context.Background(), ref, tty); err != nil {
		t.Fatal(err)
	}

	ds, err := st.Decisions(context.Background(), "crm-prod", 0, 10)
	if err != nil || len(ds) != 1 {
		t.Fatalf("decisions: %d %v", len(ds), err)
	}
	d, err := ticket.VerifyDecision(hubPub, ds[0].Raw)
	if err != nil {
		t.Fatalf("lockkit refuses the hub's grant decision: %v", err)
	}
	if err := d.Match(tk); err != nil || d.PlanHash != scope {
		t.Fatalf("decision does not bind the scope: %v %s", err, d.PlanHash)
	}
	if err := d.Usable(tk, time.Now(), 0); err != nil {
		t.Errorf("decision not usable: %v", err)
	}

	log, err := os.ReadFile(filepath.Join(dir, "tickets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	events := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		var r audit.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		if r.Ticket != tk.ID || r.Risk != route.Grant {
			t.Errorf("audit record without risk grant: %s", l)
		}
		events[r.Event] = true
	}
	if !events["push"] || !events["approve"] {
		t.Errorf("audit lacks the push or the approval:\n%s", log)
	}
}
