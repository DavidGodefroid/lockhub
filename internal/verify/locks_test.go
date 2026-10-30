package verify

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lkaudit "github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/store"
)

// lockLog writes the lock-side log of instance crm for the hub at dir:
// a pending and an approved/denied record per hub decision, as lockkit
// consoles write them. edit changes each decision record first.
func lockLog(t *testing.T, dir string, pub ed25519.PublicKey, edit func(*lkaudit.Base)) string {
	t.Helper()
	st, err := store.OpenReadOnly(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ds, err := st.AllDecisions(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	l, err := lkaudit.Open(kit.Product{Name: "locksql"}, state)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		dec, err := ticket.VerifyDecision(pub, d.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Append(lkaudit.Base{Event: lkaudit.EventPending, Ticket: d.Ticket}); err != nil {
			t.Fatal(err)
		}
		ev := lkaudit.EventDenied
		if dec.Decision == ticket.Approved {
			ev = lkaudit.EventApproved
		}
		rec := lkaudit.Base{Event: ev, Ticket: d.Ticket, Approver: &dec.Approver, Facade: dec.Facade, HubSig: dec.Sig}
		if edit != nil {
			edit(&rec)
		}
		if err := l.Append(rec); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(state, "locksql")
}

func TestLockLogsMatchTheHub(t *testing.T) {
	dir, pub := build(t, 2)
	path := lockLog(t, dir, pub, nil)
	reps, err := Locks(context.Background(), dir, pub, []LockLog{{"crm", path}}, nil)
	if err != nil || len(reps) != 1 {
		t.Fatal(reps, err)
	}
	r := reps[0]
	if !r.OK() || r.Records != 4 || r.HubDecisions != 2 || r.Anchored || r.Anchor.Line != 4 {
		t.Fatalf("%+v", r)
	}
	// Anchored at that line: a grown log verifies, a cut one does not.
	anchors := map[string]lkaudit.Anchor{"crm": r.Anchor}
	if reps, _ := Locks(context.Background(), dir, pub, []LockLog{{"crm", filepath.Join(path, "audit.log")}}, anchors); !reps[0].OK() || !reps[0].Anchored {
		t.Fatalf("anchored: %+v", reps[0])
	}
	p := filepath.Join(path, "audit.log")
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:3], "")), 0o600)
	if reps, _ := Locks(context.Background(), dir, pub, []LockLog{{"crm", p}}, anchors); reps[0].OK() {
		t.Error("cut tail accepted against its anchor")
	}
	if reps, _ := Locks(context.Background(), dir, pub, []LockLog{{"crm", p}}, nil); !reps[0].OK() {
		t.Errorf("the cut log, unanchored, should still verify (only an anchor sees it): %+v", reps[0])
	}
}

func TestLockLogClaimsADecisionTheHubDidNotMake(t *testing.T) {
	for name, edit := range map[string]func(*lkaudit.Base){
		"other signature": func(b *lkaudit.Base) { b.HubSig = "AAAA" + b.HubSig[4:] },
		"other approver":  func(b *lkaudit.Base) { b.Approver = &ticket.Approver{ID: "slack:U99"} },
		"other facade":    func(b *lkaudit.Base) { b.Facade = "slack" },
		"other ticket":    func(b *lkaudit.Base) { b.Ticket = "01NOTAHUBTICKET" },
	} {
		t.Run(name, func(t *testing.T) {
			dir, pub := build(t, 1)
			reps, err := Locks(context.Background(), dir, pub, []LockLog{{"crm", lockLog(t, dir, pub, edit)}}, nil)
			if err != nil || reps[0].OK() {
				t.Fatalf("accepted: %+v %v", reps, err)
			}
		})
	}
}

func TestLockLogEditedChain(t *testing.T) {
	dir, pub := build(t, 1)
	path := lockLog(t, dir, pub, nil)
	p := filepath.Join(path, "audit.log")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), `"event":"pending"`, `"event":"refused"`, 1)), 0o600)
	reps, err := Locks(context.Background(), dir, pub, []LockLog{{"crm", p}}, nil)
	if err != nil || reps[0].OK() || !strings.Contains(reps[0].Problems[0], "audit chain") {
		t.Fatalf("%+v %v", reps, err)
	}
}

func TestAnchorsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "anchors.json")
	if a, err := LoadAnchors(p); err != nil || len(a) != 0 {
		t.Fatal(a, err)
	}
	want := map[string]lkaudit.Anchor{"crm": {Line: 3, Hash: "sha256:ab"}, "none": {}}
	if err := SaveAnchors(p, want); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	got, err := LoadAnchors(p)
	if err != nil || len(got) != 1 || got["crm"] != want["crm"] {
		t.Fatalf("%v %v", got, err)
	}
	os.WriteFile(p, []byte(`{"crm":{"line":0,"hash":""}}`), 0o600)
	if _, err := LoadAnchors(p); err == nil {
		t.Error("empty anchor accepted")
	}
}
