package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
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
func build(t *testing.T, n int) (string, ed25519.PublicKey) { return buildCrash(t, n, false) }

// lastHubKey is the hub key of the last build.
var lastHubKey ed25519.PrivateKey

// buildCrash is build; with crash, the hub stops after the last
// decision's commit, before its audit record reaches the log.
func buildCrash(t *testing.T, n int, crash bool) (string, ed25519.PublicKey) {
	dir := t.TempDir()
	lpub, lpriv, _ := ed25519.GenerateKey(rand.Reader)
	hpub, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	al.SetKey(hpriv)
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
		if crash && i == n-1 {
			al.Close()
		}
		if _, err := h.Decide(context.Background(), store.Ref{Instance: "crm", ID: tk.ID}, hub.Verdict{Approved: i%2 == 0, ApproverID: "host:uid:1", Facade: "tty"}); err != nil {
			t.Fatal(err)
		}
	}
	al.Close()
	st.Close()
	lastHubKey = hpriv
	return dir, hpub
}

func TestHealthy(t *testing.T) {
	dir, pub := build(t, 3)
	r, err := Hub(context.Background(), dir, []ed25519.PublicKey{pub})
	if err != nil || !r.OK() || r.Decisions != 3 || r.Records != 6 {
		t.Fatalf("report %+v, %v", r, err)
	}
}

func TestWrongHubKey(t *testing.T) {
	dir, _ := build(t, 1)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	r, _ := Hub(context.Background(), dir, []ed25519.PublicKey{other})
	if r.OK() || !strings.Contains(r.Problems[0], "signed by the hub key") {
		t.Errorf("report %+v", r)
	}
}

func TestCutTail(t *testing.T) {
	dir, pub := build(t, 2)
	p := filepath.Join(dir, "tickets.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:len(lines)-1], "")), 0o600) // drop the last decision
	r, _ := Hub(context.Background(), dir, []ed25519.PublicKey{pub})
	if r.OK() || !strings.Contains(strings.Join(r.Problems, ";"), "not in the audit log") {
		t.Errorf("cut tail not seen: %+v", r)
	}
}

func TestEditedLog(t *testing.T) {
	dir, pub := build(t, 1)
	p := filepath.Join(dir, "tickets.jsonl")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), `"approver":"host:uid:1"`, `"approver":"host:uid:2"`, 1)), 0o600)
	r, _ := Hub(context.Background(), dir, []ed25519.PublicKey{pub})
	if r.OK() || !strings.Contains(r.Problems[0], "audit chain") {
		t.Errorf("edit not seen: %+v", r)
	}
}

func TestUnsignedLogRefused(t *testing.T) {
	dir, pub := build(t, 1)
	p := filepath.Join(dir, "tickets.jsonl")
	b, _ := os.ReadFile(p)
	// Strip the signatures: the chain still hashes, but nothing vouches for it.
	var out []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if i := strings.Index(l, `,"sig":"`); i >= 0 {
			l = l[:i] + "}\n"
		}
		out = append(out, l)
	}
	os.WriteFile(p, []byte(strings.Join(out, "")), 0o600)
	r, _ := Hub(context.Background(), dir, []ed25519.PublicKey{pub})
	if r.OK() || !strings.Contains(r.Problems[0], "not signed") {
		t.Errorf("unsigned log accepted: %+v", r)
	}
}

func TestMissingDatabaseNotCreated(t *testing.T) {
	dir, pub := build(t, 1)
	os.Remove(filepath.Join(dir, "hub.db"))
	os.Remove(filepath.Join(dir, "hub.db-wal"))
	os.Remove(filepath.Join(dir, "hub.db-shm"))
	if _, err := Hub(context.Background(), dir, []ed25519.PublicKey{pub}); err == nil {
		t.Error("missing database: no error")
	}
	if _, err := os.Stat(filepath.Join(dir, "hub.db")); err == nil {
		t.Error("verify created a database")
	}
}

func TestOutboxedDecision(t *testing.T) {
	dir, pub := buildCrash(t, 2, true)
	r, err := Hub(context.Background(), dir, []ed25519.PublicKey{pub})
	if err != nil || !r.OK() || r.Decisions != 2 || r.Records != 3 || r.Outboxed != 1 {
		t.Fatalf("report %+v, %v", r, err)
	}
	// An outboxed record the hub did not sign does not vouch for anything.
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := st.AuditOutbox(context.Background())
	if err != nil || len(out) != 1 {
		t.Fatalf("outbox %v %v", out, err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := []byte(strings.Replace(string(out[0].Record), `"approver":"host:uid:1"`, `"approver":"host:uid:2"`, 1))
	if err := st.Tx(context.Background(), func(tx *store.Tx) error {
		return tx.QueueAudit(forged, func(id int64) string { return audit.SignOutbox(other, id, forged) })
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.DropAudit(context.Background(), out[0].ID); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if r, _ := Hub(context.Background(), dir, []ed25519.PublicKey{pub}); r.OK() || !strings.Contains(strings.Join(r.Problems, ";"), "not signed by the hub key") {
		t.Errorf("forged outbox record accepted: %+v", r)
	}
}

// verify reads the database before the log: a row the hub logged and
// dropped meanwhile is in the snapshot below the log's last outbox id.
// Logged with that id and content, it is no replay.
func TestOutboxRowLoggedSinceSnapshot(t *testing.T) {
	dir, pub := build(t, 2)
	b, _ := os.ReadFile(filepath.Join(dir, "tickets.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var rec audit.Record
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil || rec.Outbox == 0 {
		t.Fatalf("%+v %v", rec, err)
	}
	id := rec.Outbox
	rec.Seq, rec.Prev, rec.Hash, rec.Sig, rec.Outbox = 0, "", "", "", 0
	raw, _ := json.Marshal(rec)
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	put := func(id int64, raw []byte) {
		t.Helper()
		db.Exec(`DELETE FROM audit_outbox`)
		if _, err := db.Exec(`INSERT INTO audit_outbox(id, record, sig) VALUES (?, ?, ?)`, id, raw, audit.SignOutbox(lastHubKey, id, raw)); err != nil {
			t.Fatal(err)
		}
	}
	put(id, raw)
	if r, err := Hub(context.Background(), dir, []ed25519.PublicKey{pub}); err != nil || !r.OK() || r.Outboxed != 0 {
		t.Fatalf("logged row: %+v %v", r, err)
	}
	// Under the id of another logged record: a replay.
	put(id+1, raw)
	if r, _ := Hub(context.Background(), dir, []ed25519.PublicKey{pub}); r.OK() || !strings.Contains(strings.Join(r.Problems, ";"), "replayed") {
		t.Errorf("replay accepted: %+v", r)
	}
	db.Close()
}

// A last line being appended is not read yet.
func TestUnterminatedTailIgnored(t *testing.T) {
	dir, pub := build(t, 1)
	f, _ := os.OpenFile(filepath.Join(dir, "tickets.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"seq":3,"at`)
	f.Close()
	if r, err := Hub(context.Background(), dir, []ed25519.PublicKey{pub}); err != nil || !r.OK() || r.Records != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}

// After a hub key rotation, the log and the decisions are checked with
// every key, each decision with the key of the record vouching for it.
func TestRotatedHubKey(t *testing.T) {
	dir, pub0 := build(t, 2)
	k0 := lastHubKey
	pub1, k1, _ := ed25519.GenerateKey(rand.Reader)
	p := filepath.Join(dir, "tickets.jsonl")
	al, err := audit.OpenSigned(p, k0)
	if err != nil {
		t.Fatal(err)
	}
	al.Rotate(k1)
	al.Close()
	before, _ := os.ReadFile(p)
	// One more decision, by the hub on its new key.
	lpub, lpriv, _ := ed25519.GenerateKey(rand.Reader)
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	al, err = audit.OpenSigned(p, k1, pub0)
	if err != nil {
		t.Fatal(err)
	}
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: k1, Locks: map[string]ed25519.PublicKey{"web": lpub}})
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "web"}, ticket.RiskRead,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester, tk.Screen = "ws", ticket.Requester{Agent: "a", Session: "s"}, ticket.Screen{Header: "h"}
	tk.Sign(lpriv)
	raw, _ := tk.Marshal()
	if _, _, err := h.Push(context.Background(), "web", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Decide(context.Background(), store.Ref{Instance: "web", ID: tk.ID}, hub.Verdict{Approved: true, ApproverID: "host:uid:1", Facade: "tty"}); err != nil {
		t.Fatal(err)
	}
	al.Close()
	st.Close()
	both := []ed25519.PublicKey{pub0, pub1}
	if r, err := Hub(context.Background(), dir, both); err != nil || !r.OK() || r.Decisions != 3 || r.Records != 7 {
		t.Fatalf("rotated: %+v %v", r, err)
	}
	for name, ks := range map[string][]ed25519.PublicKey{"current only": {pub1}, "old only": {pub0}} {
		if r, _ := Hub(context.Background(), dir, ks); r.OK() {
			t.Errorf("%s accepted", name)
		}
	}
	// Cut back to before the rotation: it no longer ends on the current
	// key.
	after, _ := os.ReadFile(p)
	os.WriteFile(p, before[:bytes.LastIndexByte(before[:len(before)-1], '\n')+1], 0o600)
	if r, _ := Hub(context.Background(), dir, both); r.OK() || !strings.Contains(strings.Join(r.Problems, ";"), "ends signed by hub key 1 of 2") {
		t.Errorf("cut before the rotation: %+v", r)
	}
	os.WriteFile(p, after, 0o600)
	// The lock-side check reads decisions signed by either key.
	reps, err := Locks(context.Background(), dir, both, nil, nil)
	if err != nil || len(reps) != 0 {
		t.Errorf("Locks: %v %v", reps, err)
	}
}
