package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lkaudit "github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// hubWithDecision is a hub data dir holding one approved ticket of crm,
// its key file, and crm's lock-side log of it.
func hubWithDecision(t *testing.T) (data, keyFile, lockLog string) {
	t.Helper()
	data = t.TempDir()
	lpub, lpriv, _ := ed25519.GenerateKey(rand.Reader)
	hpub, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	st, err := store.Open(filepath.Join(data, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(data, "tickets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	al.SetKey(hpriv)
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hpriv, Locks: map[string]ed25519.PublicKey{"crm": lpub}})
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, ticket.RiskRead,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester, tk.Screen = "ws", ticket.Requester{Agent: "a", Session: "s"}, ticket.Screen{Header: "h"}
	tk.Sign(lpriv)
	raw, _ := tk.Marshal()
	if _, _, err := h.Push(context.Background(), "crm", raw); err != nil {
		t.Fatal(err)
	}
	draw, err := h.Decide(context.Background(), store.Ref{Instance: "crm", ID: tk.ID}, hub.Verdict{Approved: true, ApproverID: "host:uid:1", Facade: "tty"})
	if err != nil {
		t.Fatal(err)
	}
	al.Close()
	st.Close()
	dec, err := ticket.VerifyDecision(hpub, draw)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(t.TempDir(), "hub.pub")
	os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(hpub)+"\n"), 0o644)
	state := t.TempDir()
	l, _ := lkaudit.Open(kit.Product{Name: "locksql"}, state)
	l.Append(lkaudit.Base{Event: lkaudit.EventPending, Ticket: tk.ID})
	l.Append(lkaudit.Base{Event: lkaudit.EventApproved, Ticket: tk.ID, Approver: &dec.Approver, Facade: dec.Facade, HubSig: dec.Sig})
	return data, keyFile, filepath.Join(state, "locksql", "audit.log")
}

func TestAuditVerifyLocks(t *testing.T) {
	data, keyFile, lockLog := hubWithDecision(t)
	anchors := filepath.Join(t.TempDir(), "anchors.json")
	verifyRun := func(extra ...string) (int, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"audit", "verify", "--data", data, "--hub-key-file", keyFile}, extra...), devNull(t), &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := verifyRun("--lock", "crm="+lockLog); code != 0 || !strings.Contains(out, "OK: crm: 2 audit records chained (0 before the chain), 1 hub decisions") || !strings.Contains(out, "not anchored") {
		t.Fatalf("%d %s", code, out)
	}
	if code, out := verifyRun("--lock", "crm="+lockLog, "--anchors", anchors); code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	if code, out := verifyRun("--lock", "crm="+lockLog, "--anchors", anchors); code != 0 || !strings.Contains(out, "anchored") || strings.Contains(out, "not anchored") {
		t.Fatalf("second run: %d %s", code, out)
	}
	// Cut the last record: the anchor kept since sees it, and stays.
	b, _ := os.ReadFile(lockLog)
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	os.WriteFile(lockLog, []byte(lines[0]), 0o600)
	if code, out := verifyRun("--lock", "crm="+lockLog, "--anchors", anchors); code != 1 || !strings.Contains(out, "FAIL crm") {
		t.Fatalf("cut log: %d %s", code, out)
	}
	if code, _ := verifyRun("--lock", "crm="+lockLog, "--anchors", anchors); code != 1 {
		t.Error("a failed run moved the anchor back")
	}
	for _, bad := range [][]string{{"--anchors", anchors}, {"--lock", "crm"}, {"--lock", "../x=y"}, {"--lock", "crm=a", "--lock", "crm=b"}} {
		if code, out := verifyRun(bad...); code != 2 {
			t.Errorf("%q: %d %s", bad, code, out)
		}
	}
}
