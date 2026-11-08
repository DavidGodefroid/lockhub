package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// ticketsWorld is a hub with locks shop and crm on a facade socket, and
// a facade keys directory whose pinned key for crm is not crm's: lox
// cannot verify crm's tickets (as with #147), while the hub can.
type ticketsWorld struct {
	h          *hub.Hub
	st         *store.Store
	shop, crm  ed25519.PrivateKey
	sock, keys string
	audit      string
	n          int
}

func newTicketsWorld(t *testing.T) *ticketsWorld {
	t.Helper()
	dir, err := os.MkdirTemp("", "lxt") // a short path: a unix socket's is bounded
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	shopPub, shop, _ := ed25519.GenerateKey(rand.Reader)
	crmPub, crm, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ap := filepath.Join(dir, "tickets.jsonl")
	al, _ := audit.Open(ap)
	t.Cleanup(func() { al.Close() })
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hk,
		Locks: map[string]ed25519.PublicKey{"shop": shopPub, "crm": crmPub}})
	sock := filepath.Join(dir, "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: api.FacadeHandler(h), ConnContext: peer.ConnContext}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	keys := filepath.Join(dir, "keys")
	os.MkdirAll(keys, 0o700)
	b64 := base64.StdEncoding.EncodeToString
	locks := `{"locks":{"shop":{"public_key":"` + b64(shopPub) + `"},"crm":{"public_key":"` + b64(wrong) + `"}}}`
	if err := os.WriteFile(filepath.Join(keys, family.LockKeysFile), []byte(locks), 0o600); err != nil {
		t.Fatal(err)
	}
	return &ticketsWorld{h: h, st: st, shop: shop, crm: crm, sock: sock, keys: keys, audit: ap}
}

func (w *ticketsWorld) push(t *testing.T, instance, body string) string {
	t.Helper()
	w.n++
	k := w.shop
	if instance == "crm" {
		k = w.crm
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: instance}, ticket.RiskRead,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now().Add(-time.Hour).Add(time.Duration(w.n)*time.Second), 0)
	tk.Requester = ticket.Requester{Agent: "dev-1"}
	tk.Screen = ticket.Screen{Header: "query on " + instance, Body: []string{body}, Warnings: []string{}}
	if err := tk.Sign(k); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	if _, _, err := w.h.Push(context.Background(), instance, raw); err != nil {
		t.Fatal(err)
	}
	return tk.ID
}

func (w *ticketsWorld) lox(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args = append(args, "--socket", w.sock, "--facade-keys", w.keys)
	code := run(args, nil, &out, &errb)
	return code, out.String(), errb.String()
}

func (w *ticketsWorld) state(t *testing.T, instance, id string) state.State {
	t.Helper()
	var s state.State
	w.st.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: instance, ID: id})
		s = tk.State
		return err
	})
	return s
}

// lox tickets lists the hub's pending tickets with their age, the ones
// lox cannot verify flagged; lox withdraw takes them back, by id or all
// of a lock, without lox run: each ends withdrawn and audited with the
// human and lox withdraw.
func TestTicketsAndWithdraw(t *testing.T) {
	w := newTicketsWorld(t)
	s1 := w.push(t, "shop", "SELECT id FROM orders WHERE id < 2")
	s2 := w.push(t, "shop", "SELECT 2")
	var stuck []string
	for i := 0; i < 3; i++ {
		stuck = append(stuck, w.push(t, "crm", "SELECT 3"))
	}

	code, out, errs := w.lox(t, "tickets")
	if code != 0 || strings.Count(out, "\n") != 6 || !strings.Contains(out, "shop/"+s1) || !strings.Contains(out, "SELECT id FROM orders WHERE id < 2") ||
		strings.Count(out, "unverifiable") != 3 || !strings.Contains(out, "59m ") || !strings.Contains(out, "5 pending") {
		t.Fatalf("lox tickets = %d\n%s%s", code, out, errs)
	}
	if code, out, _ := w.lox(t, "tickets", "--error"); code != 0 || strings.Count(out, "crm/") != 3 || strings.Contains(out, "shop/") {
		t.Errorf("lox tickets --error = %d\n%s", code, out)
	}
	if code, out, _ := w.lox(t, "tickets", "--lock", "shop"); code != 0 || strings.Count(out, "shop/") != 2 || strings.Contains(out, "crm/") {
		t.Errorf("lox tickets --lock shop = %d\n%s", code, out)
	}

	code, out, errs = w.lox(t, "withdraw", "--lock", "crm", "--all-pending")
	if code != 0 || !strings.Contains(out, "3 of 3 withdrawn") {
		t.Fatalf("lox withdraw --lock crm --all-pending = %d\n%s%s", code, out, errs)
	}
	for _, id := range stuck {
		if s := w.state(t, "crm", id); s != state.Withdrawn {
			t.Errorf("crm/%s is %s", id, s)
		}
	}
	code, out, errs = w.lox(t, "withdraw", "shop/"+s2)
	if code != 0 || !strings.Contains(out, "withdrawn shop/"+s2+" (its lock is told)") {
		t.Fatalf("lox withdraw shop/ID = %d\n%s%s", code, out, errs)
	}
	if code, _, errs := w.lox(t, "withdraw", "shop/"+s2); code != 1 || errs == "" {
		t.Errorf("withdrawn twice = %d %s", code, errs)
	}
	if code, out, _ := w.lox(t, "tickets"); code != 0 || strings.Count(out, "\n") != 2 || !strings.Contains(out, s1) {
		t.Errorf("left pending:\n%s", out)
	}
	if code, out, _ := w.lox(t, "withdraw", "--lock", "crm", "--error"); code != 0 || !strings.Contains(out, "nothing to withdraw") {
		t.Errorf("nothing left = %d\n%s", code, out)
	}
	b, _ := os.ReadFile(w.audit)
	if n := strings.Count(string(b), `"reason":"withdrawn by `); n != 4 || !strings.Contains(string(b), " in lox withdraw") {
		t.Errorf("%d withdrawals audited:\n%s", n, b)
	}
}

func TestWithdrawUsage(t *testing.T) {
	for _, args := range [][]string{
		{"withdraw"},
		{"withdraw", "--lock", "crm"},
		{"withdraw", "--all-pending"},
		{"withdraw", "a/b", "--lock", "crm", "--all-pending"},
		{"withdraw", "--lock", "crm", "--all-pending", "--error"},
		{"withdraw", "nope"},
		{"tickets", "extra"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, nil, &out, &errb); code != 2 {
			t.Errorf("%v = %d (%s)", args, code, errb.String())
		}
	}
}
