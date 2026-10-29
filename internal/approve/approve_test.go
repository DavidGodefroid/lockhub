package approve_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

type env struct {
	h    *hub.Hub
	st   *store.Store
	lock ed25519.PrivateKey
	sock string
}

func setup(t *testing.T) env {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	dir, err := os.MkdirTemp("", "lh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	t.Cleanup(func() { st.Close() })
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	t.Cleanup(func() { al.Close() })
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hk,
		Locks: map[string]ed25519.PublicKey{"crm": pub}})
	sock := filepath.Join(dir, "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: api.FacadeHandler(h), ConnContext: peer.ConnContext}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return env{h, st, priv, sock}
}

func (e env) push(t *testing.T, risk ticket.Risk, prod bool, body string) string {
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, risk,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: "dev-1\x1b[31m", Session: "s"}
	tk.Screen = ticket.Screen{Header: "query on crm", Body: []string{body}, Warnings: []string{"touches 3 rows"}}
	if prod {
		tk.Flags = ticket.Flags{Production: true, Retype: "crm"}
	}
	if err := tk.Sign(e.lock); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	if _, _, err := e.h.Push(context.Background(), "crm", raw); err != nil {
		t.Fatal(err)
	}
	return tk.ID
}

func (e env) run(t *testing.T, input string) string {
	var out bytes.Buffer
	s := &approve.Session{C: approve.Dial(e.sock), In: bufio.NewReader(strings.NewReader(input)), Out: &out, Display: "david", Once: true}
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func (e env) state(t *testing.T, id string) state.State {
	var st state.State
	e.st.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: "crm", ID: id})
		st = tk.State
		return err
	})
	return st
}

func TestApproveAndDeny(t *testing.T) {
	e := setup(t)
	a := e.push(t, ticket.RiskRead, false, "SELECT count(*) FROM orders")
	d := e.push(t, ticket.RiskWrite, false, "DELETE FROM orders WHERE id = $1")
	out := e.run(t, "y\nn too broad\n")
	if e.state(t, a) != state.Approved || e.state(t, d) != state.Denied {
		t.Fatalf("states %s %s\n%s", e.state(t, a), e.state(t, d), out)
	}
	for _, want := range []string{"locksql · crm · read", "SELECT count(*) FROM orders", "! touches 3 rows", "(unverified) dev-1\\x1b[31m", "approved", "denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("raw escape sequence reached the terminal")
	}
	ds, _ := e.st.Decisions(context.Background(), "crm", 0, 10)
	if len(ds) != 2 {
		t.Fatalf("decisions %d", len(ds))
	}
	if !bytes.Contains(ds[1].Raw, []byte(`"reason":"too broad"`)) || !bytes.Contains(ds[0].Raw, []byte(`"display":"david"`)) || !bytes.Contains(ds[0].Raw, []byte(`"facade":"tty"`)) ||
		!bytes.Contains(ds[0].Raw, []byte(`"id":"host:uid:`)) {
		t.Errorf("decisions %s / %s", ds[0].Raw, ds[1].Raw)
	}
}

func TestProductionRetype(t *testing.T) {
	e := setup(t)
	id := e.push(t, ticket.RiskProdWrite, true, "UPDATE customers SET tier = $1")
	out := e.run(t, "y\ncmr\ny\ncrm\n")
	if e.state(t, id) != state.Approved {
		t.Fatalf("state %s\n%s", e.state(t, id), out)
	}
	if !strings.Contains(out, "does not match: not approved") || !strings.Contains(out, "PRODUCTION") {
		t.Errorf("output:\n%s", out)
	}
}

func TestSkipAndQuit(t *testing.T) {
	e := setup(t)
	a := e.push(t, ticket.RiskRead, false, "q1")
	b := e.push(t, ticket.RiskRead, false, "q2")
	e.run(t, "s\nq\n")
	if e.state(t, a) != state.Pending || e.state(t, b) != state.Pending {
		t.Error("skip or quit decided a ticket")
	}
	// End of input is a quit, not an approval.
	e.run(t, "")
	if e.state(t, a) != state.Pending {
		t.Error("EOF decided a ticket")
	}
}

func TestFacadeSocketOnlyLocalFacades(t *testing.T) {
	e := setup(t)
	id := e.push(t, ticket.RiskRead, false, "q")
	err := approve.Dial(e.sock).Decide(context.Background(), "crm", id, api.DecideRequest{Approved: true, Facade: "slack"})
	if err == nil || !strings.Contains(err.Error(), "tty or deck") {
		t.Errorf("slack facade on the host socket: %v", err)
	}
	if e.state(t, id) != state.Pending {
		t.Error("ticket decided")
	}
}

func TestTicketState(t *testing.T) {
	e := setup(t)
	id := e.push(t, ticket.RiskRead, false, "q")
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", e.sock)
	}}}
	get := func(path string) (int, string) {
		resp, err := c.Get("http://lockhub" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return resp.StatusCode, b.String()
	}
	if code, body := get("/v1/tickets/crm/" + id); code != 200 || !strings.Contains(body, `"state":"pending"`) {
		t.Errorf("state: %d %s", code, body)
	}
	e.h.Withdraw(context.Background(), "crm", id, "stale")
	if _, body := get("/v1/tickets/crm/" + id); !strings.Contains(body, `"state":"withdrawn"`) {
		t.Errorf("after withdraw: %s", body)
	}
	if code, _ := get("/v1/tickets/other/" + id); code != 404 {
		t.Errorf("other instance: %d", code)
	}
}
