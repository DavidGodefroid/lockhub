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
	// pushed counts the tickets pushed: each is created a second after
	// the one before, so the queue (ordered by created, then id) lists
	// them in push order (lockhub#55: two tickets of one second were
	// ordered by their random ULIDs).
	pushed *int
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
	return env{h, st, priv, sock, new(int)}
}

func (e env) push(t *testing.T, risk ticket.Risk, prod bool, body string) string {
	*e.pushed++
	created := time.Now().Add(-time.Hour).Add(time.Duration(*e.pushed) * time.Second)
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, risk,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), created, 0)
	tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: "dev-1\x1b[31m", Session: "s"}
	tk.Screen = ticket.Screen{Header: "query on crm", Body: []string{body}, Warnings: []string{"touches 3 rows"}}
	if prod {
		// lockkit's Retype is the console's "retype values" answer, never
		// what the human types: lock approve asks for the instance name.
		tk.Flags = ticket.Flags{Production: true, Retype: "r"}
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
	out := e.run(t, "y\ncmr\ny\nr\ny\n\ny\ncrm\n")
	if e.state(t, id) != state.Approved {
		t.Fatalf("state %s\n%s", e.state(t, id), out)
	}
	if strings.Count(out, "does not match: not approved") != 3 || !strings.Contains(out, "PRODUCTION") ||
		!strings.Contains(out, `type the instance name "crm" to approve`) {
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

// A renewal lists each input that moved, including one the lock could
// not check now (lockkit's "unchecked").
func TestScreenShowsRenewalChanges(t *testing.T) {
	raw := []byte(`{"id":"N1","source":{"lock":"locksql"},"screen":{"header":"h"},"renews":{"of":"O1","reason":"expired","approved_at":null,"checked":true,
		"changes":[{"input":"schema","change":"changed"},{"input":"stats","change":"unchecked"}]}}`)
	out, _, err := approve.Screen(api.QueueItem{ID: "N1", Instance: "crm", Risk: "write", Ticket: raw}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"asks again for ticket O1", "schema: changed", "stats: not checked now — the run checks it"} {
		if !strings.Contains(out, want) {
			t.Errorf("screen lacks %q:\n%s", want, out)
		}
	}
}

// An expired ticket (lock approve renew) says how long ago, never a
// negative "expires in".
func TestScreenExpiredTicket(t *testing.T) {
	now := time.Now()
	raw := []byte(`{"id":"O1","source":{"lock":"locksql"},"screen":{"header":"h"}}`)
	for _, c := range []struct {
		at   time.Time
		want string
	}{{now.Add(-2 * time.Hour), "expired 2h0m0s ago"}, {now.Add(time.Hour), "expires in 1h0m0s"}} {
		at := c.at
		out, _, err := approve.Screen(api.QueueItem{ID: "O1", Instance: "crm", Risk: "write", Ticket: raw, Expires: &at}, now)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, c.want) || strings.Contains(out, "expires in -") {
			t.Errorf("screen lacks %q:\n%s", c.want, out)
		}
	}
}
