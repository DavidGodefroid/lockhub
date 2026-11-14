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

// push pushes a ticket; a production one comes with lockkit's Retype
// flag (its lock asks for the instance name).
func (e env) push(t *testing.T, risk ticket.Risk, prod bool, body string) string {
	var f ticket.Flags
	if prod {
		// lockkit's Retype is the console's "retype values" answer, never
		// what the human types: lox approve asks for the instance name.
		f = ticket.Flags{Production: true, Retype: "r"}
	}
	return e.pushFlags(t, risk, f, body)
}

func (e env) pushFlags(t *testing.T, risk ticket.Risk, f ticket.Flags, body string) string {
	*e.pushed++
	created := time.Now().Add(-time.Hour).Add(time.Duration(*e.pushed) * time.Second)
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, risk,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), created, 0)
	tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: "dev-1\x1b[31m", Session: "s"}
	tk.Screen = ticket.Screen{Header: "query on crm", Body: []string{body}, Warnings: []string{"touches 3 rows"}}
	tk.Flags.Production, tk.Flags.Retype, tk.Flags.Unconfined = f.Production, f.Retype, f.Unconfined
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

// A production ticket whose lock does not ask for the retype (no lockkit
// Retype flag) is approved with y, whatever its risk (#113): the screen
// keeps its PRODUCTION banner, the name is not asked. The queue says so
// (retype empty) for every facade; a ticket with the flag still asks it.
func TestProductionNoRetypeFlag(t *testing.T) {
	e := setup(t)
	w := e.pushFlags(t, ticket.RiskProdWrite, ticket.Flags{Production: true}, "UPDATE customers SET tier = $1")
	p := e.push(t, ticket.RiskRead, true, "SELECT id FROM customers LIMIT 1")
	items, _, err := approve.Dial(e.sock).Queue(context.Background(), 0, 0)
	if err != nil || len(items) != 2 {
		t.Fatalf("queue %v %v", items, err)
	}
	if items[0].ID != w || items[0].Retype != "" || !bytes.Contains(items[0].Ticket, []byte(`"production":true`)) || items[1].ID != p || items[1].Retype != "crm" {
		t.Errorf("queue retype: %q=%q %q=%q", items[0].ID, items[0].Retype, items[1].ID, items[1].Retype)
	}
	out := e.run(t, "y\n")
	if e.state(t, w) != state.Approved {
		t.Fatalf("state %s\n%s", e.state(t, w), out)
	}
	if !strings.Contains(out, "PRODUCTION") || strings.Contains(out, "type the instance name") {
		t.Errorf("output:\n%s", out)
	}
	out = e.run(t, "y\ncrm\n")
	if e.state(t, p) != state.Approved || !strings.Contains(out, `type the instance name "crm" to approve`) {
		t.Errorf("read with the flag: state %s\n%s", e.state(t, p), out)
	}
}

// A grant shows what it is and its scope (the lock's screen) before the
// answer prompt, and a production one whose lock asks for it needs the
// instance name.
func TestGrantShowsScope(t *testing.T) {
	grant := ticket.Risk("grant")
	if !grant.Valid() {
		t.Skip("lockkit before v0.12.0 has no grant (compat build)")
	}
	e := setup(t)
	id := e.push(t, grant, true, "tables: orders, customers · 1h · 50 statements, 10000 rows")
	out := e.run(t, "y\ncrm\n")
	if e.state(t, id) != state.Approved {
		t.Fatalf("state %s\n%s", e.state(t, id), out)
	}
	banner := strings.Index(out, "GRANT: one approval for every read inside this scope")
	scope := strings.Index(out, "tables: orders, customers")
	prompt := strings.Index(out, "approve this grant? [y]es")
	if banner < 0 || scope < banner || prompt < scope || !strings.Contains(out, `type the instance name "crm" to approve`) {
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

// An expired ticket (lox approve renew) says how long ago, never a
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

// lox approve end to end: production tickets of every risk it answers,
// none with lockkit's Retype flag (no current Lock sets it), are each
// approved with a plain y, no name asked (#113).
func TestProductionWithoutFlagApprovedWithY(t *testing.T) {
	e := setup(t)
	prod := ticket.Flags{Production: true}
	var ids []string
	for _, r := range []ticket.Risk{ticket.RiskRead, ticket.RiskReadPII, ticket.RiskWrite, ticket.RiskProdWrite} {
		ids = append(ids, e.pushFlags(t, r, prod, "statement "+string(r)))
	}
	out := e.run(t, strings.Repeat("y\n", len(ids)))
	for _, id := range ids {
		if e.state(t, id) != state.Approved {
			t.Errorf("%s is %s", id, e.state(t, id))
		}
	}
	if strings.Count(out, "PRODUCTION") < len(ids) || strings.Contains(out, "type the instance name") {
		t.Errorf("output:\n%s", out)
	}
}

// The human withdraws a pending ticket through the facade socket: the
// hub ends it withdrawn and its lock gets a denial, signed by the hub
// with lockkit's codec, whose reason names the human and lox run.
func TestWithdraw(t *testing.T) {
	e := setup(t)
	id := e.push(t, ticket.RiskRead, false, "SELECT * FROM t WHERE a < 2 AND b <> 'x' & c")
	c := approve.Dial(e.sock)
	ctx := context.Background()
	res, err := c.Withdraw(ctx, "crm", id, api.WithdrawRequest{Facade: "tty", Display: "david", Via: "lox run"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Told || res.Reason != "withdrawn by david in lox run" {
		t.Errorf("result = %+v", res)
	}
	if e.state(t, id) != state.Withdrawn {
		t.Errorf("state %s", e.state(t, id))
	}
	ds, _ := e.st.Decisions(ctx, "crm", 0, 10)
	if len(ds) != 1 {
		t.Fatalf("decisions %d", len(ds))
	}
	d, err := ticket.VerifyDecision(e.h.PublicKey(), ds[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != ticket.Denied || d.Reason != "withdrawn by david in lox run" || d.Ticket != id || d.Facade != "tty" {
		t.Errorf("decision %+v", d)
	}
	if _, err := c.Withdraw(ctx, "crm", id, api.WithdrawRequest{Facade: "tty", Via: "lox run"}); err == nil {
		t.Error("withdrawn twice")
	}
	if _, err := c.Withdraw(ctx, "crm", "nope", api.WithdrawRequest{Facade: "slack", Via: "lox run"}); err == nil {
		t.Error("a chat facade withdrew on the facade socket")
	}
}

// An unconfined agent's ticket (lockkit#133): the hub takes it (the
// flags member), the queue relays it, the screen says so.
func TestUnconfinedShown(t *testing.T) {
	e := setup(t)
	id := e.pushFlags(t, ticket.RiskRead, ticket.Flags{Unconfined: true}, "SELECT 1")
	items, _, err := approve.Dial(e.sock).Queue(context.Background(), 0, 0)
	if err != nil || len(items) != 1 || items[0].ID != id || !bytes.Contains(items[0].Ticket, []byte(`"unconfined":true`)) {
		t.Fatalf("queue %v %v", items, err)
	}
	scr, _, err := approve.Screen(items[0], time.Now())
	if err != nil || !strings.Contains(strings.SplitN(scr, "\n", 3)[1], "  UNCONFINED") {
		t.Errorf("screen %v:\n%s", err, scr)
	}
	e.pushFlags(t, ticket.RiskRead, ticket.Flags{}, "SELECT 2")
	items, _, _ = approve.Dial(e.sock).Queue(context.Background(), 0, 0)
	if scr, _, _ := approve.Screen(items[1], time.Now()); strings.Contains(scr, "UNCONFINED") || bytes.Contains(items[1].Ticket, []byte("unconfined")) {
		t.Errorf("confined ticket:\n%s", scr)
	}
}
