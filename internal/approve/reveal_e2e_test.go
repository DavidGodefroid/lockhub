package approve_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// The clear value: the lock knows it, the terminal shows it on Ctrl-O,
// the hub never sees it.
const secret = "jane.doe@example.com"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// capture records every body a handler receives and serves.
type capture struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (c *capture) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		rec := &recorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		c.mu.Lock()
		c.bodies = append(c.bodies, b, rec.buf.Bytes())
		c.mu.Unlock()
	})
}

func (c *capture) all() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.bodies...)
}

type recorder struct {
	http.ResponseWriter
	buf bytes.Buffer
}

func (r *recorder) Write(b []byte) (int, error) { r.buf.Write(b); return r.ResponseWriter.Write(b) }
func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// world is a hub on disk, a real lockkit lock (hubclient) watching it,
// and the terminal facade's keys.
type world struct {
	h        *hub.Hub
	st       *store.Store
	dir      string
	sock     string
	clk      *clock
	lockPub  ed25519.PublicKey
	lock     *hubclient.Client
	plans    *plans.Store
	tty      ed25519.PrivateKey
	lockAPI  *capture
	facade   *capture
	reports  *capture
	audit    string
	inputs   map[string]string
	inputsMu sync.Mutex
}

var caller = plans.Caller{UID: 1000, Token: "tok-dev-1"}

const policyFP = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func newWorld(t *testing.T, routes route.Rules) *world {
	t.Helper()
	dir, err := os.MkdirTemp("", "lhe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	w := &world{dir: dir, clk: &clock{t: time.Now().UTC().Truncate(time.Millisecond)}, lockAPI: &capture{}, facade: &capture{}, reports: &capture{},
		inputs: map[string]string{"sql": "sha256:" + strings.Repeat("a", 64), "schema": "sha256:" + strings.Repeat("b", 64)}}
	lockPub, lockPriv, _ := ed25519.GenerateKey(rand.Reader)
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	ttyPub, ttyPriv, _ := ed25519.GenerateKey(rand.Reader)
	w.lockPub, w.tty = lockPub, ttyPriv
	w.st, _ = store.Open(filepath.Join(dir, "hub.db"))
	t.Cleanup(func() { w.st.Close() })
	w.audit = filepath.Join(dir, "tickets.jsonl")
	al, err := audit.OpenSigned(w.audit, hubPriv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	w.h = hub.New(hub.Config{Store: w.st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubPriv, Routes: routes,
		Locks: map[string]ed25519.PublicKey{"crm": lockPub}, Now: w.clk.now, RequestWait: 10 * time.Second})
	lsrv := httptest.NewServer(w.lockAPI.wrap(api.LockHandler(w.h, "e2e")))
	t.Cleanup(lsrv.Close)
	w.sock = filepath.Join(dir, "f.sock")
	ln, err := net.Listen("unix", w.sock)
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: w.facade.wrap(api.FacadeHandler(w.h)), ConnContext: peer.ConnContext}
	go fsrv.Serve(ln)
	t.Cleanup(func() { fsrv.Close() })

	// The lock, as lock up runs it: it pins the hub key and the tty
	// facade's key (facades.json).
	w.plans, err = plans.Open(filepath.Join(dir, "plans"), plans.WithClock(w.clk.now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.plans.Close() })
	w.lock, err = hubclient.New(hubclient.Config{URL: lsrv.URL, Instance: "crm", Key: lockPriv, HubKey: hubPub, Now: w.clk.now,
		StateFile: filepath.Join(dir, "lock-hub.json"), Facades: []ticket.PinnedFacade{{Facade: ticket.FacadeTTY, Key: ttyPub}}})
	if err != nil {
		t.Fatal(err)
	}
	w.lock.SetRecompute(func(p *plans.Plan) (string, string, map[string]string, error) {
		w.inputsMu.Lock()
		defer w.inputsMu.Unlock()
		in := map[string]string{}
		for k, v := range w.inputs {
			in[k] = v
		}
		h, _ := ticket.HashOf(in)
		return policyFP, h, in, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.lock.Watch(ctx, w.plans, func(err error) {
		w.reports.mu.Lock()
		w.reports.bodies = append(w.reports.bodies, []byte(err.Error()))
		w.reports.mu.Unlock()
	})
	return w
}

// submit plans a request at the lock and sends its ticket, with the clear
// screen the lock keeps for a reveal.
func (w *world) submit(t *testing.T, risk ticket.Risk, prod bool, ttl time.Duration) string {
	t.Helper()
	w.inputsMu.Lock()
	in := map[string]string{}
	for k, v := range w.inputs {
		in[k] = v
	}
	w.inputsMu.Unlock()
	hash, _ := ticket.HashOf(in)
	p, err := w.plans.Create(plans.Binding{UID: caller.UID, Agent: "dev-1", TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: hash, Inputs: in}, json.RawMessage(`{"sql":"UPDATE customers SET email = $1"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, risk, hash, policyFP, w.clk.now(), ttl)
	tk.Workspace, tk.Requester = "~/Documents", ticket.Requester{Agent: "dev-1", Session: "s1"}
	if prod {
		tk.Flags = ticket.Flags{Production: true, Retype: "crm"}
	}
	masked := render.MaskScreen(render.ScreenSource{Header: "crm · write",
		Body: []render.Line{{{Text: "UPDATE customers SET email = "}, {Text: secret, Value: true, Column: "email", ColumnType: "text"}}}}, render.Masking{})
	clear := &ticket.Screen{Header: "crm · write", Body: []string{"UPDATE customers SET email = '" + secret + "'"}}
	id, err := w.lock.SubmitClear(context.Background(), w.plans, p.ID, caller, tk, masked, clear)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (w *world) session(input string, out io.Writer) *approve.Session {
	return &approve.Session{C: approve.Dial(w.sock), In: bufio.NewReader(strings.NewReader(input)), Out: out, Display: "david", Once: true,
		FacadeKey: w.tty, LockKeys: map[string]ed25519.PublicKey{"crm": w.lockPub}}
}

func (w *world) run(t *testing.T, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := w.session(input, &out).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func (w *world) state(t *testing.T, id string) state.State {
	t.Helper()
	var st state.State
	w.st.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: "crm", ID: id})
		st = tk.State
		return err
	})
	return st
}

// runs waits until the lock may run ticket id (its decision polled).
func (w *world) runs(t *testing.T, id string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		_, _, err := w.lock.Begin(w.plans, id, caller, func(p *plans.Plan) (string, string, error) {
			return p.Binding.PolicyFP, p.Binding.PlanHash, nil
		})
		if err == nil {
			return
		}
		if !errors.Is(err, hubclient.ErrPending) || time.Now().After(deadline) {
			t.Fatalf("lock cannot run %s: %v", id, err)
		}
	}
}

// Capture: the terminal shows the clear value on Ctrl-O; the hub's
// store, audit log, every body it receives and serves, and the lock's
// reports never hold it.
func TestRevealCapture(t *testing.T) {
	w := newWorld(t, route.Rules{})
	id := w.submit(t, ticket.RiskWrite, false, time.Hour)
	out := w.run(t, "\x0f\ny\n")
	if !strings.Contains(out, "CLEAR VALUES") || !strings.Contains(out, secret) || !strings.Contains(out, "approved") {
		t.Fatalf("terminal:\n%s", out)
	}
	if i, j := strings.Index(out, secret), strings.Index(out, "end of clear values"); i < 0 || j < i {
		t.Errorf("the clear value is outside the marked section:\n%s", out)
	}
	if w.state(t, id) != state.Approved {
		t.Fatalf("ticket is %s", w.state(t, id))
	}
	w.runs(t, id)

	var hubSide [][]byte
	hubSide = append(hubSide, w.lockAPI.all()...)
	hubSide = append(hubSide, w.facade.all()...)
	hubSide = append(hubSide, w.reports.all()...)
	for _, f := range []string{"hub.db", "hub.db-wal", "tickets.jsonl"} {
		b, _ := os.ReadFile(filepath.Join(w.dir, f))
		hubSide = append(hubSide, b)
	}
	db, _ := os.ReadFile(filepath.Join(w.dir, "hub.db"))
	wal, _ := os.ReadFile(filepath.Join(w.dir, "hub.db-wal"))
	if !bytes.Contains(append(db, wal...), []byte("UPDATE customers SET email")) {
		t.Error("the hub's store does not hold the masked ticket: the capture read the wrong files")
	}
	sawReveal := false
	for _, b := range hubSide {
		if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte("jane.doe")) {
			t.Errorf("the hub saw the clear value: %.300s", b)
		}
		sawReveal = sawReveal || bytes.Contains(b, []byte(`"box"`))
	}
	if !sawReveal {
		t.Error("the capture saw no sealed answer: the test captured nothing")
	}
	log, _ := os.ReadFile(w.audit)
	if !strings.Contains(string(log), `"event":"reveal"`) || !strings.Contains(string(log), `"reason":"answered"`) {
		t.Errorf("no reveal in the audit log:\n%s", log)
	}
}

// The hub refuses a reveal for slack, telegram and mobile, for a facade
// the routing keeps from the ticket, and a key signed for another facade.
func TestRevealRefusals(t *testing.T) {
	w := newWorld(t, route.Rules{Only: map[string][]string{"crm": {"deck", "slack", "telegram", "mobile"}}})
	id := w.submit(t, ticket.RiskWrite, false, time.Hour)
	tk, _ := ticket.VerifyTicket(w.lockPub, mustTicket(t, w, id))
	c := approve.Dial(w.sock)
	for _, f := range []string{"slack", "telegram", "mobile", "tty"} {
		rk, _, _ := ticket.NewRevealKey(w.tty, ticket.FacadeTTY, tk, w.clk.now())
		kb, _ := json.Marshal(rk)
		_, err := c.Reveal(context.Background(), "crm", id, api.RevealRequest{Facade: f, Key: kb})
		var he *approve.HubError
		if !errors.As(err, &he) || (he.Status != 400 && he.Status != 403) {
			t.Errorf("reveal on %s: %v", f, err)
		}
	}
	// deck is routed, but the key is the tty's: the hub refuses it.
	rk, _, _ := ticket.NewRevealKey(w.tty, ticket.FacadeTTY, tk, w.clk.now())
	kb, _ := json.Marshal(rk)
	if _, err := c.Reveal(context.Background(), "crm", id, api.RevealRequest{Facade: "deck", Key: kb}); err == nil || !strings.Contains(err.Error(), "another facade") {
		t.Errorf("tty key from the deck: %v", err)
	}
	// A deck key the lock does not pin: the hub relays, the lock refuses.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	rk, _, _ = ticket.NewRevealKey(other, ticket.FacadeDeck, tk, w.clk.now())
	kb, _ = json.Marshal(rk)
	_, err := c.Reveal(context.Background(), "crm", id, api.RevealRequest{Facade: "deck", Key: kb})
	if approve.Explain(err) != "the lock does not pin this terminal's facade key (run lock up)" {
		t.Errorf("unpinned deck key: %v (%s)", err, approve.Explain(err))
	}
}

func mustTicket(t *testing.T, w *world, id string) []byte {
	t.Helper()
	var raw []byte
	w.st.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: "crm", ID: id})
		raw = tk.Raw
		return err
	})
	return raw
}

// expire lets ticket id expire undecided, at the hub and the lock.
func (w *world) expire(t *testing.T, id string) {
	t.Helper()
	w.clk.add(2 * time.Hour)
	if err := w.h.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.state(t, id) != state.Expired {
		t.Fatalf("ticket is %s", w.state(t, id))
	}
}

// H1: nothing changed, not production: r approves the renewal in one
// step, and the lock runs it.
func TestRenewUnchangedOneClick(t *testing.T) {
	w := newWorld(t, route.Rules{})
	id := w.submit(t, ticket.RiskWrite, false, time.Hour)
	w.expire(t, id)
	out := w.run(t, "r\n")
	if !strings.Contains(out, "EXPIRED") || !strings.Contains(out, "re-approved as ticket") {
		t.Fatalf("terminal:\n%s", out)
	}
	res, _ := approve.Dial(w.sock).QueueAll(context.Background(), 0, 0)
	if len(res.Expired) != 0 || len(res.Tickets) != 0 {
		t.Errorf("queue after the re-approval: %+v", res)
	}
	ds, _ := w.st.Decisions(context.Background(), "crm", 0, 10)
	if len(ds) != 1 || !bytes.Contains(ds[0].Raw, []byte(hub.RenewalReason)) || !bytes.Contains(ds[0].Raw, []byte(`"facade":"tty"`)) {
		t.Fatalf("decisions %d %v", len(ds), ds)
	}
	w.runs(t, ds[0].Ticket)
}

// Changed: the renewal waits with its changes, approved with y.
func TestRenewChangedWaits(t *testing.T) {
	w := newWorld(t, route.Rules{})
	id := w.submit(t, ticket.RiskWrite, false, time.Hour)
	w.expire(t, id)
	w.inputsMu.Lock()
	w.inputs["schema"] = "sha256:" + strings.Repeat("c", 64)
	w.inputsMu.Unlock()
	out := w.run(t, "r\ny\n")
	for _, want := range []string{"the lock asks again with ticket", "asks again for ticket " + id, "changed since then:", "schema: changed", "approved"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sql: changed") {
		t.Errorf("an unchanged input shown as changed:\n%s", out)
	}
	ds, _ := w.st.Decisions(context.Background(), "crm", 0, 10)
	if len(ds) != 1 || bytes.Contains(ds[0].Raw, []byte("re-approved")) {
		t.Fatalf("decisions %d %v", len(ds), ds)
	}
	w.runs(t, ds[0].Ticket)
}

// Production: never one click; the renewal asks for the typed name.
func TestRenewProductionRetype(t *testing.T) {
	w := newWorld(t, route.Rules{})
	id := w.submit(t, ticket.RiskProdWrite, true, time.Hour)
	w.expire(t, id)
	out := w.run(t, "r\ny\ncrm\n")
	if strings.Contains(out, "re-approved") || !strings.Contains(out, `type "crm" to approve`) || !strings.Contains(out, "nothing changed since then") {
		t.Fatalf("terminal:\n%s", out)
	}
	ds, _ := w.st.Decisions(context.Background(), "crm", 0, 10)
	if len(ds) != 1 {
		t.Fatalf("decisions %d", len(ds))
	}
	w.runs(t, ds[0].Ticket)
}

// The renew endpoint itself: slack and telegram cannot renew; an
// existing renewal comes back without a second ticket.
func TestRenewEndpoint(t *testing.T) {
	w := newWorld(t, route.Rules{})
	id := w.submit(t, ticket.RiskWrite, false, time.Hour)
	w.expire(t, id)
	c := approve.Dial(w.sock)
	for _, f := range []string{"slack", "telegram", "mobile"} {
		if _, err := c.Renew(context.Background(), "crm", id, api.RenewRequest{Facade: f}); err == nil {
			t.Errorf("renew on %s accepted", f)
		}
	}
	w.inputsMu.Lock()
	w.inputs["sql"] = "sha256:" + strings.Repeat("d", 64)
	w.inputsMu.Unlock()
	r1, err := c.Renew(context.Background(), "crm", id, api.RenewRequest{Facade: "tty"})
	if err != nil || r1.AutoApproved || r1.Ticket == "" {
		t.Fatalf("renew %+v %v", r1, err)
	}
	if w.state(t, r1.Ticket) != state.Pending {
		t.Errorf("renewal is %s", w.state(t, r1.Ticket))
	}
	r2, err := c.Renew(context.Background(), "crm", id, api.RenewRequest{Facade: "tty"})
	if err != nil || r2.Ticket != r1.Ticket {
		t.Errorf("renew again: %+v %v, want %s", r2, err, r1.Ticket)
	}
}
