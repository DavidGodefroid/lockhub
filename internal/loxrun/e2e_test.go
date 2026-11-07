package loxrun_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	"github.com/DavidGodefroid/lockkit/lazyconn"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/loxaudit"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

const (
	// prodProfile is a production profile of the lock.
	prodProfile = "shop-prod"
	inst        = "shop"
	password    = "pw-of-profile-A"
	policyFP    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

var caller = plans.Caller{UID: 1000, Token: "tok-dev-1"}

// conn is a backend connection the lock opened.
type conn struct {
	profile, secret string
	closed          bool
}

func (c *conn) Close() error { c.closed = true; return nil }

// world: the real hub (lockkit codec, store, signed audit) behind its
// lock API and its facade socket; a real lockkit lock (hubclient, plans,
// lazyconn pool) that starts disconnected; and lox run on the facade
// socket, driven by key presses.
type world struct {
	t       *testing.T
	h       *hub.Hub
	st      *store.Store
	dir     string
	hubPub  ed25519.PublicKey
	lock    *hubclient.Client
	plans   *plans.Store
	pool    *lazyconn.Pool[*conn]
	keys    chan loxrun.Key
	out     *syncBuf
	events  chan loxrun.Event
	idle    chan func()
	mu      sync.Mutex
	dials   []*conn
	stopRun context.CancelFunc
	runDone chan error
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type stopper struct{}

func (stopper) Stop() bool { return true }

func newWorld(t *testing.T) *world { return newWorldArm(t, -1) }

// newWorldArm is newWorld with lox run's KeyArm (0: the default).
func newWorldArm(t *testing.T, arm time.Duration) *world {
	t.Helper()
	dir, err := os.MkdirTemp("", "loxrun")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	w := &world{t: t, dir: dir, keys: make(chan loxrun.Key, 16), out: &syncBuf{}, events: make(chan loxrun.Event, 256), idle: make(chan func(), 8)}
	lockPub, lockPriv, _ := ed25519.GenerateKey(rand.Reader)
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	w.hubPub = hubPub
	if w.st, err = store.Open(filepath.Join(dir, "hub.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.st.Close() })
	al, err := audit.OpenSigned(filepath.Join(dir, "tickets.jsonl"), hubPriv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	w.h = hub.New(hub.Config{Store: w.st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubPriv, Routes: route.Rules{},
		Locks: map[string]ed25519.PublicKey{inst: lockPub}})
	lsrv := httptest.NewServer(api.LockHandler(w.h, "e2e"))
	t.Cleanup(lsrv.Close)
	sock := filepath.Join(dir, "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: api.FacadeHandler(w.h), ConnContext: peer.ConnContext}
	go fsrv.Serve(ln)
	t.Cleanup(func() { fsrv.Close() })

	if w.plans, err = plans.Open(filepath.Join(dir, "plans")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.plans.Close() })
	w.lock, err = hubclient.New(hubclient.Config{URL: lsrv.URL, Instance: inst, Key: lockPriv, HubKey: hubPub,
		StateFile: filepath.Join(dir, "lock-hub.json")})
	if err != nil {
		t.Fatal(err)
	}
	lctx, lcancel := context.WithCancel(context.Background())
	watched := make(chan struct{})
	go func() { defer close(watched); w.lock.Watch(lctx, w.plans, func(error) {}) }()
	t.Cleanup(func() { lcancel(); <-watched })

	// Profile A takes its password from the decider ("ask"); B and the
	// production profile from the lock's keychain.
	w.pool, err = lazyconn.New(lazyconn.Config[*conn]{
		Lock: "locksql", Asker: w.lock,
		Profile: func(name string) (lazyconn.Profile, error) {
			p := lazyconn.Profile{Endpoint: "db.internal:5432/" + name, Credential: ticket.CredentialKeychain, PolicyFP: policyFP}
			switch name {
			case "A":
				p.Credential, p.NeedSecret = ticket.CredentialAsk, true
			case prodProfile:
				p.Production = true
			}
			return p, nil
		},
		Dial: func(_ context.Context, name string, g lazyconn.Grant) (*conn, error) {
			c := &conn{profile: name, secret: string(g.Secret)}
			w.mu.Lock()
			w.dials = append(w.dials, c)
			w.mu.Unlock()
			return c, nil
		},
		AfterFunc: func(_ time.Duration, f func()) lazyconn.Timer { w.idle <- f; return stopper{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.pool.Close() })

	// lox run, drawing frames on a 100x30 "terminal".
	ctx, cancel := context.WithCancel(context.Background())
	w.stopRun, w.runDone = cancel, make(chan error, 1)
	s := &loxrun.Session{Hub: approve.Dial(sock), Keys: w.keys, Out: w.out, Size: func() (int, int) { return 100, 30 },
		Style: loxrun.Style{Color: true, Unicode: true}, Workspace: "~/e2e", Locks: 1, Display: "david",
		LockKeys:  map[string]ed25519.PublicKey{inst: lockPub},
		QueueWait: 2 * time.Second, StatePoll: 50 * time.Millisecond, KeyArm: arm,
		Observe: func(e loxrun.Event) { w.events <- e },
		// The a key: the hub's audit, read from its data directory as
		// lox run reads it.
		Audit: func() ([]loxrun.Exchange, []loxrun.RunEvent, error) {
			return loxaudit.Load(context.Background(), loxaudit.Source{Data: dir, HubKeys: []ed25519.PublicKey{hubPub},
				LockKeys: map[string]ed25519.PublicKey{inst: lockPub}})
		}}
	go func() { w.runDone <- s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-w.runDone })
	return w
}

// wait returns the next event of kind for ticket id ("" any).
func (w *world) wait(kind loxrun.EventKind, id string) loxrun.Event {
	w.t.Helper()
	timeout := time.After(15 * time.Second)
	for {
		select {
		case e := <-w.events:
			if e.Kind == kind && (id == "" || e.ID == id) {
				return e
			}
			if e.Kind == loxrun.EvFailed {
				w.t.Fatalf("lox run failed to decide %s: %v", e.ID, e.Err)
			}
		case <-timeout:
			w.t.Fatalf("no %s event for %q; terminal:\n%s", kind, id, w.out.String())
		}
	}
}

func (w *world) press(keys ...loxrun.Key) {
	for _, k := range keys {
		w.keys <- k
	}
}

func typed(s string) []loxrun.Key {
	var ks []loxrun.Key
	for _, r := range s {
		ks = append(ks, loxrun.R(r))
	}
	return append(ks, loxrun.Key{Code: loxrun.KeyEnter})
}

// acquire is the agent's request for profile: its connection, opened on
// demand (lazyconn asks the hub through its lock).
func (w *world) acquire(profile string) chan error {
	done := make(chan error, 1)
	go func() {
		_, release, err := w.pool.Acquire(context.Background(), lazyconn.Request{Profile: profile,
			Requester: ticket.Requester{Agent: "dev-1", Session: "s1"}, Workspace: "~/e2e"})
		if err == nil {
			release()
		}
		done <- err
	}()
	return done
}

// submit plans an agent request at the lock and sends its version-2
// ticket of kind with the masked screen.
func (w *world) submit(kind ticket.Kind, risk ticket.Risk, profile, sql string) string {
	w.t.Helper()
	return w.submitWith(kind, risk, profile, sql, nil)
}

// submitWith is submit with mod applied to the ticket before the lock
// signs it.
func (w *world) submitWith(kind ticket.Kind, risk ticket.Risk, profile, sql string, mod func(*ticket.Ticket)) string {
	w.t.Helper()
	return w.submitScreen(kind, risk, profile, sql, mod, nil)
}

// submitFlags is submit with the ticket's flags and the screen's warnings
// (a WARN verdict).
func (w *world) submitFlags(kind ticket.Kind, risk ticket.Risk, profile, sql string, flags ticket.Flags, warnings []string) string {
	w.t.Helper()
	return w.submitScreen(kind, risk, profile, sql, func(tk *ticket.Ticket) {
		tk.Flags.Production, tk.Flags.NeverAuto = flags.Production, flags.NeverAuto || tk.Flags.NeverAuto
	}, warnings)
}

// submitScreen is submitWith with the screen's warnings.
func (w *world) submitScreen(kind ticket.Kind, risk ticket.Risk, profile, sql string, mod func(*ticket.Ticket), warnings []string) string {
	w.t.Helper()
	in := map[string]string{"sql": "sha256:" + strings.Repeat("a", 64), "n": ticket.NewNonce()}
	hash, _ := ticket.HashOf(in)
	p, err := w.plans.Create(plans.Binding{UID: caller.UID, Agent: "dev-1", TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: hash, Inputs: in}, json.RawMessage(`{}`), 0)
	if err != nil {
		w.t.Fatal(err)
	}
	tk := ticket.NewKindTicket(ticket.Source{Lock: "locksql"}, kind, risk, &ticket.Subject{Profile: profile, Target: "customers"},
		hash, policyFP, time.Now(), time.Hour)
	tk.Workspace, tk.Requester = "~/e2e", ticket.Requester{Agent: "dev-1", Session: "s1"}
	if mod != nil {
		mod(tk)
	}
	masked := render.MaskScreen(render.ScreenSource{Header: inst + " / " + profile + " · " + string(kind), Warnings: warnings,
		Body: []render.Line{{{Text: sql}, {Text: "jane.doe@example.com", Value: true, Column: "email", ColumnType: "text"}}}}, render.Masking{})
	id, err := w.lock.Submit(context.Background(), w.plans, p.ID, caller, tk, masked)
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

// decision is the hub's signed decision on ticket id, as the lock gets it.
func (w *world) decision(id string) *ticket.Decision {
	w.t.Helper()
	ds, err := w.h.Decisions(context.Background(), inst, 0, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, d := range ds {
		if d.Ticket == id {
			dec, err := ticket.VerifyDecision(w.hubPub, d.Raw)
			if err != nil {
				w.t.Fatal(err)
			}
			return dec
		}
	}
	w.t.Fatalf("no decision on %s", id)
	return nil
}

func (w *world) ticketState(id string) state.State {
	var s state.State
	w.st.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: inst, ID: id})
		s = tk.State
		return err
	})
	return s
}

func (w *world) lastDial() *conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dials[len(w.dials)-1]
}

// bells checks the terminal rang n bells (once the frame is drawn).
func (w *world) bells(n int) {
	w.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := strings.Count(w.out.String(), "\a")
		if got == n {
			// No later one either.
			time.Sleep(100 * time.Millisecond)
			if got = strings.Count(w.out.String(), "\a"); got == n {
				return
			}
		}
		if got > n || time.Now().After(deadline) {
			w.t.Fatalf("%d bells, want %d (one per question, none for auto traffic)", got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The ticket's scenario, end to end: the agent's first request asks for
// the connection (credentials typed in lox run, sealed to the lock); a
// SELECT runs without a question; an UPDATE is asked; after an idle close
// the connection comes back without a question; another profile asks its
// own; manual mode asks a read; the bell rings only for questions; the
// hub never holds the password; quitting lox run fails closed.
func TestRunE2E(t *testing.T) {
	w := newWorld(t)

	// 1. The agent's first request for A: a connect ticket, asked.
	done := w.acquire("A")
	q := w.wait(loxrun.EvQuestion, "")
	connA := q.ID
	w.bells(1)
	select {
	case err := <-done:
		t.Fatalf("connected before the human answered: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	w.press(loxrun.R('y'))
	w.press(typed(password)...)
	if d := w.wait(loxrun.EvDecided, connA); !d.Approved || d.Rule != "" {
		t.Fatalf("connect decision %+v: want the human's approval", d)
	}
	if err := <-done; err != nil {
		t.Fatalf("connect: %v", err)
	}
	if c := w.lastDial(); c.profile != "A" || c.secret != password {
		t.Fatalf("dialed %+v: want A with the password typed in lox run", c)
	}
	if d := w.decision(connA); d.Auto() || d.Secret == nil || d.V != ticket.VersionKinds {
		t.Errorf("signed connect decision %+v: want human, version 2, a sealed secret", d)
	}
	w.wait(loxrun.EvResult, connA) // consumed: the lock connected

	// 2. A SELECT on A: auto, no question, no bell.
	sel := w.submit(ticket.KindRead, ticket.RiskRead, "A", "SELECT id FROM customers WHERE email = ")
	if d := w.wait(loxrun.EvDecided, sel); !d.Approved || d.Rule != "default:read" {
		t.Fatalf("SELECT decision %+v: want auto by default:read", d)
	}
	if d := w.decision(sel); !d.Auto() || d.Rule.ID != "default:read" {
		t.Errorf("signed SELECT decision rule %+v", d.Rule)
	}

	// 3. An UPDATE on A: asked, approved by the human.
	upd := w.submit(ticket.KindWrite, ticket.RiskWrite, "A", "UPDATE customers SET email = ")
	w.wait(loxrun.EvQuestion, upd)
	w.press(loxrun.R('y'))
	if d := w.wait(loxrun.EvDecided, upd); !d.Approved || d.Rule != "" {
		t.Fatalf("UPDATE decision %+v", d)
	}
	if d := w.decision(upd); d.Auto() {
		t.Error("UPDATE approved by a rule")
	}

	// 4. The lock closes A's connection once idle; the next request asks
	// again, and lox run approves it on the session's approval, with the
	// password sealed again: no question.
	(<-w.idle)()
	if w.pool.Connected("A") {
		t.Fatal("A still connected after its idle close")
	}
	done = w.acquire("A")
	again := w.wait(loxrun.EvDecided, "")
	if again.Rule != "session:connect" || !again.Approved {
		t.Fatalf("reconnect decision %+v: want session:connect", again)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c := w.lastDial(); c.secret != password {
		t.Errorf("reconnect dialed with %q", c.secret)
	}

	// 5. Profile B: its own question.
	done = w.acquire("B")
	qb := w.wait(loxrun.EvQuestion, "")
	w.press(loxrun.R('y'))
	if d := w.wait(loxrun.EvDecided, qb.ID); !d.Approved || d.Rule != "" {
		t.Fatalf("B decision %+v", d)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// 6. Manual mode (Shift+Tab): a SELECT is asked; denied.
	w.press(loxrun.Key{Code: loxrun.KeyShiftTab})
	if m := w.wait(loxrun.EvMode, ""); m.Mode != loxrun.Manual {
		t.Fatalf("mode %v", m.Mode)
	}
	sel2 := w.submit(ticket.KindRead, ticket.RiskRead, "B", "SELECT id FROM customers WHERE email = ")
	w.wait(loxrun.EvQuestion, sel2)
	w.press(loxrun.R('n'))
	if d := w.wait(loxrun.EvDecided, sel2); d.Approved {
		t.Fatal("denied SELECT approved")
	}

	// The bell rang for the four questions only.
	w.bells(4)
	// The masked value shows masked; the clear one nowhere.
	screen := w.out.String()
	if strings.Contains(screen, "jane.doe@example.com") || !strings.Contains(screen, "‹j***(20)›") {
		t.Errorf("terminal shows a clear value, or no masked one")
	}
	// The hub never held the password: not in its store, not in its audit.
	for _, f := range []string{"hub.db", "hub.db-wal", "tickets.jsonl"} {
		b, _ := os.ReadFile(filepath.Join(w.dir, f))
		if bytes.Contains(b, []byte(password)) {
			t.Errorf("%s holds the password", f)
		}
	}

	// 7. Quit (q q): decisions stop; a new ticket waits (fail closed).
	w.press(loxrun.R('q'), loxrun.R('q'))
	select {
	case err := <-w.runDone:
		if err != nil {
			t.Fatal(err)
		}
		w.runDone <- nil // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("lox run did not quit")
	}
	late := w.submit(ticket.KindRead, ticket.RiskRead, "A", "SELECT 1 -- ")
	time.Sleep(300 * time.Millisecond)
	if s := w.ticketState(late); s != state.Pending {
		t.Errorf("ticket after quit: %s, want pending", s)
	}
	_, _, err := w.lock.Begin(w.plans, late, caller, func(p *plans.Plan) (string, string, error) {
		return p.Binding.PolicyFP, p.Binding.PlanHash, nil
	})
	if !errors.Is(err, hubclient.ErrPending) {
		t.Errorf("lock may run a ticket after lox run quit: %v", err)
	}
}

// A read whose SQL and requester hold <, >, & and non-ASCII reaches
// lox run byte for byte (the facade does not HTML-escape the signed
// ticket, #147): it verifies under the pinned lock key and is
// auto-approved, and the lock gets the decision.
func TestRunE2EHTMLChars(t *testing.T) {
	w := newWorld(t)
	done := w.acquire("B")
	q := w.wait(loxrun.EvQuestion, "")
	w.press(loxrun.R('y'))
	if d := w.wait(loxrun.EvDecided, q.ID); !d.Approved {
		t.Fatalf("connect decision %+v", d)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sql := "SELECT id FROM b WHERE b.id >= 'a' AND b.id < 'z' AND b.source <> 'manual' AND b.flags & 4 = 4 AND b.name = 'Zoé « ç »' AND "
	sel := w.submitWith(ticket.KindRead, ticket.RiskRead, "B", sql, func(tk *ticket.Ticket) {
		tk.Requester.Session = "s1 <&> ünïcode"
		tk.Workspace = "~/e2e/<a&b>"
	})
	if d := w.wait(loxrun.EvDecided, sel); !d.Approved || d.Rule != "default:read" {
		t.Fatalf("SELECT decision %+v: want auto by default:read", d)
	}
	if d := w.decision(sel); !d.Auto() {
		t.Errorf("signed SELECT decision %+v", d)
	}
}

// The question on top changes under the human's key (the first UPDATE
// decided, the second one comes up): a y pressed right then is not the
// second one's approval; it stays pending at the hub until the human
// answers it once shown (default KeyArm).
func TestRunE2EKeyGuard(t *testing.T) {
	w := newWorldArm(t, 0)
	upd1 := w.submit(ticket.KindWrite, ticket.RiskWrite, "B", "UPDATE customers SET email = ")
	w.wait(loxrun.EvShown, upd1)
	upd2 := w.submit(ticket.KindWrite, ticket.RiskWrite, "B", "UPDATE customers SET name = ")
	w.wait(loxrun.EvQuestion, upd2)
	time.Sleep(500 * time.Millisecond)
	w.press(loxrun.R('y'))
	if d := w.wait(loxrun.EvDecided, upd1); !d.Approved {
		t.Fatalf("first UPDATE %+v", d)
	}
	w.wait(loxrun.EvShown, upd2)
	w.press(loxrun.R('y')) // meant for the first one
	time.Sleep(150 * time.Millisecond)
	if s := w.ticketState(upd2); s != state.Pending {
		t.Fatalf("second UPDATE %s by a key pressed before it was shown", s)
	}
	time.Sleep(400 * time.Millisecond)
	w.press(loxrun.R('n'))
	if d := w.wait(loxrun.EvDecided, upd2); d.Approved || d.Rule != "" {
		t.Fatalf("second UPDATE %+v", d)
	}
	if d := w.decision(upd2); d.Decision != ticket.Denied {
		t.Error("the hub signed an approval of the second UPDATE")
	}
}

// From the agent's tickets to the audit listing: a connection approved
// with a password typed in lox run, an auto SELECT, an UPDATE approved
// and one denied; lox audit lists each with its decision and the rule or
// human behind it, filters them, shows the deciding rule in the detail,
// and never a clear value nor the password; lox run's a key shows the
// same listing without leaving the session.
func TestAuditE2E(t *testing.T) {
	w := newWorld(t)
	done := w.acquire("A")
	conn := w.wait(loxrun.EvQuestion, "").ID
	w.press(loxrun.R('y'))
	w.press(typed(password)...)
	w.wait(loxrun.EvDecided, conn)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	w.wait(loxrun.EvResult, conn)
	sel := w.submit(ticket.KindRead, ticket.RiskRead, "A", "SELECT id FROM customers WHERE email = ")
	w.wait(loxrun.EvDecided, sel)
	upd := w.submit(ticket.KindWrite, ticket.RiskWrite, "A", "UPDATE customers SET email = ")
	w.wait(loxrun.EvQuestion, upd)
	w.press(loxrun.R('y'))
	w.wait(loxrun.EvDecided, upd)
	del := w.submit(ticket.KindWrite, ticket.RiskWrite, "A", "DELETE FROM customers WHERE email = ")
	w.wait(loxrun.EvQuestion, del)
	w.press(loxrun.R('n'))
	w.wait(loxrun.EvDecided, del)

	src := loxaudit.Source{Data: w.dir, HubKeys: []ed25519.PublicKey{w.hubPub}}
	xs, _, err := loxaudit.Load(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(xs) != 4 {
		t.Fatalf("%d exchanges, want 4", len(xs))
	}
	want := map[string]struct{ decision, rule, facade string }{
		conn: {"human", "", "tty"}, sel: {"auto", "default:read", ""}, upd: {"human", "", "tty"}, del: {"denied", "", "tty"},
	}
	for _, x := range xs {
		wx, ok := want[x.ID]
		if !ok || x.Decision() != wx.decision || x.Rule != wx.rule || x.Facade != wx.facade || x.Agent != "dev-1" || x.Profile != "A" ||
			x.Sig != loxrun.SigOK {
			t.Errorf("%s: %s rule %q facade %q agent %q profile %q sig %v (%s)", x.ID, x.Decision(), x.Rule, x.Facade, x.Agent, x.Profile, x.Sig, x.SigNote)
		}
	}
	if w := (loxaudit.Filter{Writes: true}).Apply(xs); len(w) != 2 {
		t.Errorf("--writes: %d", len(w))
	}
	if d := (loxaudit.Filter{Decision: "denied"}).Apply(xs); len(d) != 1 || d[0].ID != del {
		t.Errorf("--decision denied: %v", d)
	}
	st := loxrun.Style{Color: true, Unicode: true}
	listing := strings.Join(loxrun.AuditListing(xs, nil, time.Local, 120, st), "\n")
	x, _ := loxaudit.Find(xs, inst+"/"+sel)
	detail := strings.Join(loxrun.AuditDetail(x, time.Local, 100, st), "\n")
	if !strings.Contains(detail, "default:read") || !strings.Contains(detail, "decision signed by the hub key") {
		t.Errorf("detail lacks the deciding rule or the signature:\n%s", detail)
	}
	for _, out := range []string{listing, detail} {
		if strings.Contains(out, password) || strings.Contains(out, "jane.doe@example.com") {
			t.Errorf("clear value printed:\n%s", out)
		}
	}
	if !strings.Contains(listing, "4 exchanges") || !strings.Contains(listing, "‹j***(20)›") {
		t.Errorf("listing:\n%s", listing)
	}

	// Inside lox run: a opens the hub's audit.
	w.press(loxrun.R('a'))
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(w.out.String(), "the hub's audit") {
		if time.Now().After(deadline) {
			t.Fatalf("a did not open the hub's audit:\n%s", w.out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if screen := w.out.String(); !strings.Contains(screen, "4 exchanges") || strings.Contains(screen, password) {
		t.Errorf("lox run's audit view")
	}
}
