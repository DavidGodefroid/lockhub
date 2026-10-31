package mobile_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
	"github.com/DavidGodefroid/lockhub/internal/facade/mobile/mobiletest"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

const (
	origin = "https://hub.example.net"
	rpID   = "hub.example.net"
	inst   = "crm"
	pii    = "jane.doe@example.com"
)

// env is a hub with the mobile facade: its lock API (for a real lockkit
// lock client), its facade socket (a real unix socket, so the peer is the
// test's uid) and its mobile listener (TLS: the session cookie is Secure).
type env struct {
	t       *testing.T
	dir     string
	hub     *hub.Hub
	hubKey  ed25519.PrivateKey
	lockKey ed25519.PrivateKey
	svc     *mobile.Service
	lockAPI *httptest.Server
	mobile  *httptest.Server
	facade  *http.Client
	routes  route.Rules
}

func newEnv(t *testing.T, routes route.Rules) *env { t.Helper(); return newEnvWith(t, routes, nil) }

// newEnvWith is newEnv with Web Push on (vapid non-nil).
func newEnvWith(t *testing.T, routes route.Rules, vapid *ecdsa.PrivateKey) *env {
	t.Helper()
	dir := t.TempDir()
	_, hubKey, _ := ed25519.GenerateKey(rand.Reader)
	lockPub, lockKey, _ := ed25519.GenerateKey(rand.Reader)
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.OpenSigned(filepath.Join(dir, "tickets.jsonl"), hubKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close(); st.Close() })
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubKey,
		Locks: map[string]ed25519.PublicKey{inst: lockPub}, Routes: routes})
	svc, err := mobile.New(mobile.Config{Hub: h, Origin: origin, HubKeyID: ticket.KeyID(hubKey.Public().(ed25519.PublicKey)), VAPID: vapid})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, hub: h, hubKey: hubKey, lockKey: lockKey, svc: svc, routes: routes}
	e.lockAPI = httptest.NewServer(api.LockHandler(h, "test"))
	e.mobile = httptest.NewTLSServer(svc.Handler())
	t.Cleanup(func() { e.lockAPI.Close(); e.mobile.Close() })

	sdir, err := os.MkdirTemp("", "lhm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sdir) })
	sock := filepath.Join(sdir, "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: api.FacadeHandler(h, svc.FacadeRoutes), ConnContext: peer.ConnContext}
	go fsrv.Serve(ln)
	t.Cleanup(func() { fsrv.Close() })
	e.facade = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	return e
}

// host calls the facade socket as `lox mobile` does.
func (e *env) host(method, path string, in, out any) int {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://lockhub"+path, body)
	resp, err := e.facade.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return resp.StatusCode
}

func (e *env) phone(name string) *mobiletest.Phone {
	return mobiletest.New(e.mobile.URL, origin, rpID, name, e.mobile.Client())
}

// pair runs `lox mobile pair` with phone p and returns the confirmed
// record (what lox up pins at the locks).
func (e *env) pair(p *mobiletest.Phone) ticket.Device {
	e.t.Helper()
	var start mobile.PairStartResult
	if c := e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: p.Auth.Name}, &start); c != 200 {
		e.t.Fatalf("pair start: %d", c)
	}
	fp, err := p.Pair(start.Code)
	if err != nil {
		e.t.Fatal(err)
	}
	var st mobile.PairStateResult
	e.host("GET", "/v1/mobile/pairings/"+start.ID+"?wait=1", nil, &st)
	if st.State != "registered" || st.Fingerprint != fp {
		e.t.Fatalf("pairing state %+v, phone fingerprint %s", st, fp)
	}
	var conf mobile.PairConfirmResult
	if c := e.host("POST", "/v1/mobile/pairings/"+start.ID+"/confirm", mobile.PairConfirm{Confirm: true, Fingerprint: st.Fingerprint}, &conf); c != 200 {
		e.t.Fatalf("confirm: %d", c)
	}
	devs, err := ticket.ParseDevices([]byte(`{"devices":[` + string(conf.Record) + `],"v":1}`))
	if err != nil {
		e.t.Fatal(err)
	}
	return devs[0]
}

// lock is a real lockkit lock client pinning devs.
type lock struct {
	c     *hubclient.Client
	st    *plans.Store
	pub   ed25519.PublicKey
	calls plans.Caller
}

func (e *env) lock(devs ...ticket.Device) *lock { return e.newLock(nil, devs...) }

// lockRequire is a lock that wants a device's signature on writes.
func (e *env) lockRequire(devs ...ticket.Device) *lock {
	return e.newLock([]ticket.Risk{ticket.RiskWrite}, devs...)
}

func (e *env) newLock(require []ticket.Risk, devs ...ticket.Device) *lock {
	e.t.Helper()
	st, err := plans.Open(filepath.Join(e.t.TempDir(), "plans"))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { st.Close() })
	c, err := hubclient.New(hubclient.Config{URL: e.lockAPI.URL, Instance: inst, Key: e.lockKey,
		HubKey: e.hubKey.Public().(ed25519.PublicKey), StateFile: filepath.Join(e.t.TempDir(), "state.json"),
		Devices: devs, SealClear: len(devs) > 0, RequireDevice: require})
	if err != nil {
		e.t.Fatal(err)
	}
	return &lock{c: c, st: st, pub: e.lockKey.Public().(ed25519.PublicKey), calls: plans.Caller{UID: 1000, Token: "tok"}}
}

// submit opens a plan touching personal data and pushes its ticket: the
// masked screen for the hub, the clear one sealed to the devices.
func (l *lock) submit(t *testing.T, risk ticket.Risk, production bool, sql string) (planID, ticketID string) {
	t.Helper()
	hash, _ := ticket.HashOf(sql + time.Now().String())
	fp, _ := ticket.HashOf("policy")
	p, err := l.st.Create(plans.Binding{UID: 1000, Agent: "dev-1", TokenHash: plans.HashToken("tok"), PolicyFP: fp, PlanHash: hash},
		json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, risk, hash, fp, time.Now(), ticket.ClampTTL(risk, 0))
	tk.Requester = ticket.Requester{Agent: "dev-1 <b>@here</b>", Session: "s"}
	if production {
		tk.Flags = ticket.Flags{Production: true} // no lockkit Retype flag: the name is still asked
	}
	masked := render.MaskScreen(render.ScreenSource{Header: "crm / shop · write",
		Body: []render.Line{{{Text: "UPDATE customers SET email = "}, {Text: pii, Value: true, Column: "email", ColumnType: "text"}}}}, render.Masking{})
	clear := &ticket.Screen{Header: "crm / shop · write", Body: []string{"UPDATE customers SET email = '" + pii + "'"}}
	id, err := l.c.SubmitClear(context.Background(), l.st, p.ID, l.calls, tk, masked, clear)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID, id
}

// run is the lock acting on its ticket: poll, then Begin.
func (l *lock) run(t *testing.T, ticketID string) (*plans.Plan, *ticket.Decision, error) {
	t.Helper()
	p, d, _, err := l.run2(t, ticketID)
	return p, d, err
}

// run2 is run with Poll's error too.
func (l *lock) run2(t *testing.T, ticketID string) (*plans.Plan, *ticket.Decision, error, error) {
	t.Helper()
	_, perr := l.c.Poll(context.Background(), 0)
	p, d, err := l.c.Begin(l.st, ticketID, l.calls, func(p *plans.Plan) (string, string, error) {
		return p.Binding.PolicyFP, p.Binding.PlanHash, nil
	})
	return p, d, perr, err
}

// item is the queue item of ticket id as phone p sees it.
func item(t *testing.T, p *mobiletest.Phone, id string) mobile.Item {
	t.Helper()
	q, err := p.Queue()
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range q.Tickets {
		if it.ID == id {
			return it
		}
	}
	t.Fatalf("ticket %s not in the phone's queue (%d tickets)", id, len(q.Tickets))
	return mobile.Item{}
}
