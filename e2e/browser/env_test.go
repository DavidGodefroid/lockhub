package browser

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

const (
	inst = "crm"
	pii  = "jane.doe@example.com"
)

// chrome finds Chrome; without one the test is skipped, except on the
// Linux CI runner, which has it.
func chrome(t *testing.T) string {
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	if p := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; runtime.GOOS == "darwin" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if os.Getenv("CI") != "" && runtime.GOOS == "linux" {
		t.Fatal("no Chrome on the CI runner")
	}
	t.Skip("no Chrome")
	return ""
}

// env is a hub with its mobile listener (behind an interposer the test
// controls), its facade socket (the host's side), a lock API, and a
// headless Chrome with a virtual WebAuthn authenticator on the web app.
type env struct {
	t       *testing.T
	hubKey  ed25519.PrivateKey
	lockKey ed25519.PrivateKey
	h       *hub.Hub
	origin  string
	lockAPI string
	host    *http.Client
	ctx     context.Context
	auth    webauthn.AuthenticatorID

	// The interposer between the page and the mobile listener.
	mu      sync.Mutex
	mutate  func(map[string]any) // rewrites a prepare response (nil: none)
	stmt    json.RawMessage      // the last statement the hub prepared
	chal    string               // and its challenge
	decides atomic.Int32         // /decide requests that reached the hub
}

func newEnv(t *testing.T) *env {
	exe := chrome(t)
	dir := t.TempDir()
	_, hubKey, _ := ed25519.GenerateKey(rand.Reader)
	lockPub, lockKey, _ := ed25519.GenerateKey(rand.Reader)
	e := &env{t: t, hubKey: hubKey, lockKey: lockKey}
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	al, err := audit.OpenSigned(filepath.Join(dir, "tickets.jsonl"), hubKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	e.h = hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubKey,
		Locks: map[string]ed25519.PublicKey{inst: lockPub}, Routes: route.Rules{}})

	// The mobile listener, at https://localhost:PORT (a self-signed
	// certificate: Chrome runs with --ignore-certificate-errors).
	msrv := httptest.NewUnstartedServer(nil)
	msrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	port := msrv.Listener.Addr().(*net.TCPAddr).Port
	e.origin = "https://localhost:" + strconv.Itoa(port)
	svc, err := mobile.New(mobile.Config{Hub: e.h, Origin: e.origin, HubKeyID: ticket.KeyID(hubKey.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	msrv.Config.Handler = e.interpose(svc.Handler())
	msrv.StartTLS()
	t.Cleanup(msrv.Close)
	lockAPI := httptest.NewServer(api.LockHandler(e.h, "test"))
	t.Cleanup(lockAPI.Close)
	e.lockAPI = lockAPI.URL

	// The facade socket, for lock mobile pair's side.
	sdir, _ := os.MkdirTemp("", "lhb")
	t.Cleanup(func() { os.RemoveAll(sdir) })
	ln, err := net.Listen("unix", filepath.Join(sdir, "f.sock"))
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: api.FacadeHandler(e.h, svc.FacadeRoutes), ConnContext: peer.ConnContext}
	go fsrv.Serve(ln)
	t.Cleanup(func() { fsrv.Close() })
	e.host = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", filepath.Join(sdir, "f.sock"))
	}}}

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(exe),
		chromedp.Flag("ignore-certificate-errors", true), chromedp.Flag("no-sandbox", os.Getenv("CI") != ""))
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancel)
	ctx, cancel := chromedp.NewContext(actx)
	t.Cleanup(cancel)
	ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
	t.Cleanup(cancel)
	e.ctx = ctx
	if err := chromedp.Do(ctx, chromedp.Navigate(e.origin+"/#pair")); err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error {
			_, err := chromedp.Call(ctx, emulation.SetFocusEmulationEnabled, emulation.SetFocusEmulationEnabledParams{Enabled: true})
			return err
		},
		func() error { _, err := chromedp.Call(ctx, page.BringToFront, cdp.Empty{}); return err },
		func() error { _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{}); return err },
		func() error {
			r, err := chromedp.Call(ctx, webauthn.AddVirtualAuthenticator, webauthn.AddVirtualAuthenticatorParams{Options: &webauthn.VirtualAuthenticatorOptions{
				Protocol: webauthn.AuthenticatorProtocolCtap2, Transport: webauthn.AuthenticatorTransportInternal, HasResidentKey: true,
				HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true}})
			if err == nil {
				e.auth = r.AuthenticatorID
			}
			return err
		},
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	e.waitFor("page focus", `document.hasFocus() ? "ok" : ""`)
	return e
}

// interpose wraps the mobile listener: it counts the /decide requests that
// reach the hub and lets the test rewrite the hub's prepare responses.
func (e *env) interpose(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/m/v1/tickets/") {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasSuffix(p, "/decide") {
			e.decides.Add(1)
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasSuffix(p, "/prepare") {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		e.mu.Lock()
		mut := e.mutate
		var res map[string]any
		if rec.Code == http.StatusOK && json.Unmarshal(body, &res) == nil {
			e.stmt, _ = json.Marshal(res["statement"])
			e.chal, _ = res["challenge"].(string)
			if mut != nil {
				mut(res)
				body, _ = json.Marshal(res)
			}
		}
		e.mu.Unlock()
		for k, v := range rec.Header() {
			if k != "Content-Length" {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(rec.Code)
		w.Write(body)
	})
}

func (e *env) setMutate(f func(map[string]any)) {
	e.mu.Lock()
	e.mutate = f
	e.mu.Unlock()
}

// lastStatement is the last statement and challenge the hub prepared, as
// the hub sent them.
func (e *env) lastStatement() (json.RawMessage, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stmt, e.chal
}

// call is a request on the facade socket (the host's side).
func (e *env) call(method, path string, in, out any) {
	e.t.Helper()
	if code, b := e.try(method, path, in); code != 200 {
		e.t.Fatalf("%s %s: %d %s", method, path, code, b)
	} else if out != nil {
		json.Unmarshal(b, out)
	}
}

func (e *env) try(method, path string, in any) (int, []byte) {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://lockhub"+path, body)
	resp, err := e.host.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *env) eval(js string) string {
	e.t.Helper()
	s, err := chromedp.Run(e.ctx, chromedp.Evaluate[string](js, chromedp.EvalAwaitPromise))
	if err != nil {
		e.t.Fatalf("%s: %v", js, err)
	}
	return s
}

// waitFor polls a JS condition returning a non-empty string.
func (e *env) waitFor(what, js string) string {
	e.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if s := e.eval(js); s != "" {
			return s
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.t.Fatalf("waiting for %s; status: %q", what, e.eval(`document.getElementById("status").textContent`))
	return ""
}

// open loads the web app at path afresh (a full load: no script of the
// previous page, such as its queue poll, keeps running).
func (e *env) open(path string) {
	e.t.Helper()
	if err := chromedp.Do(e.ctx, chromedp.Navigate("about:blank")); err != nil {
		e.t.Fatal(err)
	}
	if err := chromedp.Do(e.ctx, chromedp.Navigate(e.origin+path)); err != nil {
		e.t.Fatal(err)
	}
	e.waitFor("the app", `document.readyState === "complete" && !(document.getElementById("pair").hidden && document.getElementById("login").hidden && document.getElementById("queue").hidden) ? "ok" : ""`)
}

// focus gives the page DevTools focus again (headless Chrome refuses
// WebAuthn to a page without focus).
func (e *env) focus() {
	chromedp.Call(e.ctx, page.BringToFront, cdp.Empty{})
	chromedp.Call(e.ctx, emulation.SetFocusEmulationEnabled, emulation.SetFocusEmulationEnabledParams{Enabled: true})
	time.Sleep(200 * time.Millisecond)
}

const noFocus = "does not have focus"

// act runs js inside an evaluation that waits for until (the page has
// focus while it runs) and returns its value; on a focus refusal of the
// headless browser it returns "".
func (e *env) act(what, js, until string) string {
	e.t.Helper()
	e.focus()
	s := e.eval(`new Promise((ok) => { ` + js + `; const st = document.getElementById("status"); let n = 0;
		const i = setInterval(() => { const v = (` + until + `); const f = st.textContent.includes("` + noFocus + `");
		if (v || f || ++n > 300) { clearInterval(i); ok(v || (f ? "" : "timeout; status: " + st.textContent)); } }, 100); })`)
	if strings.HasPrefix(s, "timeout") {
		e.t.Fatalf("%s: %s", what, s)
	}
	return s
}

func (e *env) retry(what string, f func() string) string {
	e.t.Helper()
	for i := 0; i < 8; i++ {
		if s := f(); s != "" {
			return s
		}
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
		e.clearStatus()
	}
	e.t.Fatalf("%s: the headless browser kept refusing focus (visibility %s, hasFocus %s)", what,
		e.eval(`document.visibilityState`), e.eval(`String(document.hasFocus())`))
	return ""
}

func (e *env) clearStatus() {
	e.eval(`(() => { document.getElementById("status").textContent = ""; return ""; })()`)
}

func (e *env) status() string { return e.eval(`document.getElementById("status").textContent`) }

// pair runs lock mobile pair --name name and types its code into the page
// (a new code per attempt: one is used once); it returns the pairing, in
// the registered state, and checks the page's fingerprint is the
// terminal's.
func (e *env) pair(name string) (id, fp string) {
	e.t.Helper()
	e.open("/#pair")
	var start mobile.PairStartResult
	pageFP := e.retry("pairing "+name, func() string {
		if start.ID != "" {
			e.call("POST", "/v1/mobile/pairings/"+start.ID+"/confirm", mobile.PairConfirm{Confirm: false}, nil)
		}
		e.call("POST", "/v1/mobile/pairings", mobile.PairStart{Name: name}, &start)
		return e.act("pairing", `document.getElementById("pair-done").hidden = true; document.getElementById("code").value = `+jsString(start.Code)+`; document.getElementById("pair-form").requestSubmit()`,
			`document.getElementById("pair-done").hidden ? "" : document.getElementById("fp").textContent`)
	})
	var ps mobile.PairStateResult
	e.call("GET", "/v1/mobile/pairings/"+start.ID, nil, &ps)
	if ps.State != "registered" || ps.Fingerprint != pageFP {
		e.t.Fatalf("pairing %s: terminal state %q fingerprint %q, page %q", name, ps.State, ps.Fingerprint, pageFP)
	}
	if got := e.idb("pending"); got != name {
		e.t.Fatalf("pairing %s: the page's pending pairing is %q", name, got)
	}
	return start.ID, ps.Fingerprint
}

// confirm answers y at the terminal; it returns the confirmed device.
func (e *env) confirm(id, fp string) ticket.Device {
	e.t.Helper()
	var conf mobile.PairConfirmResult
	e.call("POST", "/v1/mobile/pairings/"+id+"/confirm", mobile.PairConfirm{Confirm: true, Fingerprint: fp}, &conf)
	devs, err := ticket.ParseDevices([]byte(`{"devices":[` + string(conf.Record) + `],"v":1}`))
	if err != nil {
		e.t.Fatal(err)
	}
	return devs[0]
}

// decline answers n at the terminal.
func (e *env) decline(id string) {
	e.t.Helper()
	var ps mobile.PairStateResult
	e.call("POST", "/v1/mobile/pairings/"+id+"/confirm", mobile.PairConfirm{Confirm: false}, &ps)
	if ps.State != "refused" {
		e.t.Fatalf("declined pairing: %q", ps.State)
	}
}

// devices is lock mobile devices.
func (e *env) devices() []mobile.DeviceInfo {
	e.t.Helper()
	var ds []mobile.DeviceInfo
	e.call("GET", "/v1/mobile/devices", nil, &ds)
	return ds
}

// idb is the name of the device record the page keeps under key in
// IndexedDB ("device" or "pending"), or "".
func (e *env) idb(key string) string {
	e.t.Helper()
	return e.eval(`new Promise((ok, ko) => { const r = indexedDB.open("lockhub", 1);
		r.onupgradeneeded = () => r.result.createObjectStore("keys");
		r.onerror = () => ko(r.error);
		r.onsuccess = () => { const g = r.result.transaction("keys").objectStore("keys").get(` + jsString(key) + `);
			g.onsuccess = () => ok(g.result ? g.result.rec.name : ""); g.onerror = () => ko(g.error); }; })`)
}

// signIn presses the sign-in button of a fresh, signed-out page and
// returns who signed in and the status once the queue shows. An attempt
// a focus refusal spoiled (the page may have fallen back to the older
// device) is signed out and started again.
func (e *env) signIn() (who, status string) {
	e.t.Helper()
	s := e.retry("sign-in", func() string {
		e.open("/")
		if e.eval(`document.getElementById("queue").hidden ? "" : "signed in"`) != "" {
			e.signOut()
		}
		e.waitFor("the sign-in button", `document.getElementById("login").hidden ? "" : "ok"`)
		return e.act("sign-in", `document.getElementById("login-btn").click()`,
			`document.getElementById("queue").hidden || !document.getElementById("who").textContent || document.getElementById("status").textContent.includes("`+noFocus+`") ? "" : document.getElementById("who").textContent + "|" + document.getElementById("status").textContent`)
	})
	who, status, _ = strings.Cut(s, "|")
	return who, status
}

// signOut presses the page's sign-out button, then loads the page afresh
// (its queue poll would see the ended session later).
func (e *env) signOut() {
	e.t.Helper()
	e.waitFor("the queue", `document.getElementById("queue").hidden ? "" : "ok"`)
	e.eval(`(() => { document.getElementById("logout").click(); return ""; })()`)
	e.waitFor("signed out", `document.getElementById("login").hidden ? "" : "ok"`)
	e.open("/")
}

// signCount is the virtual authenticator's total signature count: it
// moves with every assertion the page gets.
func (e *env) signCount() float64 {
	e.t.Helper()
	r, err := chromedp.Call(e.ctx, webauthn.GetCredentials, webauthn.GetCredentialsParams{AuthenticatorID: e.auth})
	if err != nil {
		e.t.Fatal(err)
	}
	n := 0.0
	for _, c := range r.Credentials {
		n += c.SignCount
	}
	return n
}

// lock is a lockkit lock pinning devs (none: a lock without devices).
type lock struct {
	c      *hubclient.Client
	st     *plans.Store
	caller plans.Caller
}

func (e *env) lock(devs ...ticket.Device) *lock {
	e.t.Helper()
	pst, err := plans.Open(filepath.Join(e.t.TempDir(), "plans"))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { pst.Close() })
	cfg := hubclient.Config{URL: e.lockAPI, Instance: inst, Key: e.lockKey, HubKey: e.hubKey.Public().(ed25519.PublicKey),
		StateFile: filepath.Join(e.t.TempDir(), "state.json")}
	if len(devs) > 0 {
		cfg.Devices, cfg.SealClear, cfg.RequireDevice = devs, true, []ticket.Risk{ticket.RiskWrite}
	}
	lc, err := hubclient.New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return &lock{c: lc, st: pst, caller: plans.Caller{UID: 1000, Token: "tok"}}
}

// newPlan is a plan of the lock's, bound to its ticket.
func (l *lock) newPlan(t *testing.T) (*plans.Plan, *ticket.Ticket) {
	t.Helper()
	hash, _ := ticket.HashOf("plan")
	fp, _ := ticket.HashOf("policy")
	p, err := l.st.Create(plans.Binding{UID: 1000, Agent: "dev-1", TokenHash: plans.HashToken("tok"), PolicyFP: fp, PlanHash: hash}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, ticket.RiskWrite, hash, fp, time.Now(), ticket.ClampTTL(ticket.RiskWrite, 0))
	tk.Requester = ticket.Requester{Agent: "dev-1", Session: "s"}
	return p, tk
}

// run polls the hub and begins the plan of ticket id.
func (l *lock) run(t *testing.T, id string) (*plans.Plan, *ticket.Decision, error) {
	t.Helper()
	if _, err := l.c.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	return l.c.Begin(l.st, id, l.caller, func(p *plans.Plan) (string, string, error) { return p.Binding.PolicyFP, p.Binding.PlanHash, nil })
}

// ticketState is the hub's state of ticket id.
func (e *env) ticketState(id string) string {
	e.t.Helper()
	var tk store.Ticket
	err := e.h.Store().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		tk, err = tx.Ticket(store.Ref{Instance: inst, ID: id})
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return string(tk.State)
}

func jsString(s string) string { b, _ := json.Marshal(s); return string(b) }
