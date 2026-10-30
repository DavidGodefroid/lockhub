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
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
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

// The phase-6 exit criterion in a real browser: the web app pairs the
// phone (WebAuthn registration, a non-extractable WebCrypto X25519 key),
// the human confirms the fingerprint the page shows, a real lockkit lock
// seals its clear screen to it, the page opens it with WebCrypto and
// approves with a user-verified assertion, and the lock runs the plan.
func TestWebAppApproves(t *testing.T) {
	exe := chrome(t)
	dir := t.TempDir()
	_, hubKey, _ := ed25519.GenerateKey(rand.Reader)
	lockPub, lockKey, _ := ed25519.GenerateKey(rand.Reader)
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	al, err := audit.OpenSigned(filepath.Join(dir, "tickets.jsonl"), hubKey)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubKey,
		Locks: map[string]ed25519.PublicKey{inst: lockPub}, Routes: route.Rules{}})

	// The mobile listener, at https://localhost:PORT (a self-signed
	// certificate: Chrome runs with --ignore-certificate-errors).
	msrv := httptest.NewUnstartedServer(nil)
	msrv.Config.ErrorLog = log.New(io.Discard, "", 0)
	port := msrv.Listener.Addr().(*net.TCPAddr).Port
	origin := "https://localhost:" + itoa(port)
	svc, err := mobile.New(mobile.Config{Hub: h, Origin: origin, HubKeyID: ticket.KeyID(hubKey.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	msrv.Config.Handler = svc.Handler()
	msrv.StartTLS()
	defer msrv.Close()
	lockAPI := httptest.NewServer(api.LockHandler(h, "test"))
	defer lockAPI.Close()

	// The facade socket, for lock mobile pair's side.
	sdir, _ := os.MkdirTemp("", "lhb")
	defer os.RemoveAll(sdir)
	ln, err := net.Listen("unix", filepath.Join(sdir, "f.sock"))
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: api.FacadeHandler(h, svc.FacadeRoutes), ConnContext: peer.ConnContext}
	go fsrv.Serve(ln)
	defer fsrv.Close()
	host := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", filepath.Join(sdir, "f.sock"))
	}}}
	call := func(method, path string, in, out any) {
		t.Helper()
		var body io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			body = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, "http://lockhub"+path, body)
		resp, err := host.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
		}
		if out != nil {
			json.Unmarshal(b, out)
		}
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(exe),
		chromedp.Flag("ignore-certificate-errors", true), chromedp.Flag("no-sandbox", os.Getenv("CI") != ""))
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(actx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Navigate(origin+"/#pair")); err != nil {
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
			_, err := chromedp.Call(ctx, webauthn.AddVirtualAuthenticator, webauthn.AddVirtualAuthenticatorParams{Options: &webauthn.VirtualAuthenticatorOptions{
				Protocol: webauthn.AuthenticatorProtocolCtap2, Transport: webauthn.AuthenticatorTransportInternal, HasResidentKey: true,
				HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true}})
			return err
		},
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	eval := func(js string) string {
		t.Helper()
		s, err := chromedp.Run(ctx, chromedp.Evaluate[string](js, chromedp.EvalAwaitPromise))
		if err != nil {
			t.Fatalf("%s: %v", js, err)
		}
		return s
	}
	// waitFor polls a JS condition returning a non-empty string.
	waitFor := func(what, js string) string {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if s := eval(js); s != "" {
				return s
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("waiting for %s; status: %q", what, eval(`document.getElementById("status").textContent`))
		return ""
	}

	waitFor("page focus", `document.hasFocus() ? "ok" : ""`)

	// Pairing: lock mobile pair's code, typed into the page.
	var start mobile.PairStartResult
	call("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "phone"}, &start)
	// Actions run inside an evaluation that waits for their outcome (the
	// page has DevTools focus while one runs).
	act := func(what, js, until string) string {
		t.Helper()
		s := eval(`new Promise((ok) => { ` + js + `; const st = document.getElementById("status"); let n = 0;
			const i = setInterval(() => { const v = (` + until + `); if (v || ++n > 300) { clearInterval(i); ok(v || ("timeout; status: " + st.textContent)); } }, 100); })`)
		if strings.HasPrefix(s, "timeout") {
			t.Fatalf("%s: %s", what, s)
		}
		return s
	}
	pageFP := act("pairing", `document.getElementById("code").value = `+jsString(start.Code)+`; document.getElementById("pair-form").requestSubmit()`,
		`document.getElementById("pair-done").hidden ? "" : document.getElementById("fp").textContent`)
	var ps mobile.PairStateResult
	call("GET", "/v1/mobile/pairings/"+start.ID, nil, &ps)
	if ps.State != "registered" || ps.Fingerprint != pageFP {
		t.Fatalf("terminal fingerprint %q, page %q", ps.Fingerprint, pageFP)
	}
	var conf mobile.PairConfirmResult
	call("POST", "/v1/mobile/pairings/"+start.ID+"/confirm", mobile.PairConfirm{Confirm: true, Fingerprint: ps.Fingerprint}, &conf)
	devs, err := ticket.ParseDevices([]byte(`{"devices":[` + string(conf.Record) + `],"v":1}`))
	if err != nil {
		t.Fatal(err)
	}

	// A lock pinning the phone pushes a ticket with personal data.
	pst, err := plans.Open(filepath.Join(t.TempDir(), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	defer pst.Close()
	lc, err := hubclient.New(hubclient.Config{URL: lockAPI.URL, Instance: inst, Key: lockKey, HubKey: hubKey.Public().(ed25519.PublicKey),
		StateFile: filepath.Join(t.TempDir(), "state.json"), Devices: devs, SealClear: true, RequireDevice: []ticket.Risk{ticket.RiskWrite}})
	if err != nil {
		t.Fatal(err)
	}
	caller := plans.Caller{UID: 1000, Token: "tok"}
	hash, _ := ticket.HashOf("plan")
	fp, _ := ticket.HashOf("policy")
	p, err := pst.Create(plans.Binding{UID: 1000, Agent: "dev-1", TokenHash: plans.HashToken("tok"), PolicyFP: fp, PlanHash: hash}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, ticket.RiskWrite, hash, fp, time.Now(), ticket.ClampTTL(ticket.RiskWrite, 0))
	tk.Requester = ticket.Requester{Agent: `<img src=x onerror="document.title='pwned'">`, Session: "s"}
	masked := render.MaskScreen(render.ScreenSource{Header: "crm / shop · write",
		Body: []render.Line{{{Text: "UPDATE customers SET email = "}, {Text: pii, Value: true, Column: "email", ColumnType: "text"}}}}, render.Masking{})
	clear := &ticket.Screen{Header: "crm / shop · write", Body: []string{"UPDATE customers SET email = '" + pii + "'"}}
	id, err := lc.SubmitClear(context.Background(), pst, p.ID, caller, tk, masked, clear)
	if err != nil {
		t.Fatal(err)
	}

	// The page: sign in, the ticket, its clear values, approve.
	if err := chromedp.Do(ctx, chromedp.Navigate(origin+"/")); err != nil {
		t.Fatal(err)
	}
	waitFor("the sign-in button", `document.getElementById("login").hidden ? "" : "ok"`)
	act("sign-in", `document.getElementById("login-btn").click()`, `document.querySelector(".ticket .approve") ? "ok" : ""`)
	got := waitFor("the clear values", `(() => { const c = document.querySelector(".ticket .clear"); return c && !c.hidden ? c.textContent : ""; })()`)
	if !strings.Contains(got, pii) {
		t.Fatalf("clear values on the page: %q", got)
	}
	if masked := eval(`document.querySelector(".ticket .body").textContent`); strings.Contains(masked, pii) {
		t.Fatalf("the masked screen shows %q", masked)
	}
	if title := eval(`document.title`); title == "pwned" || eval(`String(document.querySelectorAll(".ticket img").length)`) != "0" {
		t.Fatal("agent text was rendered as markup")
	}
	act("approval", `document.querySelector(".ticket .reason").value = "ok from the phone"; document.querySelector(".ticket .approve").click()`,
		`document.getElementById("status").textContent === "Approved." ? "ok" : ""`)

	// The lock runs it: the device's signature verified at the lock.
	if _, err := lc.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	pl, d, err := lc.Begin(pst, id, caller, func(p *plans.Plan) (string, string, error) { return p.Binding.PolicyFP, p.Binding.PlanHash, nil })
	if err != nil || pl.ID != p.ID {
		t.Fatalf("the lock did not run the phone's approval: %v", err)
	}
	if d.Device == nil || d.Reason != "ok from the phone" || d.Approver.ID != devs[0].ID {
		t.Fatalf("decision %+v", d)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func jsString(s string) string { b, _ := json.Marshal(s); return string(b) }
