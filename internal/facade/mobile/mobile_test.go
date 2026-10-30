package mobile_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
	"github.com/DavidGodefroid/lockhub/internal/facade/mobile/mobiletest"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

func status(err error) int {
	var e *mobiletest.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestNewRefusesBadOrigins(t *testing.T) {
	e := newEnv(t, route.Rules{})
	for _, o := range []string{"http://hub.example.net", "https://hub.example.net/", "https://hub.example.net:443",
		"https://Hub.example.net", "https://hub.example.net/app", ""} {
		if _, err := mobile.New(mobile.Config{Hub: e.hub, Origin: o}); err == nil {
			t.Errorf("origin %q accepted", o)
		}
	}
}

func TestPostNeedsOriginAndHeader(t *testing.T) {
	e := newEnv(t, route.Rules{})
	for name, mod := range map[string]func(*http.Request){
		"no origin":    func(r *http.Request) { r.Header.Del("Origin") },
		"other origin": func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.net") },
		"no header":    func(r *http.Request) { r.Header.Del(mobile.CSRFHeader) },
		"form":         func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	} {
		req, _ := http.NewRequest("POST", e.mobile.URL+"/m/v1/login/begin", strings.NewReader("{}"))
		req.Header.Set("Origin", origin)
		req.Header.Set(mobile.CSRFHeader, "1")
		req.Header.Set("Content-Type", "application/json")
		mod(req)
		resp, err := e.mobile.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
}

func TestStaticAndHeaders(t *testing.T) {
	e := newEnv(t, route.Rules{})
	for _, p := range []string{"/", "/app.js", "/sw.js", "/manifest.webmanifest"} {
		resp, err := e.mobile.Client().Get(e.mobile.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if resp.StatusCode != 200 || len(b) == 0 || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") ||
			resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: %d csp %q", p, resp.StatusCode, csp)
		}
	}
	// Neither the lock API nor the facade API is on this listener.
	for _, p := range []string{"/v1/hello", "/v1/queue", "/v1/decisions", "/v1/mobile/pairings", "/v1/mobile/devices"} {
		resp, err := e.mobile.Client().Get(e.mobile.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s served on the mobile listener: %d", p, resp.StatusCode)
		}
	}
}

func TestNeedsSession(t *testing.T) {
	e := newEnv(t, route.Rules{})
	p := e.phone("phone")
	if _, err := p.Queue(); status(err) != http.StatusUnauthorized {
		t.Fatalf("queue without a session: %v", err)
	}
	if err := p.Login(); status(err) != http.StatusForbidden {
		t.Fatalf("login with no device paired: %v", err)
	}
}

func TestPairingRefusals(t *testing.T) {
	e := newEnv(t, route.Rules{})
	var start mobile.PairStartResult
	e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "phone"}, &start)
	p := e.phone("phone")
	// Wrong codes: after PairingAttempts, every open pairing ends.
	for i := 0; i < mobile.PairingAttempts; i++ {
		if _, err := p.Pair("WRONGCOD"); status(err) != http.StatusForbidden {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if _, err := p.Pair(start.Code); status(err) != http.StatusForbidden {
		t.Fatalf("the right code after too many wrong ones: %v", err)
	}
	var st mobile.PairStateResult
	e.host("GET", "/v1/mobile/pairings/"+start.ID, nil, &st)
	if st.State == "waiting" || st.State == "registered" {
		t.Fatalf("pairing still open: %s", st.State)
	}

	// A registration without user verification is refused.
	e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "phone"}, &start)
	var begin struct {
		Pairing string         `json:"pairing"`
		Options map[string]any `json:"options"`
	}
	if err := p.Do("POST", "/m/v1/pair/begin", mobile.PairBegin{Code: start.Code}, &begin); err != nil {
		t.Fatal(err)
	}
	cred := p.Registration(begin.Options, 0x41, origin) // UP|AT, no UV
	err := p.Do("POST", "/m/v1/pair/finish", mobile.PairFinish{Pairing: begin.Pairing, Credential: cred,
		X25519: b64(p.Auth.Seal.PublicKey().Bytes())}, nil)
	if status(err) != http.StatusBadRequest {
		t.Fatalf("registration without UV: %v", err)
	}
	// From another origin.
	e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "phone"}, &start)
	p.Do("POST", "/m/v1/pair/begin", mobile.PairBegin{Code: start.Code}, &begin)
	cred = p.Registration(begin.Options, 0x45, "https://evil.example.net")
	err = p.Do("POST", "/m/v1/pair/finish", mobile.PairFinish{Pairing: begin.Pairing, Credential: cred,
		X25519: b64(p.Auth.Seal.PublicKey().Bytes())}, nil)
	if status(err) != http.StatusBadRequest {
		t.Fatalf("registration from another origin: %v", err)
	}

	// Registered, but the terminal shows another fingerprint: refused,
	// nothing stored.
	e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "phone"}, &start)
	if _, err := p.Pair(start.Code); err != nil {
		t.Fatal(err)
	}
	var res mobile.PairStateResult
	e.host("POST", "/v1/mobile/pairings/"+start.ID+"/confirm", mobile.PairConfirm{Confirm: true, Fingerprint: "0000 0000"}, &res)
	if res.State != "refused" {
		t.Fatalf("confirm with another fingerprint: %+v", res)
	}
	var devs []mobile.DeviceInfo
	e.host("GET", "/v1/mobile/devices", nil, &devs)
	if len(devs) != 0 {
		t.Fatalf("a refused device was stored: %+v", devs)
	}
}

func TestSessionAndDrafts(t *testing.T) {
	e := newEnv(t, route.Rules{})
	phone := e.phone("phone")
	dev := e.pair(phone)
	l := e.lock(dev)
	if err := phone.Login(); err != nil {
		t.Fatal(err)
	}
	_, id1 := l.submit(t, ticket.RiskWrite, false, "UPDATE a")
	_, id2 := l.submit(t, ticket.RiskWrite, false, "UPDATE b")
	it1, it2 := item(t, phone, id1), item(t, phone, id2)

	// A draft is single use and bound to its ticket.
	pr, err := phone.Prepare(it1, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := phone.Decide(it2, pr.Draft, pr.Challenge, ""); status(err) != http.StatusForbidden {
		t.Fatalf("draft of another ticket: %v", err)
	}
	if err := phone.Decide(it1, pr.Draft, pr.Challenge, ""); status(err) != http.StatusForbidden {
		t.Fatalf("draft used twice: %v", err)
	}
	// An assertion over another challenge than the draft's.
	pr, _ = phone.Prepare(it1, true, "")
	if err := phone.Decide(it1, pr.Draft, []byte("not the challenge, but 32 bytes."), ""); status(err) != http.StatusForbidden {
		t.Fatalf("assertion over another challenge: %v", err)
	}
	// The statement the hub asks to sign is checked by the phone.
	pr, _ = phone.Prepare(it1, true, "ok")
	if _, err := phone.Check(it1, pr.Statement, false, "ok"); err == nil {
		t.Fatal("the phone signed a denial for an approval")
	}
	if _, err := phone.Check(it2, pr.Statement, true, "ok"); err == nil {
		t.Fatal("the phone signed for another ticket")
	}
	// A cloned authenticator (counter going back) is refused.
	phone.Auth.Counter = 0
	if err := phone.Answer(it1, true, "", ""); status(err) != http.StatusForbidden {
		t.Fatalf("counter going back: %v", err)
	}
	phone.Auth.Counter = 1000
	if err := phone.Answer(it1, true, "", ""); err != nil {
		t.Fatal(err)
	}

	// Revoked: the session ends, sign-in is refused.
	if c := e.host("POST", "/v1/mobile/devices/"+dev.ID+"/revoke", struct{}{}, nil); c != 200 {
		t.Fatalf("revoke: %d", c)
	}
	if _, err := phone.Queue(); status(err) != http.StatusUnauthorized {
		t.Fatalf("queue after revoke: %v", err)
	}
	if err := phone.Login(); err == nil {
		t.Fatal("a revoked device signed in")
	}
}

// A sign-in signs SHA-256(LoginContext || nonce), computed by the phone:
// never a challenge the hub chose whole (which could be a decision's).
func TestLoginChallengeIsThePhones(t *testing.T) {
	e := newEnv(t, route.Rules{})
	phone := e.phone("phone")
	dev := e.pair(phone)
	l := e.lock(dev)
	_, id := l.submit(t, ticket.RiskWrite, false, "UPDATE x")
	var b mobile.LoginBeginResult
	if err := phone.Do("POST", "/m/v1/login/begin", struct{}{}, &b); err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.RawURLEncoding.DecodeString(b.Nonce)
	// An assertion over the bare nonce (a hub-chosen challenge) is refused.
	a := phone.Auth.Assert(nonce)
	err := phone.Do("POST", "/m/v1/login/finish", mobile.LoginFinish{ID: b.ID,
		Assertion: mobile.Assertion{Device: a.Device, AuthData: a.AuthData, ClientData: a.ClientData, Sig: a.Sig}}, nil)
	if status(err) != http.StatusForbidden {
		t.Fatalf("sign-in over the bare nonce: %v", err)
	}
	// And a sign-in's assertion is no decision: the lock refuses it.
	if err := phone.Do("POST", "/m/v1/login/begin", struct{}{}, &b); err != nil {
		t.Fatal(err)
	}
	nonce, _ = base64.RawURLEncoding.DecodeString(b.Nonce)
	login := phone.Auth.Assert(mobile.LoginChallenge(nonce))
	raw := ticketRaw(t, e, id)
	var tk ticket.Ticket
	json.Unmarshal(raw, &tk)
	d := &ticket.Decision{V: 1, Ticket: tk.ID, Instance: inst, KeyID: tk.Source.KeyID, PlanHash: tk.PlanHash, Decision: ticket.Approved,
		Approver: ticket.Approver{ID: dev.ID, Display: dev.Name}, Facade: ticket.FacadeMobile, At: tk.Created, Nonce: ticket.NewNonce(),
		HubKeyID: ticket.KeyID(e.hubKey.Public().(ed25519.PublicKey)), Device: login}
	if err := ticket.VerifyDevice(&dev, d, raw); err == nil {
		t.Fatal("a sign-in assertion verified as a decision")
	}
}

func TestPairingNameAndCodeOnce(t *testing.T) {
	e := newEnv(t, route.Rules{})
	phone := e.phone("phone")
	e.pair(phone)
	if c := e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "phone"}, nil); c != http.StatusConflict {
		t.Fatalf("a second active device named phone: %d", c)
	}
	var start mobile.PairStartResult
	e.host("POST", "/v1/mobile/pairings", mobile.PairStart{Name: "tablet"}, &start)
	tablet := e.phone("tablet")
	if err := tablet.Do("POST", "/m/v1/pair/begin", mobile.PairBegin{Code: start.Code}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tablet.Do("POST", "/m/v1/pair/begin", mobile.PairBegin{Code: start.Code}, nil); status(err) != http.StatusForbidden {
		t.Fatalf("a code begun twice: %v", err)
	}
}

// Routing on mobile: every risk but unlock; production asks for the
// retype; an instance routed away is not shown.
func TestRouting(t *testing.T) {
	e := newEnv(t, route.Rules{})
	phone := e.phone("phone")
	dev := e.pair(phone)
	l := e.lock(dev)
	phone.Login()
	_, unlock := l.submit(t, ticket.RiskUnlock, false, "unlock")
	it := item(t, phone, unlock)
	if it.Answerable || it.Why == "" {
		t.Fatalf("unlock answerable on mobile: %+v", it)
	}
	if _, err := phone.Prepare(it, true, ""); status(err) != http.StatusForbidden {
		t.Fatalf("prepare of an unlock: %v", err)
	}
	_, prod := l.submit(t, ticket.RiskProdWrite, true, "prod")
	it = item(t, phone, prod)
	if !it.Answerable || !it.Retype {
		t.Fatalf("production on mobile: %+v", it)
	}
	if err := phone.Answer(it, true, "", "wrong"); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("production without the retype: %v", err)
	}
	if err := phone.Answer(it, true, "", inst); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.run(t, prod); err != nil {
		t.Fatalf("production approved on the phone: %v", err)
	}

	e2 := newEnv(t, route.Rules{Only: map[string][]string{inst: {route.TTY}}})
	p2 := e2.phone("phone")
	d2 := e2.pair(p2)
	l2 := e2.lock(d2)
	p2.Login()
	l2.submit(t, ticket.RiskRead, false, "read")
	q, _ := p2.Queue()
	if len(q.Tickets) != 0 {
		t.Fatalf("an instance routed to tty only is shown on mobile: %+v", q.Tickets)
	}
}

// Agent text reaches the phone as data in the lock's JSON, never as
// markup: the web app sets it with textContent only.
func TestAgentTextIsData(t *testing.T) {
	b, err := staticFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(b, bad) {
			t.Errorf("app.js uses %s", bad)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func staticFile(name string) (string, error) {
	b, err := os.ReadFile("static/" + name)
	return string(b), err
}
