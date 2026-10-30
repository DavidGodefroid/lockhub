package mobile_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/facade/mobile"
	"github.com/DavidGodefroid/lockhub/internal/facade/mobile/mobiletest"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

func TestCheckEndpoint(t *testing.T) {
	for _, ok := range []string{
		"https://fcm.googleapis.com/fcm/send/abc:APA91b",
		"https://updates.push.services.mozilla.com/wpush/v2/gAAAAAB",
		"https://web.push.apple.com/QGuQyavXutnMH",
		"https://api.push.apple.com/3/device/x",
		"https://wns2-par02p.notify.windows.com/w/?token=BQYAAA",
	} {
		if err := mobile.CheckEndpoint(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"http://fcm.googleapis.com/fcm/send/x", // http
		"https://fcm.googleapis.com:443/fcm/send/x",               // explicit port
		"https://fcm.googleapis.com:8443/fcm/send/x",              // port
		"https://fcm.googleapis.com:/fcm/send/x",                  // empty port
		"https://user@fcm.googleapis.com/fcm/send/x",              // userinfo
		"https://user:pw@fcm.googleapis.com/fcm/send/x",           // userinfo
		"https://fcm.googleapis.com.evil.net/fcm/send/x",          // lookalike
		"https://evilfcm.googleapis.com/fcm/send/x",               // not the host
		"https://x.fcm.googleapis.com/fcm/send/x",                 // not the host
		"https://fcm.googleapis.com./fcm/send/x",                  // trailing dot
		"https://FCM.googleapis.com/fcm/send/x",                   // not as a browser writes it
		"https://evilpush.apple.com/x",                            // suffix without the dot
		"https://push.apple.com/x",                                // no label
		"https://a.b.push.apple.com/x",                            // deeper
		"https://push.apple.com.evil.net/x",                       // lookalike
		"https://evil.notify.windows.com/w/?token=x",              // not wns2-
		"https://wns2-.notify.windows.com/w/?token=x",             // no label after the prefix
		"https://wns2-x.y.notify.windows.com/w/?token=x",          // deeper
		"https://127.0.0.1/x",                                     // IP
		"https://[::1]/x",                                         // IP
		"https://169.254.169.254/latest/meta-data",                // IP
		"https://fcm.googleapis.com",                              // no path
		"https://fcm.googleapis.com/x#frag",                       // fragment
		"https://fcm.googleapis.com\\@evil.net/x",                 // backslash
		"https://fcm.googleapis.com/x y",                          // space
		"ftp://fcm.googleapis.com/x",                              // scheme
		"//fcm.googleapis.com/x",                                  // no scheme
		"https:fcm.googleapis.com/x",                              // opaque
		"https://fcm.googleapis.com/" + strings.Repeat("a", 3000), // too long
	} {
		if err := mobile.CheckEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func newVAPID(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifyVAPID checks an Authorization header against the public key
// (base64url uncompressed point) and returns the JWT's claims.
func verifyVAPID(t *testing.T, authz, pub string) map[string]any {
	t.Helper()
	rest, ok := strings.CutPrefix(authz, "vapid t=")
	if !ok {
		t.Fatalf("authorization %q", authz)
	}
	tok, k, ok := strings.Cut(rest, ", k=")
	if !ok || k != pub {
		t.Fatalf("authorization key %q, want %q", k, pub)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt %q", tok)
	}
	b64 := base64.RawURLEncoding
	hdr, _ := b64.DecodeString(parts[0])
	var h map[string]string
	if json.Unmarshal(hdr, &h) != nil || h["alg"] != "ES256" || h["typ"] != "JWT" {
		t.Fatalf("jwt header %s", hdr)
	}
	raw, err := b64.DecodeString(pub)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	pt := ek.Bytes()
	pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pt[1:33]), Y: new(big.Int).SetBytes(pt[33:])}
	sig, _ := b64.DecodeString(parts[2])
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pk, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the VAPID JWT does not verify with the public key")
	}
	cb, _ := b64.DecodeString(parts[1])
	var c map[string]any
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVAPIDToken(t *testing.T) {
	e := newEnvWith(t, route.Rules{}, newVAPID(t))
	now := time.Now()
	tok, err := mobile.VAPIDToken(e.svc, "https://fcm.googleapis.com", now)
	if err != nil {
		t.Fatal(err)
	}
	c := verifyVAPID(t, "vapid t="+tok+", k="+mobile.VAPIDPublic(e.svc), mobile.VAPIDPublic(e.svc))
	exp := int64(c["exp"].(float64))
	if c["aud"] != "https://fcm.googleapis.com" || c["sub"] != origin || exp <= now.Unix() || exp > now.Add(12*time.Hour).Unix() {
		t.Fatalf("claims %v", c)
	}
}

// pushServer is a push service for tests: it records every request.
type pushServer struct {
	*httptest.Server
	mu     sync.Mutex
	reqs   []*http.Request
	bodies [][]byte
	status int
	got    chan struct{}
}

func newPushServer(t *testing.T) *pushServer {
	ps := &pushServer{status: http.StatusCreated, got: make(chan struct{}, 16)}
	ps.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ps.mu.Lock()
		ps.reqs, ps.bodies = append(ps.reqs, r), append(ps.bodies, b)
		code := ps.status
		ps.mu.Unlock()
		w.WriteHeader(code)
		ps.got <- struct{}{}
	}))
	t.Cleanup(ps.Close)
	return ps
}

func (ps *pushServer) count() int { ps.mu.Lock(); defer ps.mu.Unlock(); return len(ps.reqs) }

func (ps *pushServer) wait(t *testing.T) {
	t.Helper()
	select {
	case <-ps.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no push")
	}
}

// quiet checks that no push comes for a while.
func (ps *pushServer) quiet(t *testing.T, want int) {
	t.Helper()
	time.Sleep(300 * time.Millisecond)
	if n := ps.count(); n != want {
		t.Fatalf("%d pushes, want %d", n, want)
	}
}

// pushEnv is a hub with push on, pushing to ps only (the allowlist is
// the test server's URL), every round at once, and a paired phone signed
// in and subscribed.
func pushEnv(t *testing.T, routes route.Rules) (*env, *pushServer, *mobiletest.Phone, ticket.Device, string) {
	t.Helper()
	e := newEnvWith(t, routes, newVAPID(t))
	ps := newPushServer(t)
	mobile.SetPushTransport(e.svc, ps.Client(), func(raw string) (*url.URL, error) {
		if !strings.HasPrefix(raw, ps.URL+"/") {
			return nil, errors.New("not the test push service")
		}
		return url.Parse(raw)
	}, 0)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.svc.RunPush(ctx)
	p := e.phone("phone")
	dev := e.pair(p)
	if err := p.Login(); err != nil {
		t.Fatal(err)
	}
	endpoint := ps.URL + "/push/sub-secret-1"
	if err := p.Do("POST", "/m/v1/push/subscribe", mobile.PushSubscribe{Endpoint: endpoint}, nil); err != nil {
		t.Fatal(err)
	}
	var info mobile.PushInfo
	if err := p.Do("GET", "/m/v1/push", nil, &info); err != nil || info.Key != mobile.VAPIDPublic(e.svc) || info.Subscriptions != 1 {
		t.Fatalf("push info %+v %v", info, err)
	}
	return e, ps, p, dev, endpoint
}

func TestPendingTicketPushesOnceWithoutPayload(t *testing.T) {
	e, ps, _, dev, _ := pushEnv(t, route.Rules{})
	l := e.lock(dev)
	_, id := l.submit(t, ticket.RiskWrite, false, "UPDATE customers")
	ps.wait(t)
	ps.quiet(t, 1)
	ps.mu.Lock()
	r, body := ps.reqs[0], ps.bodies[0]
	ps.mu.Unlock()
	if r.Method != http.MethodPost || len(body) != 0 || r.ContentLength > 0 || r.URL.Path != "/push/sub-secret-1" || r.URL.RawQuery != "" {
		t.Fatalf("push %s %s (%d bytes body, content-length %d)", r.Method, r.URL, len(body), r.ContentLength)
	}
	if r.Header.Get("TTL") == "" || r.Header.Get("Urgency") != "high" || r.Header.Get("Topic") != mobile.PushTopic || r.Header.Get("Content-Encoding") != "" {
		t.Fatalf("headers %v", r.Header)
	}
	c := verifyVAPID(t, r.Header.Get("Authorization"), mobile.VAPIDPublic(e.svc))
	if c["aud"] != ps.URL {
		t.Fatalf("aud %v, want %s", c["aud"], ps.URL)
	}
	// Nothing of the ticket reaches the push service.
	var all bytes.Buffer
	r.Header.Write(&all)
	all.WriteString(r.URL.String())
	for _, secret := range []string{id, inst, pii, "UPDATE", "customers", "dev-1"} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("the push carries %q:\n%s", secret, all.String())
		}
	}
}

func TestTicketRoutedAwayFromMobileDoesNotPush(t *testing.T) {
	e, ps, _, dev, _ := pushEnv(t, route.Rules{Only: map[string][]string{inst: {route.TTY}}})
	l := e.lock(dev)
	l.submit(t, ticket.RiskWrite, false, "UPDATE customers")
	ps.quiet(t, 0)
	// Unlock is never answered on mobile either.
	e2, ps2, _, dev2, _ := pushEnv(t, route.Rules{})
	e2.lock(dev2).submit(t, ticket.RiskUnlock, false, "unlock")
	ps2.quiet(t, 0)
}

func TestPushGoneRemovesSubscription(t *testing.T) {
	e, ps, _, dev, _ := pushEnv(t, route.Rules{})
	ps.mu.Lock()
	ps.status = http.StatusGone
	ps.mu.Unlock()
	l := e.lock(dev)
	l.submit(t, ticket.RiskWrite, false, "UPDATE a")
	ps.wait(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		subs, err := e.hub.Store().PushSubscriptions(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		if len(subs) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("410: the subscription is still there")
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.submit(t, ticket.RiskWrite, false, "UPDATE b")
	ps.quiet(t, 1)
}

func TestRevokeDropsSubscriptionsAndStopsPushes(t *testing.T) {
	e, ps, _, dev, endpoint := pushEnv(t, route.Rules{})
	if c := e.host("POST", "/v1/mobile/devices/"+dev.ID+"/revoke", struct{}{}, nil); c != 200 {
		t.Fatalf("revoke: %d", c)
	}
	ctx := context.Background()
	if subs, _ := e.hub.Store().PushSubscriptions(ctx, ""); len(subs) != 0 {
		t.Fatalf("subscriptions after revoke: %v", subs)
	}
	// A revoked device cannot subscribe again, even straight in the store.
	if err := e.hub.Store().PutPushSubscription(ctx, dev.ID, endpoint, 4, time.Now()); err == nil {
		t.Fatal("a revoked device subscribed")
	}
	l := e.lock(dev)
	l.submit(t, ticket.RiskWrite, false, "UPDATE customers")
	mobile.PushAll(ctx, e.svc)
	ps.quiet(t, 0)
}

func TestPushSubscribeGuards(t *testing.T) {
	e, _, p, _, _ := pushEnv(t, route.Rules{})
	body := `{"endpoint":"` + "https://fcm.googleapis.com/fcm/send/x" + `"}`
	send := func(c *http.Client, hdr map[string]string) int {
		req, _ := http.NewRequest("POST", e.mobile.URL+"/m/v1/push/subscribe", strings.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	all := map[string]string{"Content-Type": "application/json", "Origin": origin, mobile.CSRFHeader: "1"}
	without := func(k string) map[string]string {
		m := map[string]string{}
		for kk, v := range all {
			if kk != k {
				m[kk] = v
			}
		}
		return m
	}
	if c := send(e.mobile.Client(), all); c != http.StatusUnauthorized {
		t.Errorf("no session: %d", c)
	}
	if c := send(p.HTTP, without("Origin")); c != http.StatusForbidden {
		t.Errorf("no Origin: %d", c)
	}
	if c := send(p.HTTP, map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example", mobile.CSRFHeader: "1"}); c != http.StatusForbidden {
		t.Errorf("other Origin: %d", c)
	}
	if c := send(p.HTTP, without(mobile.CSRFHeader)); c != http.StatusForbidden {
		t.Errorf("no custom header: %d", c)
	}
	// The real allowlist was replaced by the test server's: a real push
	// service's endpoint is refused here, as any other host would be.
	if c := send(p.HTTP, all); c != http.StatusBadRequest {
		t.Errorf("endpoint off the allowlist: %d", c)
	}
	if err := p.Do("GET", "/m/v1/push", nil, nil); err != nil {
		t.Errorf("push info with a session: %v", err)
	}
	// Unsubscribe drops it.
	subs, _ := e.hub.Store().PushSubscriptions(context.Background(), "")
	if len(subs) != 1 {
		t.Fatalf("subs %v", subs)
	}
	if err := p.Do("POST", "/m/v1/push/unsubscribe", mobile.PushSubscribe{Endpoint: subs[0].Endpoint}, nil); err != nil {
		t.Fatal(err)
	}
	if subs, _ := e.hub.Store().PushSubscriptions(context.Background(), ""); len(subs) != 0 {
		t.Fatalf("after unsubscribe: %v", subs)
	}
}

func TestPushOffServesNoPushAPI(t *testing.T) {
	e := newEnv(t, route.Rules{})
	p := e.phone("phone")
	e.pair(p)
	if err := p.Login(); err != nil {
		t.Fatal(err)
	}
	if err := p.Do("GET", "/m/v1/push", nil, nil); status(err) != http.StatusNotFound {
		t.Errorf("push info without push: %v", err)
	}
	if err := p.Do("POST", "/m/v1/push/subscribe", mobile.PushSubscribe{Endpoint: "https://fcm.googleapis.com/fcm/send/x"}, nil); status(err) != http.StatusNotFound && status(err) != http.StatusMethodNotAllowed {
		t.Errorf("subscribe without push: %v", err)
	}
	e.svc.RunPush(context.Background()) // returns at once
}

func TestSubscriptionsPerDeviceAreCapped(t *testing.T) {
	e, ps, p, _, _ := pushEnv(t, route.Rules{})
	for i := range mobile.MaxPushSubscriptions + 2 {
		if err := p.Do("POST", "/m/v1/push/subscribe", mobile.PushSubscribe{Endpoint: ps.URL + "/push/" + string(rune('a'+i))}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if subs, _ := e.hub.Store().PushSubscriptions(context.Background(), ""); len(subs) != mobile.MaxPushSubscriptions {
		t.Fatalf("%d subscriptions, want %d", len(subs), mobile.MaxPushSubscriptions)
	}
}
