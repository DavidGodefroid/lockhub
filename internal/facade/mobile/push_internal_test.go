package mobile

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"142.250.74.106", "63.245.208.195", "17.188.128.1", "2a00:1450:4007:80e::200a", "2620:149:a44::1"} {
		if !publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.1.2.3", "0.0.0.0",
		"100.64.0.1", "100.127.255.254", "198.18.0.1", "198.19.255.254", "240.0.0.1", "255.255.255.255",
		"192.0.0.8", "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
		"::1", "::", "fe80::1", "fc00::1", "fd12::1", "fec0::1", "ff02::1",
		"64:ff9b::7f00:1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1",
		"2002:7f00:1::1", "3fff::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:0:a00:1",
	} {
		if publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s accepted", s)
		}
	}
}

// The production client refuses, at dial time, an allowed push host that
// resolves to a non-public address (here: DNS answering 127.0.0.1).
func TestPushClientRefusesNonPublicAddress(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := pushClient()
	tr := c.Transport.(*http.Transport)
	dial := tr.DialContext // the production dialer, with its address check
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, srv.Listener.Addr().String()) // fcm.googleapis.com "resolves" to the test server
	}
	if _, err := checkEndpoint("https://fcm.googleapis.com/fcm/send/x"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://fcm.googleapis.com/fcm/send/x", http.NoBody)
	_, err := c.Do(req)
	if err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("dialed a loopback address: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the request reached the server")
	}
}

// The production client follows no redirect.
func TestPushClientFollowsNoRedirect(t *testing.T) {
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) { followed.Add(1) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	c := pushClient()
	c.Transport = srv.Client().Transport // reach the loopback test server; the redirect policy is the client's
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/push", http.NoBody)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || followed.Load() != 0 {
		t.Fatalf("status %d, followed %d", resp.StatusCode, followed.Load())
	}
}
