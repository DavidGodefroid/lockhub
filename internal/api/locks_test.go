package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

type client struct {
	t    *testing.T
	srv  *httptest.Server
	lock hubtest.Lock
	now  func() time.Time
}

func (c client) do(method, path string, body []byte, mutate func(*http.Request)) (int, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, bytes.NewReader(body))
	c.lock.Sign(req, body, c.now())
	if mutate != nil {
		mutate(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func setup(t *testing.T) (hubtest.Env, *httptest.Server, client, client) {
	a, b := hubtest.NewLock("a"), hubtest.NewLock("b")
	e := hubtest.New(t, 0, a, b)
	srv := httptest.NewServer(api.LockHandler(e.Hub, "test"))
	t.Cleanup(srv.Close)
	return e, srv, client{t, srv, a, e.Clock.Now}, client{t, srv, b, e.Clock.Now}
}

func TestEndToEnd(t *testing.T) {
	e, _, ca, cb := setup(t)
	tk := ca.lock.Ticket("T1", "write", e.Clock.T, 24*time.Hour)

	if code, body := ca.do("POST", "/v1/tickets", tk, nil); code != http.StatusCreated {
		t.Fatalf("push: %d %s", code, body)
	}
	if code, _ := ca.do("POST", "/v1/tickets", tk, nil); code != http.StatusOK {
		t.Fatalf("re-push: %d (want 200, idempotent)", code)
	}

	// A lock waits for its decision while a human decides.
	type res struct {
		code int
		body []byte
	}
	done := make(chan res, 1)
	go func() {
		code, body := ca.do("GET", "/v1/decisions?since=0&wait=10", nil, nil)
		done <- res{code, body}
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := e.Hub.Decide(context.Background(), store.Ref{Instance: "a", ID: "T1"}, hub.Verdict{Approved: true, ApproverID: "host:u", Facade: "tty"}); err != nil {
		t.Fatal(err)
	}
	r := <-done
	var dr api.DecisionsResult
	if err := json.Unmarshal(r.body, &dr); r.code != 200 || err != nil || len(dr.Decisions) != 1 || dr.Cursor != dr.Decisions[0].Seq {
		t.Fatalf("decisions: %d %s", r.code, r.body)
	}
	var dec hubtest.Decision
	json.Unmarshal(dr.Decisions[0].Decision, &dec)
	if !dec.Approved || dec.Ticket != "T1" {
		t.Errorf("decision %+v", dec)
	}

	// b sees nothing of a's.
	if code, body := cb.do("GET", "/v1/decisions", nil, nil); code != 200 || !bytes.Contains(body, []byte(`"decisions":[]`)) {
		t.Errorf("b decisions: %d %s", code, body)
	}
	if code, _ := cb.do("POST", "/v1/tickets/T1/consumed", nil, nil); code != http.StatusNotFound {
		t.Errorf("b consumed a's ticket: %d", code)
	}
	if code, _ := ca.do("POST", "/v1/tickets/T1/consumed", nil, nil); code != http.StatusNoContent {
		t.Errorf("consumed: %d", code)
	}
	if code, _ := ca.do("POST", "/v1/tickets/T1/consumed", nil, nil); code != http.StatusConflict {
		t.Errorf("consumed twice: %d", code)
	}
}

func TestWithdraw(t *testing.T) {
	e, _, ca, _ := setup(t)
	ca.do("POST", "/v1/tickets", ca.lock.Ticket("W", "read", e.Clock.T, 0), nil)
	if code, body := ca.do("POST", "/v1/tickets/W/withdraw", []byte(`{"reason":"plan stale"}`), nil); code != http.StatusNoContent {
		t.Fatalf("withdraw: %d %s", code, body)
	}
	if code, _ := ca.do("POST", "/v1/tickets/W/withdraw", nil, nil); code != http.StatusConflict {
		t.Errorf("withdraw twice: %d", code)
	}
	if code, _ := ca.do("POST", "/v1/tickets/nope/withdraw", nil, nil); code != http.StatusNotFound {
		t.Errorf("unknown: %d", code)
	}
}

func TestAuthRefusals(t *testing.T) {
	e, srv, ca, cb := setup(t)
	tk := ca.lock.Ticket("T", "read", e.Clock.T, 0)
	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"no headers", func(r *http.Request) { r.Header = http.Header{} }, 401},
		{"bad signature", func(r *http.Request) { r.Header.Set("Lock-Sig", "AAAA") }, 401},
		{"other instance header", func(r *http.Request) { r.Header.Set("Lock-Instance", "b") }, 401},
		{"unknown instance", func(r *http.Request) { r.Header.Set("Lock-Instance", "zz") }, 401},
		{"short nonce", func(r *http.Request) { r.Header.Set("Lock-Nonce", "ab") }, 401},
	}
	for _, c := range cases {
		if code, body := ca.do("POST", "/v1/tickets", tk, c.mutate); code != c.want {
			t.Errorf("%s: %d %s", c.name, code, body)
		}
	}
	// Body changed after signing.
	req, _ := http.NewRequest("POST", srv.URL+"/v1/tickets", bytes.NewReader(tk))
	ca.lock.Sign(req, []byte("other"), e.Clock.T)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("tampered body: %d", resp.StatusCode)
	}
	// Replay of a whole signed request.
	req, _ = http.NewRequest("GET", srv.URL+"/v1/decisions", nil)
	ca.lock.Sign(req, nil, e.Clock.T)
	h := req.Header.Clone()
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Fatalf("first: %d", resp.StatusCode)
	}
	req2, _ := http.NewRequest("GET", srv.URL+"/v1/decisions", nil)
	req2.Header = h
	if resp, _ := http.DefaultClient.Do(req2); resp.StatusCode != 401 {
		t.Errorf("replay: %d", resp.StatusCode)
	}
	// Clock skew.
	skewed := client{t, srv, ca.lock, func() time.Time { return e.Clock.T.Add(-2 * time.Minute) }}
	if code, _ := skewed.do("GET", "/v1/decisions", nil, nil); code != 401 {
		t.Errorf("skew: %d", code)
	}
	// A valid request of b cannot push a's ticket.
	if code, _ := cb.do("POST", "/v1/tickets", tk, nil); code != http.StatusBadRequest {
		t.Errorf("b pushes a's ticket: %d", code)
	}
}

func TestBadQueryAndBody(t *testing.T) {
	_, _, ca, _ := setup(t)
	if code, _ := ca.do("GET", "/v1/decisions?since=-1", nil, nil); code != 400 {
		t.Errorf("since=-1: %d", code)
	}
	if code, _ := ca.do("GET", "/v1/decisions?wait=x", nil, nil); code != 400 {
		t.Errorf("wait=x: %d", code)
	}
	big := bytes.Repeat([]byte("x"), api.MaxBody+1)
	if code, _ := ca.do("POST", "/v1/tickets", big, nil); code != http.StatusRequestEntityTooLarge {
		t.Errorf("big body: %d", code)
	}
}
