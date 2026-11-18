package loxlive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// lox run (shared) and lox live (exclusive) never serve one workspace
// together; several lox run may, as before; the lock goes with its
// holder.
func TestServeLock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	run1, err := Acquire(state, Run)
	if err != nil {
		t.Fatal(err)
	}
	run2, err := Acquire(state, Run)
	if err != nil {
		t.Fatalf("a second lox run: %v", err)
	}
	_, err = Acquire(state, Live)
	var he *HeldError
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "lox run serves this workspace") {
		t.Fatalf("lox live next to lox run: %v", err)
	}
	run1()
	if _, err := Acquire(state, Live); err == nil {
		t.Fatal("lox live started while a lox run still serves")
	}
	run2()
	live, err := Acquire(state, Live)
	if err != nil {
		t.Fatalf("lox live once lox run stopped: %v", err)
	}
	_, err = Acquire(state, Run)
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "lox live serves this workspace") || !strings.Contains(err.Error(), "lox approve") ||
		!strings.Contains(err.Error(), "pid ") {
		t.Fatalf("lox run next to lox live: %v", err)
	}
	if _, err := Acquire(state, Live); !errors.As(err, &he) || !strings.Contains(err.Error(), "lox live serves this workspace") {
		t.Fatalf("a second lox live: %v", err)
	}
	live()
	again, err := Acquire(state, Run)
	if err != nil {
		t.Fatalf("lox run once lox live stopped: %v", err)
	}
	again()
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state directory %v %v", fi, err)
	}
}

// The health: serving only when it is enrolled, the hub answers and every
// lock of the workspace serves.
func TestTrackerHealth(t *testing.T) {
	tr := NewTracker()
	if h := tr.Health(); h.Serving || h.Locks == nil || h.Detail == "" {
		t.Fatalf("before the start: %+v", h)
	}
	tr.NeedsEnrolment([]string{"db", "mq"}, "the configuration differs")
	h := tr.Health()
	if h.Serving || h.Locks["db"] != NeedsEnrolment || h.Locks["mq"] != NeedsEnrolment || !strings.Contains(h.Detail, "the configuration differs") {
		t.Fatalf("needs enrolment: %+v", h)
	}
	tr.Started([]string{"db", "mq"})
	if h := tr.Health(); h.Serving || h.Locks["db"] != Down {
		t.Fatalf("started, nothing known yet: %+v", h)
	}
	tr.Hub(nil)
	tr.Console("db", loxrun.ConsoleStatus{State: loxrun.ConsoleServing})
	tr.Console("mq", loxrun.ConsoleStatus{State: loxrun.ConsoleWaiting, Blocked: loxrun.BlockedSecret, Detail: "its console asks a password"})
	h = tr.Health()
	if h.Serving || h.Locks["db"] != Serving || h.Locks["mq"] != MissingSecret || !strings.Contains(h.Detail, "mq") {
		t.Fatalf("one lock blocked: %+v", h)
	}
	tr.Console("mq", loxrun.ConsoleStatus{State: loxrun.ConsoleServing})
	if h := tr.Health(); !h.Serving || h.Detail != "serving" {
		t.Fatalf("all serving: %+v", h)
	}
	// A lock pinned to a state whatever its console says (credentials: ask).
	tr.Fixed("db", MissingSecret, "its profile's credentials are asked")
	tr.Console("db", loxrun.ConsoleStatus{State: loxrun.ConsoleServing})
	if h := tr.Health(); h.Serving || h.Locks["db"] != MissingSecret {
		t.Fatalf("fixed: %+v", h)
	}
	tr.Started([]string{"db", "mq"})
	tr.Console("db", loxrun.ConsoleStatus{State: loxrun.ConsoleServing})
	tr.Console("mq", loxrun.ConsoleStatus{State: loxrun.ConsoleStopped, Detail: "exit 1"})
	tr.Hub(errors.New("connection refused"))
	h = tr.Health()
	if h.Serving || h.Locks["mq"] != Down || !strings.Contains(h.Detail, "hub") {
		t.Fatalf("hub down: %+v", h)
	}
	for _, c := range []struct {
		st   loxrun.ConsoleStatus
		want string
	}{
		{loxrun.ConsoleStatus{State: loxrun.ConsoleWaiting, Blocked: loxrun.BlockedEnrolment}, NeedsEnrolment},
		{loxrun.ConsoleStatus{State: loxrun.ConsoleWaiting, Blocked: loxrun.BlockedRefused}, Refused},
		{loxrun.ConsoleStatus{State: loxrun.ConsoleWaiting}, Down},
		{loxrun.ConsoleStatus{State: loxrun.ConsoleStarting}, Down},
		{loxrun.ConsoleStatus{State: loxrun.ConsoleUnreachable}, Down},
		{loxrun.ConsoleStatus{State: loxrun.ConsoleNotStarted}, Down},
	} {
		tr.Console("mq", c.st)
		if got := tr.Health().Locks["mq"]; got != c.want {
			t.Errorf("%+v: %s, want %s", c.st, got, c.want)
		}
	}
	tr.Stopped("lox live is stopping")
	if h := tr.Health(); h.Serving || h.Locks["db"] != Down {
		t.Fatalf("stopped: %+v", h)
	}
}

// fakeHub is the facade socket as the status socket uses it.
type fakeHub struct {
	mu        sync.Mutex
	items     []api.QueueItem
	states    map[string]string
	withdrawn []api.WithdrawRequest
	down      bool
}

func (h *fakeHub) QueueAll(context.Context, uint64, time.Duration) (api.QueueResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down {
		return api.QueueResult{}, errors.New("dial unix: connection refused")
	}
	return api.QueueResult{Tickets: append([]api.QueueItem(nil), h.items...)}, nil
}

func (h *fakeHub) State(_ context.Context, instance, id string) (api.TicketState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down {
		return api.TicketState{}, errors.New("dial unix: connection refused")
	}
	s, ok := h.states[instance+"/"+id]
	if !ok {
		return api.TicketState{}, &approve.HubError{Status: 404, Kind: "not_found", Message: "no such ticket"}
	}
	return api.TicketState{ID: id, Instance: instance, State: s}, nil
}

func (h *fakeHub) Withdraw(_ context.Context, instance, id string, req api.WithdrawRequest) (api.WithdrawResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.withdrawn = append(h.withdrawn, req)
	h.states[instance+"/"+id] = "withdrawn"
	return api.WithdrawResult{Reason: "withdrawn", Told: true}, nil
}

// push signs a pending ticket of agent on instance shop.
func (h *fakeHub) push(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, agent string) string {
	t.Helper()
	tk := ticket.NewKindTicket(ticket.Source{Lock: "locksql", Instance: "shop", KeyID: ticket.KeyID(pub)}, ticket.KindWrite, ticket.RiskWrite,
		&ticket.Subject{Profile: "prod"}, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), time.Now(), time.Hour)
	tk.Requester = ticket.Requester{Agent: agent}
	tk.Screen = ticket.Screen{Header: "shop", Body: []string{"UPDATE"}, Warnings: []string{}}
	if err := tk.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.items = append(h.items, api.QueueItem{ID: tk.ID, Instance: "shop", Risk: "write", Created: tk.Created, Facades: []string{"tty"}, Ticket: raw})
	h.states["shop/"+tk.ID] = "pending"
	return tk.ID
}

// serve serves a status socket in a temp directory and returns a client
// of it.
func serve(t *testing.T, s *Status) (*http.Client, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "loxlive")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "status.sock")
	ln, err := Listen(sock, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := s.Server()
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}, sock
}

func do(t *testing.T, c *http.Client, method, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://lox-live"+path, strings.NewReader("{}"))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The status socket's contract: the health, a ticket's state, and the
// withdrawal of a pending ticket a dutydesk agent raised; nothing on it
// decides a ticket.
func TestStatusSocket(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := &fakeHub{states: map[string]string{"shop/A1": "approved", "shop/C1": "consumed", "shop/D1": "denied", "shop/E1": "expired", "shop/W1": "withdrawn", "shop/R1": "lock_removed"}}
	mine := h.push(t, priv, pub, "dutydesk:INC-42")
	other := h.push(t, priv, pub, "dev-1")
	near := h.push(t, priv, pub, "dutydesk")
	tr := NewTracker()
	tr.Started([]string{"shop"})
	tr.Hub(nil)
	tr.Console("shop", loxrun.ConsoleStatus{State: loxrun.ConsoleServing})
	c, sock := serve(t, &Status{Tracker: tr, Hub: h, LockKeys: func() map[string]ed25519.PublicKey { return map[string]ed25519.PublicKey{"shop": pub} }})

	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode: %v %v", fi, err)
	}
	code, body := do(t, c, "GET", "/v1/health")
	var raw map[string]json.RawMessage
	if code != 200 || json.Unmarshal([]byte(body), &raw) != nil || len(raw) != 4 {
		t.Fatalf("health: %d %s", code, body)
	}
	var got Health
	json.Unmarshal([]byte(body), &got)
	if !got.Serving || got.Locks["shop"] != "serving" || got.Pending != 3 || got.Detail == "" {
		t.Fatalf("health: %s", body)
	}
	for _, k := range []string{"serving", "locks", "pending", "detail"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("health lacks %q: %s", k, body)
		}
	}

	for id, want := range map[string]string{mine: "pending", "A1": "approved", "C1": "consumed", "D1": "denied", "E1": "expired", "W1": "withdrawn", "R1": "withdrawn"} {
		code, body := do(t, c, "GET", "/v1/tickets/shop/"+id)
		if code != 200 || strings.TrimSpace(body) != `{"state":"`+want+`"}` {
			t.Errorf("state of %s: %d %s", id, code, body)
		}
	}
	if code, _ := do(t, c, "GET", "/v1/tickets/shop/NOPE"); code != 404 {
		t.Errorf("unknown ticket: %d", code)
	}

	// Only a pending ticket of a dutydesk: agent is withdrawn.
	for id, want := range map[string]int{other: 403, near: 403, "A1": 403, "NOPE": 404} {
		if code, body := do(t, c, "POST", "/v1/tickets/shop/"+id+"/withdraw"); code != want {
			t.Errorf("withdraw %s: %d %s, want %d", id, code, body, want)
		}
	}
	if len(h.withdrawn) != 0 {
		t.Fatalf("withdrawn: %+v", h.withdrawn)
	}
	if code, body := do(t, c, "POST", "/v1/tickets/shop/"+mine+"/withdraw"); code != 204 || body != "" {
		t.Fatalf("withdraw of its own ticket: %d %s", code, body)
	}
	if len(h.withdrawn) != 1 || h.withdrawn[0].Facade != route.Live || h.withdrawn[0].Via != hub.ViaLive || !strings.Contains(h.withdrawn[0].Display, "uid ") {
		t.Fatalf("withdrawal sent as %+v", h.withdrawn)
	}
	// A ticket that does not verify under the pinned key names no agent
	// lox live trusts.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	forged := h.push(t, priv2, pub2, "dutydesk:INC-1")
	if code, _ := do(t, c, "POST", "/v1/tickets/shop/"+forged+"/withdraw"); code != 403 {
		t.Errorf("withdraw of an unverifiable ticket: %d", code)
	}

	// Nothing decides, reveals or renews; nothing else is served.
	for _, p := range [][2]string{
		{"POST", "/v1/tickets/shop/" + other + "/decide"}, {"POST", "/v1/tickets/shop/" + other + "/reveal"},
		{"POST", "/v1/tickets/shop/" + other + "/renew"}, {"GET", "/v1/queue"}, {"GET", "/v1/hub"}, {"GET", "/v1/decided"},
		{"POST", "/v1/health"}, {"DELETE", "/v1/tickets/shop/" + other}, {"PUT", "/v1/tickets/shop/" + other},
	} {
		if code, _ := do(t, c, p[0], p[1]); code != 404 && code != 405 {
			t.Errorf("%s %s: %d", p[0], p[1], code)
		}
	}
	if s := h.states["shop/"+other]; s != "pending" {
		t.Errorf("the other ticket is %s", s)
	}

	// The hub does not answer: not serving, and a ticket's state is unknown (503).
	h.mu.Lock()
	h.down = true
	h.mu.Unlock()
	code, body = do(t, c, "GET", "/v1/health")
	json.Unmarshal([]byte(body), &got)
	if code != 200 || got.Serving || !strings.Contains(got.Detail, "hub") {
		t.Errorf("health with the hub down: %d %s", code, body)
	}
	if code, _ := do(t, c, "GET", "/v1/tickets/shop/"+mine); code != 503 {
		t.Errorf("state with the hub down: %d", code)
	}
}

// Listen refuses to replace anything that is not a socket, and replaces a
// socket left by a lox live that died.
func TestListen(t *testing.T) {
	dir, err := os.MkdirTemp("", "loxlive")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "sub", "status.sock")
	ln, err := Listen(p, "")
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	ln, err = Listen(p, "")
	if err != nil {
		t.Fatalf("over a stale socket: %v", err)
	}
	ln.Close()
	f := filepath.Join(dir, "file")
	os.WriteFile(f, []byte("x"), 0o600)
	if _, err := Listen(f, ""); err == nil {
		t.Error("a regular file was replaced by the socket")
	}
	if _, err := Listen(filepath.Join(dir, "g.sock"), "no-such-group-xyz"); err == nil {
		t.Error("an unknown group was accepted")
	}
}
