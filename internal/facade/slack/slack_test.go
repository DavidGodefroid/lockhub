package slack_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/facade/slack"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

func TestEscapeCorpus(t *testing.T) {
	for _, in := range []string{
		"<!channel> deploy", "<!here>", "<!everyone>", "<@U0123> look", "<#C0123>",
		"<https://evil.example|click to approve>", "&lt;!channel&gt;", "`` ` ``` break out",
		"\x1b[31mred\x1b[0m", "\u202eevil\u202c", "zero\u200bwidth\u200dhere\ufeff", "*bold* _it_ ~st~",
		"line1\nline2", "\x00nul",
	} {
		out := slack.Escape(in)
		for _, bad := range []string{"<", ">", "`", "\x1b", "\u202e", "\u200b", "\u200d", "\ufeff", "\n", "\x00"} {
			if strings.Contains(out, bad) {
				t.Errorf("Escape(%q) = %q keeps %q", in, out, bad)
			}
		}
		if strings.Contains(in, "&") && !strings.Contains(out, "&amp;") {
			t.Errorf("Escape(%q) = %q: & not escaped", in, out)
		}
	}
}

// fakeSlack is the Web API and the Socket Mode endpoint.
type fakeSlack struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	calls []call
	ws    chan *websocket.Conn
	acks  chan string
	ts    int
}

type call struct {
	method, auth string
	body         map[string]any
	raw          string
}

func newFakeSlack(t *testing.T) *fakeSlack {
	f := &fakeSlack{t: t, ws: make(chan *websocket.Conn, 4), acks: make(chan string, 16)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ws" {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		f.ws <- c
		for {
			_, b, err := c.Read(context.Background())
			if err != nil {
				return
			}
			var a struct {
				EnvelopeID string `json:"envelope_id"`
			}
			json.Unmarshal(b, &a)
			f.acks <- a.EnvelopeID
		}
	}
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	json.Unmarshal(b, &body)
	m := strings.TrimPrefix(r.URL.Path, "/api/")
	f.mu.Lock()
	f.calls = append(f.calls, call{m, r.Header.Get("Authorization"), body, string(b)})
	f.ts++
	ts := f.ts
	f.mu.Unlock()
	switch m {
	case "apps.connections.open":
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "url": "ws" + strings.TrimPrefix(f.srv.URL, "http") + "/ws"})
	case "chat.postMessage":
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": "17000." + string(rune('0'+ts%10))})
	default:
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

func (f *fakeSlack) of(method string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeSlack) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, c := range f.calls {
		b.WriteString(c.raw + "\n")
	}
	return b.String()
}

// waitFor bounds eventually.
const waitFor = 30 * time.Second

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	// A deadline, not a count of polls: on a loaded runner the facade's
	// close after a decision (an fsync'd audit flush, then an HTTP call)
	// took more than 3 s (lockhub#55). Only a failure waits this long.
	for deadline := time.Now().Add(waitFor); ; {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s: %s", waitFor, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type env struct {
	h    *hub.Hub
	st   *store.Store
	lock ed25519.PrivateKey
	f    *fakeSlack
	conn *websocket.Conn
}

func setup(t *testing.T, rules route.Rules) env {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	t.Cleanup(func() { st.Close() })
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	t.Cleanup(func() { al.Close() })
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hk,
		Locks: map[string]ed25519.PublicKey{"crm": pub}, Routes: rules})
	f := newFakeSlack(t)
	s, err := slack.New(slack.Config{Team: "T1", Users: []string{"U1"}, Channel: "C1",
		AppToken: "xapp-1", BotToken: "xoxb-1", API: f.srv.URL + "/api/"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	fc := &chat.Facade{H: h, T: s, Wait: 50 * time.Millisecond}
	go fc.Run(ctx)
	var conn *websocket.Conn
	select {
	case conn = <-f.ws:
	case <-time.After(5 * time.Second):
		t.Fatal("no socket mode connection")
	}
	return env{h, st, priv, f, conn}
}

const secret = "jane.doe@example.com"

var sealedCT = b64([]byte(secret + "0123456789abcdef"))

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (e env) push(t *testing.T, risk ticket.Risk, prod bool) string {
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, risk,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: "<!channel> dev-1", Session: "s"}
	tk.Screen = ticket.Screen{Header: "query on crm", Body: []string{"SELECT * FROM users WHERE email = '<email:1>'"},
		Note: "<https://evil.example|approve here>", Warnings: []string{"touches 3 rows"}}
	tk.PII.Touched = []string{"email"}
	tk.PII.ClearSealed = &ticket.Sealed{Alg: ticket.SealAlg, EPK: b64(make([]byte, 32)), Nonce: b64(make([]byte, 24)), CT: sealedCT}
	if prod {
		tk.Flags = ticket.Flags{Production: true, Retype: "crm"}
	}
	if err := tk.Sign(e.lock); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	if _, _, err := e.h.Push(context.Background(), "crm", raw); err != nil {
		t.Fatal(err)
	}
	return tk.ID
}

var envSeq int

func (e env) click(t *testing.T, team, user, channel, action, value string) {
	envSeq++
	p := map[string]any{"type": "block_actions", "team": map[string]string{"id": team},
		"user": map[string]string{"id": user, "team_id": team}, "channel": map[string]string{"id": channel},
		"actions": []map[string]string{{"action_id": action, "value": value}}}
	pb, _ := json.Marshal(p)
	id := "env-" + string(rune('a'+envSeq%26))
	b, _ := json.Marshal(map[string]any{"envelope_id": id, "type": "interactive", "payload": json.RawMessage(pb)})
	if err := e.conn.Write(context.Background(), websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-e.f.acks:
		if got != id {
			t.Fatalf("ack %q, want %q", got, id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("envelope not acknowledged")
	}
}

func (e env) state(id string) state.State {
	var s state.State
	e.st.Tx(context.Background(), func(tx *store.Tx) error {
		tk, err := tx.Ticket(store.Ref{Instance: "crm", ID: id})
		s = tk.State
		return err
	})
	return s
}

func hasButtons(c call) bool { return strings.Contains(c.raw, `"type":"actions"`) }

func TestApproveFromAllowedUserOnly(t *testing.T) {
	e := setup(t, route.Rules{Enabled: []string{route.TTY, route.Slack}})
	id := e.push(t, ticket.RiskRead, false)
	eventually(t, "posted", func() bool { return len(e.f.of("chat.postMessage")) == 1 })
	pm := e.f.of("chat.postMessage")[0]
	if pm.auth != "Bearer xoxb-1" || pm.body["channel"] != "C1" || !hasButtons(pm) || pm.body["unfurl_links"] != false {
		t.Fatalf("post %s", pm.raw)
	}
	v := "crm/" + id
	// Not allowed: other user, other team, other channel, unknown action.
	e.click(t, "T1", "U2", "C1", "approve", v)
	e.click(t, "T2", "U1", "C1", "approve", v)
	e.click(t, "T1", "U1", "C2", "approve", v)
	e.click(t, "T1", "U1", "C1", "reveal", v)
	time.Sleep(100 * time.Millisecond)
	if s := e.state(id); s != state.Pending {
		t.Fatalf("state %s after refused clicks", s)
	}
	e.click(t, "T1", "U1", "C1", "approve", v)
	eventually(t, "approved", func() bool { return e.state(id) == state.Approved })
	ds, _ := e.st.Decisions(context.Background(), "crm", 0, 10)
	if len(ds) != 1 || !strings.Contains(string(ds[0].Raw), `"facade":"slack"`) || !strings.Contains(string(ds[0].Raw), `slack:T1:U1`) {
		t.Fatalf("decision %s", ds[0].Raw)
	}
	eventually(t, "message closed", func() bool { return len(e.f.of("chat.update")) == 1 })
	up := e.f.of("chat.update")[0]
	if hasButtons(up) || !strings.Contains(up.raw, "approved by slack U1") || up.body["ts"] == nil || up.body["ts"] == "" {
		t.Errorf("update %s", up.raw)
	}
}

func TestNoButtonsForProductionOrProdWrite(t *testing.T) {
	e := setup(t, route.Rules{Enabled: []string{route.TTY, route.Slack}})
	prod := e.push(t, ticket.RiskRead, true)
	pw := e.push(t, ticket.RiskProdWrite, false)
	eventually(t, "posted", func() bool { return len(e.f.of("chat.postMessage")) == 2 })
	for _, c := range e.f.of("chat.postMessage") {
		if hasButtons(c) || !strings.Contains(c.raw, "answer it in the terminal or the deck") {
			t.Errorf("chat answerable: %s", c.raw)
		}
	}
	// A forged click is refused, with a reply.
	e.click(t, "T1", "U1", "C1", "approve", "crm/"+prod)
	e.click(t, "T1", "U1", "C1", "approve", "crm/"+pw)
	eventually(t, "replies", func() bool { return len(e.f.of("chat.postEphemeral")) == 2 })
	if e.state(prod) != state.Pending || e.state(pw) != state.Pending {
		t.Fatal("decided on chat")
	}
	// The hub refuses it too, whatever a facade checks.
	for _, f := range []string{route.Slack, route.Telegram} {
		_, err := e.h.Decide(context.Background(), store.Ref{Instance: "crm", ID: prod}, hub.Verdict{Approved: true, ApproverID: "x", Facade: f, Retype: "crm"})
		if !errors.Is(err, hub.ErrNotRouted) {
			t.Errorf("hub let %s decide a production ticket: %v", f, err)
		}
	}
	if _, err := e.h.Decide(context.Background(), store.Ref{Instance: "crm", ID: prod}, hub.Verdict{Approved: true, ApproverID: "host:uid:1", Facade: route.TTY, Retype: "crm"}); err != nil {
		t.Errorf("tty: %v", err)
	}
}

// No routing (a hub without routing.json, #61): slack is not enabled, and
// shows nothing.
func TestNoRoutingNotShown(t *testing.T) {
	e := setup(t, route.Rules{})
	e.push(t, ticket.RiskRead, false)
	time.Sleep(200 * time.Millisecond)
	if n := len(e.f.of("chat.postMessage")); n != 0 {
		t.Fatalf("%d messages with no routing", n)
	}
}

func TestRoutedAwayNotShown(t *testing.T) {
	e := setup(t, route.Rules{Enabled: []string{route.TTY, route.Slack}, Only: map[string][]string{"crm": {route.TTY}}})
	e.push(t, ticket.RiskRead, false)
	time.Sleep(200 * time.Millisecond)
	if n := len(e.f.of("chat.postMessage")); n != 0 {
		t.Fatalf("%d messages for an instance routed to tty only", n)
	}
}

func TestPayloadsHoldNoClearValuesAndNoLiveMarkup(t *testing.T) {
	e := setup(t, route.Rules{Enabled: []string{route.TTY, route.Slack}})
	id := e.push(t, ticket.RiskReadPII, false)
	eventually(t, "posted", func() bool { return len(e.f.of("chat.postMessage")) == 1 })
	// Decided elsewhere: the message is closed.
	if _, err := e.h.Decide(context.Background(), store.Ref{Instance: "crm", ID: id},
		hub.Verdict{Approved: false, ApproverID: "host:uid:1000", Facade: route.TTY}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "closed", func() bool { return len(e.f.of("chat.update")) == 1 })
	if !strings.Contains(e.f.of("chat.update")[0].raw, "no longer pending") {
		t.Errorf("update %s", e.f.of("chat.update")[0].raw)
	}
	all := e.f.all()
	if strings.Contains(all, secret) || strings.Contains(all, sealedCT) {
		t.Fatal("the sealed clear value reached Slack")
	}
	// JSON escapes < and > as < / >: check the decoded texts.
	for _, c := range append(e.f.of("chat.postMessage"), e.f.of("chat.update")...) {
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, y := range x {
					if s, ok := y.(string); ok && k == "text" && (strings.Contains(s, "<!") || strings.Contains(s, "<http")) {
						t.Errorf("live markup in %q", s)
					}
					walk(y)
				}
			case []any:
				for _, y := range x {
					walk(y)
				}
			}
		}
		walk(c.body)
	}
	if !strings.Contains(all, "requester (unverified)") || !strings.Contains(all, "personal data touched (masked)") {
		t.Errorf("payload %s", all)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	for _, c := range []slack.Config{
		{Users: []string{"U1"}, Channel: "C1", AppToken: "xapp-1", BotToken: "xoxb-1"},
		{Team: "T1", Channel: "C1", AppToken: "xapp-1", BotToken: "xoxb-1"},
		{Team: "T1", Users: []string{"U1"}, Channel: "C1", AppToken: "xoxb-1", BotToken: "xoxb-1"},
		{Team: "T1", Users: []string{"U1"}, Channel: "C1", AppToken: "xapp-1", BotToken: "xoxp-1"},
	} {
		if _, err := slack.New(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestLongTextStaysInsideItsCodeSpan(t *testing.T) {
	long := strings.Repeat("a", 5000) + " <!channel> *spoof*"
	c := chat.Card{ID: "t1", Instance: "crm", Risk: "read", Lock: "locksql", Requester: long, Header: long, Note: long, Body: []string{long, long}, Warnings: []string{long}, Answerable: true}
	for _, b := range slack.Blocks(c, "") {
		raw, _ := json.Marshal(b)
		var m struct {
			Text struct{ Text string } `json:"text"`
		}
		json.Unmarshal(raw, &m)
		s := m.Text.Text
		if len(s) > 3000 {
			t.Errorf("text of %d bytes", len(s))
		}
		if n := strings.Count(s, "`"); n%2 != 0 {
			t.Errorf("unbalanced code delimiters (%d) in %q…", n, s[:min(len(s), 80)])
		}
		if strings.Contains(s, "<!") {
			t.Error("live markup")
		}
	}
}
