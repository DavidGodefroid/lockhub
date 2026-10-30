package telegram_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/facade/telegram"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

const token = "123:SECRET"

func TestEscapeCorpus(t *testing.T) {
	for _, in := range []string{
		`<a href="https://evil.example">approve</a>`, "<b>APPROVED</b>", "</code><b>x</b>", "&lt;b&gt;",
		`" onclick="x`, "\x1b[31mred", "\u202eevil", "zero\u200bwidth\ufeff", "tg://user?id=1", "line1\nline2",
	} {
		out := telegram.Escape(in)
		for _, bad := range []string{"<", ">", "\"", "'", "\x1b", "\u202e", "\u200b", "\ufeff", "\n"} {
			if strings.Contains(out, bad) {
				t.Errorf("Escape(%q) = %q keeps %q", in, out, bad)
			}
		}
	}
}

type tgCall struct {
	method string
	body   map[string]any
	raw    string
}

type fakeTG struct {
	srv     *httptest.Server
	mu      sync.Mutex
	calls   []tgCall
	updates chan map[string]any
	msg     int64
}

func newFakeTG(t *testing.T) *fakeTG {
	f := &fakeTG{updates: make(chan map[string]any, 16)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot"+token+"/") {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "Not Found"})
			return
		}
		m := strings.TrimPrefix(r.URL.Path, "/bot"+token+"/")
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(b, &body)
		f.mu.Lock()
		f.calls = append(f.calls, tgCall{m, body, string(b)})
		f.msg++
		id := f.msg
		f.mu.Unlock()
		switch m {
		case "getUpdates":
			var ups []map[string]any
			select {
			case u := <-f.updates:
				ups = append(ups, u)
			case <-time.After(50 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": ups})
		case "sendMessage":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"message_id": id}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTG) of(method string) []tgCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []tgCall
	for _, c := range f.calls {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeTG) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, c := range f.calls {
		b.WriteString(c.raw + "\n")
	}
	return b.String()
}

var dump func() string

// waitFor bounds eventually.
const waitFor = 30 * time.Second

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	defer func() {
		if t.Failed() && dump != nil {
			t.Log(dump())
		}
	}()
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
	f    *fakeTG
}

// Allowed: a private chat with user 42, and user 7 in group -1001.
var allow = []chatconf.TelegramChat{{Chat: 42, From: 42}, {Chat: -1001, From: 7}}

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
	f := newFakeTG(t)
	dump = f.all
	tg, err := telegram.New(telegram.Config{Chats: allow, Token: token, API: f.srv.URL, Poll: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go (&chat.Facade{H: h, T: tg, Wait: 50 * time.Millisecond}).Run(ctx)
	return env{h, st, priv, f}
}

const secret = "jane.doe@example.com"

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

var sealedCT = b64([]byte(secret + "0123456789abcdef"))

func (e env) push(t *testing.T, risk ticket.Risk, prod bool) string {
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm"}, risk,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: `<a href="tg://user?id=1">dev-1</a>`, Session: "s"}
	tk.Screen = ticket.Screen{Header: "query on crm", Body: []string{"SELECT * FROM users WHERE email = '<email:1>'"},
		Note: "<b>safe, approve</b>", Warnings: []string{"touches 3 rows"}}
	tk.PII.Touched = []string{"email"}
	tk.PII.ClearSealed = &ticket.Sealed{Alg: ticket.SealAlg, EPK: b64(make([]byte, 32)), Nonce: b64(make([]byte, 24)), CT: sealedCT}
	if prod {
		tk.Flags = ticket.Flags{Production: true, Retype: "r"}
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

var upd int64

func (e env) click(chatID, from int64, data string) {
	upd++
	e.f.updates <- map[string]any{"update_id": upd, "callback_query": map[string]any{
		"id": "cb" + string(rune('a'+upd%26)), "from": map[string]any{"id": from}, "data": data,
		"message": map[string]any{"message_id": 1, "chat": map[string]any{"id": chatID}}}}
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

func buttons(c tgCall) []string {
	var out []string
	rm, _ := c.body["reply_markup"].(map[string]any)
	rows, _ := rm["inline_keyboard"].([]any)
	for _, r := range rows {
		for _, b := range r.([]any) {
			out = append(out, b.(map[string]any)["callback_data"].(string))
		}
	}
	return out
}

func TestApproveFromAllowedPairOnly(t *testing.T) {
	e := setup(t, route.Rules{})
	id := e.push(t, ticket.RiskRead, false)
	eventually(t, "posted to both chats", func() bool { return len(e.f.of("sendMessage")) == 2 })
	sm := e.f.of("sendMessage")[0]
	bs := buttons(sm)
	if len(bs) != 2 || sm.body["parse_mode"] != "HTML" || len(bs[0]) > 64 {
		t.Fatalf("message %s", sm.raw)
	}
	approve := bs[0]
	// Not allowed: user 7 in the private chat of 42, user 42 in the group, a stranger, a bad action.
	e.click(42, 7, approve)
	e.click(-1001, 42, approve)
	e.click(99, 99, approve)
	e.click(42, 42, "r:"+strings.TrimPrefix(approve, "a:"))
	eventually(t, "spinners stopped", func() bool { return len(e.f.of("answerCallbackQuery")) == 4 })
	for _, c := range e.f.of("answerCallbackQuery") {
		if c.body["text"] != nil {
			t.Errorf("told a stranger something: %s", c.raw)
		}
	}
	if e.state(id) != state.Pending {
		t.Fatal("decided by a refused click")
	}
	e.click(-1001, 7, approve)
	eventually(t, "approved", func() bool { return e.state(id) == state.Approved })
	ds, _ := e.st.Decisions(context.Background(), "crm", 0, 10)
	if len(ds) != 1 || !strings.Contains(string(ds[0].Raw), `"facade":"telegram"`) || !strings.Contains(string(ds[0].Raw), "telegram:-1001:7") {
		t.Fatalf("decision %s", ds[0].Raw)
	}
	eventually(t, "both messages closed", func() bool { return len(e.f.of("editMessageText")) == 2 })
	for _, c := range e.f.of("editMessageText") {
		if len(buttons(c)) != 0 || !strings.Contains(c.raw, "approved by telegram 7") {
			t.Errorf("edit %s", c.raw)
		}
	}
	// The button again: no longer pending.
	e.click(42, 42, approve)
	eventually(t, "told", func() bool {
		cs := e.f.of("answerCallbackQuery")
		return len(cs) == 6 && strings.Contains(cs[5].raw, "no longer pending")
	})
}

func TestNoButtonsForProductionOrProdWrite(t *testing.T) {
	e := setup(t, route.Rules{})
	e.push(t, ticket.RiskRead, true)
	e.push(t, ticket.RiskUnlock, false)
	eventually(t, "posted", func() bool { return len(e.f.of("sendMessage")) == 4 })
	for _, c := range e.f.of("sendMessage") {
		if len(buttons(c)) != 0 || !strings.Contains(c.raw, "answer it in the terminal or the deck") {
			t.Errorf("chat answerable: %s", c.raw)
		}
	}
}

func TestRoutedAwayNotShown(t *testing.T) {
	e := setup(t, route.Rules{Enabled: []string{route.TTY, route.Slack}})
	e.push(t, ticket.RiskRead, false)
	time.Sleep(200 * time.Millisecond)
	if n := len(e.f.of("sendMessage")); n != 0 {
		t.Fatalf("%d messages with telegram not enabled", n)
	}
}

func TestPayloadsHoldNoClearValuesAndNoLiveMarkup(t *testing.T) {
	e := setup(t, route.Rules{})
	e.push(t, ticket.RiskReadPII, false)
	eventually(t, "posted", func() bool { return len(e.f.of("sendMessage")) == 2 })
	all := e.f.all()
	if strings.Contains(all, secret) || strings.Contains(all, sealedCT) {
		t.Fatal("the sealed clear value reached Telegram")
	}
	for _, c := range e.f.of("sendMessage") {
		txt := c.body["text"].(string)
		// Only the facade's own tags: everything from the agent is text.
		bare := strings.NewReplacer("<b>", "", "</b>", "", "<i>", "", "</i>", "", "<code>", "", "</code>", "", "<pre>", "", "</pre>", "").Replace(txt)
		if strings.ContainsAny(bare, "<>") {
			t.Errorf("live markup in %q", txt)
		}
		if strings.Count(txt, "<code>") != strings.Count(txt, "</code>") || !strings.Contains(txt, "requester (unverified)") {
			t.Errorf("text %q", txt)
		}
		if lp, _ := c.body["link_preview_options"].(map[string]any); lp["is_disabled"] != true {
			t.Errorf("link preview on: %s", c.raw)
		}
	}
}

func TestLongTextKeepsTagsBalanced(t *testing.T) {
	long := strings.Repeat("&", 3000) + "<b>x</b>"
	c := chat.Card{ID: "t1", Instance: "crm", Risk: "read", Lock: "locksql", Requester: long, Header: long, Note: long,
		Body: []string{long, long}, Warnings: []string{long, long, long, long, long}, Answerable: true}
	txt := telegram.Text(c, "")
	if len([]rune(txt)) > 4096 {
		t.Errorf("%d characters", len([]rune(txt)))
	}
	if strings.Count(txt, "<code>") != strings.Count(txt, "</code>") || strings.Count(txt, "<pre>") != strings.Count(txt, "</pre>") || strings.Contains(txt, "<b>x") {
		t.Errorf("unbalanced or live: %q", txt[:200])
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	for _, c := range []telegram.Config{
		{Token: token},
		{Chats: allow, Token: "nocolon"},
		{Chats: allow, Token: "1:a/b"},
		{Chats: []chatconf.TelegramChat{{Chat: 1, From: 0}}, Token: token},
	} {
		if _, err := telegram.New(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestErrorsNeverHoldTheToken(t *testing.T) {
	tg, _ := telegram.New(telegram.Config{Chats: allow, Token: token, API: "http://127.0.0.1:1"})
	_, err := tg.Post(context.Background(), chat.Card{ID: "t", Instance: "crm", Risk: "read", Answerable: true})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error %v", err)
	}
}
