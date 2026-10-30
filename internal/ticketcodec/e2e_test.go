package ticketcodec_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// TestLockkitEndToEnd: a lock built on lockkit pushes a real ticket over
// the signed API, a human approves it, the lock long-polls the decision
// and verifies it with lockkit against its own ticket.
func TestLockkitEndToEnd(t *testing.T) {
	lockPub, lockPriv, _ := ed25519.GenerateKey(rand.Reader)
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "hub.db"))
	defer st.Close()
	al, _ := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	defer al.Close()
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubPriv,
		Locks: map[string]ed25519.PublicKey{"crm-prod": lockPub}})
	srv := httptest.NewServer(api.LockHandler(h, "e2e"))
	defer srv.Close()

	do := func(method, path string, body []byte) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		now, nonce := time.Now(), ticket.NewNonce()
		msg := ticket.RequestMessage(method, path, "crm-prod", now, nonce, body)
		req.Header.Set("Lock-Instance", "crm-prod")
		req.Header.Set("Lock-Time", strconv.FormatInt(now.Unix(), 10))
		req.Header.Set("Lock-Nonce", nonce)
		req.Header.Set("Lock-Sig", ticket.SignBytes(lockPriv, ticket.ContextRequest, msg))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return resp.StatusCode, b.Bytes()
	}

	tk := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm-prod"}, ticket.RiskProdWrite,
		"sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64), time.Now(), 0)
	tk.Workspace, tk.Requester = "~/Documents", ticket.Requester{Agent: "dev-1", Session: "s1"}
	tk.Flags = ticket.Flags{Production: true, Retype: "crm-prod"}
	tk.Screen = ticket.Screen{Header: "UPDATE on crm-prod", Body: []string{"UPDATE customers SET tier = $1 WHERE id = $2"}}
	if err := tk.Sign(lockPriv); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	if code, body := do("POST", "/v1/tickets", raw); code != http.StatusCreated {
		t.Fatalf("push: %d %s", code, body)
	}

	ref := store.Ref{Instance: "crm-prod", ID: tk.ID}
	if _, err := h.Decide(context.Background(), ref, hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty"}); err == nil {
		t.Fatal("production ticket approved without the retype")
	}
	if _, err := h.Decide(context.Background(), ref, hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty", Retype: "crm-prod"}); err != nil {
		t.Fatal(err)
	}

	code, body := do("GET", "/v1/decisions?since=0&wait=5", nil)
	var res api.DecisionsResult
	if err := json.Unmarshal(body, &res); code != 200 || err != nil || len(res.Decisions) != 1 {
		t.Fatalf("decisions: %d %s", code, body)
	}
	d, err := ticket.VerifyDecision(hubPub, res.Decisions[0].Decision)
	if err != nil {
		t.Fatalf("lockkit refuses the hub's decision: %v", err)
	}
	if err := d.Match(tk); err != nil {
		t.Fatalf("decision does not match the ticket: %v", err)
	}
	if err := d.Usable(tk, time.Now(), 0); err != nil {
		t.Errorf("decision not usable: %v", err)
	}
	if code, _ := do("POST", "/v1/tickets/"+tk.ID+"/consumed", nil); code != http.StatusNoContent {
		t.Errorf("consumed: %d", code)
	}
}

// TestHelloAnnouncesVersionsAndKey: the hello names the ticket versions
// lockkit verifies and the hub key's id as lockkit computes it, and
// lockkit's hub client still reads it.
func TestHelloAnnouncesVersionsAndKey(t *testing.T) {
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	al, err := audit.Open(filepath.Join(dir, "tickets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubPriv, Locks: map[string]ed25519.PublicKey{}})
	srv := httptest.NewServer(api.LockHandler(h, "e2e"))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/hello")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if got, want := string(raw["ticket_versions"]), "["+strconv.Itoa(ticket.Version)+"]"; got != want {
		t.Errorf("ticket_versions %s, want %s", got, want)
	}
	if got, want := string(raw["hub_key_id"]), strconv.Quote(ticket.KeyID(hubPub)); got != want {
		t.Errorf("hub_key_id %s, want %s", got, want)
	}
	_, lockPriv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := hubclient.New(hubclient.Config{URL: srv.URL, Instance: "crm-prod", Key: lockPriv, HubKey: hubPub, StateFile: filepath.Join(dir, "client.json")})
	if err != nil {
		t.Fatal(err)
	}
	if hh, err := c.Hello(context.Background()); err != nil || hh.Name != "lockhub" || hh.API != 1 {
		t.Errorf("lockkit hub client: %+v %v", hh, err)
	}
}
