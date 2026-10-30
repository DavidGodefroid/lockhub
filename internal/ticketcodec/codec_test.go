package ticketcodec

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/hub"
)

// fixtures are lockkit's signed ticket fixtures (a format change in lockkit
// fails here): those of the lockkit this build uses, or of the one
// LOCKKIT_FIXTURES names (a lockkit module directory; scripts/compat.sh).
func fixtures(t *testing.T) (dir string, lock, hubKey ed25519.PrivateKey) {
	t.Helper()
	mod := os.Getenv("LOCKKIT_FIXTURES")
	if mod == "" {
		out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/DavidGodefroid/lockkit").Output()
		if err != nil {
			t.Skipf("go list: %v", err)
		}
		mod = strings.TrimSpace(string(out))
	}
	dir = filepath.Join(mod, "ticket", "testdata")
	b, err := os.ReadFile(filepath.Join(dir, "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var k struct {
		Lock string `json:"lock_ed25519_seed"`
		Hub  string `json:"hub_ed25519_seed"`
	}
	json.Unmarshal(b, &k)
	seed := func(s string) ed25519.PrivateKey {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return ed25519.NewKeyFromSeed(raw)
	}
	return dir, seed(k.Lock), seed(k.Hub)
}

func TestLockkitFixtures(t *testing.T) {
	dir, lock, hubKey := fixtures(t)
	lockPub := lock.Public().(ed25519.PublicKey)
	raw, err := os.ReadFile(filepath.Join(dir, "ticket-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c Codec
	info, err := c.VerifyTicket(lockPub, raw)
	if err != nil {
		t.Fatalf("lockkit's ticket fixture does not verify: %v", err)
	}
	if info.KeyID != c.KeyID(lockPub) || info.ID == "" || info.Instance == "" || info.PlanHash == "" {
		t.Errorf("info %+v", info)
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if _, err := c.VerifyTicket(other, raw); err == nil {
		t.Error("ticket verified with another key")
	}
	for _, name := range []string{"decision-approved-v1.json", "decision-denied-v1.json"} {
		d, _ := os.ReadFile(filepath.Join(dir, name))
		if _, err := ticket.VerifyDecision(hubKey.Public().(ed25519.PublicKey), d); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A decision the hub signs verifies with lockkit and matches the ticket.
	for _, approved := range []bool{true, false} {
		out, err := c.SignDecision(hubKey, info, hub.Verdict{Approved: approved, ApproverID: "host:uid:1000", Facade: "tty", Reason: "ok"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		d, err := ticket.VerifyDecision(hubKey.Public().(ed25519.PublicKey), out)
		if err != nil {
			t.Fatalf("hub decision does not verify: %v", err)
		}
		tk, _ := ticket.VerifyTicket(lockPub, raw)
		if err := d.Match(tk); err != nil {
			t.Errorf("hub decision does not match its ticket: %v", err)
		}
		if (d.Decision == ticket.Approved) != approved || d.Approver.ID != "host:uid:1000" || d.Facade != "tty" {
			t.Errorf("decision %+v", d)
		}
	}
}

func TestRequestSignature(t *testing.T) {
	_, lock, _ := fixtures(t)
	pub := lock.Public().(ed25519.PublicKey)
	at, nonce, body := time.Unix(1_800_000_000, 0), ticket.NewNonce(), []byte(`{"x":1}`)
	msg := ticket.RequestMessage("POST", "/v1/tickets", "crm-prod", at, nonce, body)
	sig := ticket.SignBytes(lock, ticket.ContextRequest, msg)
	var c Codec
	if !c.VerifyRequest(pub, "POST", "/v1/tickets", "crm-prod", at, nonce, body, sig) {
		t.Error("lockkit request signature refused")
	}
	if c.VerifyRequest(pub, "POST", "/v1/tickets", "other", at, nonce, body, sig) {
		t.Error("signature accepted for another instance")
	}
	if c.VerifyRequest(pub, "POST", "/v1/tickets", "crm-prod", at, nonce, []byte(`{"x":2}`), sig) {
		t.Error("tampered body accepted")
	}
	// A signature under another context (a ticket's) is not a request's.
	if c.VerifyRequest(pub, "POST", "/v1/tickets", "crm-prod", at, nonce, body, ticket.SignBytes(lock, ticket.ContextTicket, msg)) {
		t.Error("cross-context signature accepted")
	}
}

func TestTTLClampedToRisk(t *testing.T) {
	_, lock, _ := fixtures(t)
	src := ticket.Source{Lock: "locksql", Instance: "crm-prod"}
	now := time.Now()
	mk := func(risk ticket.Risk, ttl time.Duration) []byte {
		tk := ticket.NewTicket(src, risk, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), now, ttl)
		tk.Workspace, tk.Requester = "ws", ticket.Requester{Agent: "dev-1", Session: "s"}
		tk.Screen = ticket.Screen{Header: "h"}
		if err := tk.Sign(lock); err != nil {
			t.Fatal(err)
		}
		b, _ := tk.Marshal()
		return b
	}
	var c Codec
	pub := lock.Public().(ed25519.PublicKey)
	for _, x := range []struct {
		risk ticket.Risk
		ttl  time.Duration
		want time.Duration
	}{
		{ticket.RiskRead, 0, 0},
		{ticket.RiskWrite, 0, 24 * time.Hour},
		{ticket.RiskWrite, 72 * time.Hour, 24 * time.Hour},
		{ticket.RiskProdWrite, time.Hour, time.Hour},
		{ticket.RiskProdWrite, 0, 4 * time.Hour},
	} {
		info, err := c.VerifyTicket(pub, mk(x.risk, x.ttl))
		if err != nil {
			t.Fatalf("%s: %v", x.risk, err)
		}
		if info.TTL != x.want {
			t.Errorf("%s ttl %v: got %v, want %v", x.risk, x.ttl, info.TTL, x.want)
		}
	}
}
