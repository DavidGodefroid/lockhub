package ticketcodec

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
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
		{ticket.RiskRead, 0, ticket.RiskRead.TTL()},
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

// TestLockkitFixturesKinds: a version-2 (kind) ticket of lockkit verifies
// here, and the decision the hub signs on it names its rule and relays the
// secret lox run sealed to the lock, which the lock opens. Fixtures of a
// lockkit before ticket kinds have none: skipped.
func TestLockkitFixturesKinds(t *testing.T) {
	dir, lock, hubKey := fixtures(t)
	raw, err := os.ReadFile(filepath.Join(dir, "ticket-connect-v2.json"))
	if os.IsNotExist(err) {
		t.Skip("lockkit fixtures before ticket kinds")
	}
	if err != nil {
		t.Fatal(err)
	}
	lockPub := lock.Public().(ed25519.PublicKey)
	var c Codec
	info, err := c.VerifyTicket(lockPub, raw)
	if err != nil {
		t.Fatalf("lockkit's connect ticket does not verify: %v", err)
	}
	if info.V != ticket.VersionKinds || info.Kind != string(ticket.KindConnect) || !info.AskSecret {
		t.Fatalf("info %+v: want version 2, kind connect, a secret asked", info)
	}
	tk, _ := ticket.VerifyTicket(lockPub, raw)
	box, err := ticket.SealSecret(tk, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := json.Marshal(box)
	for _, rule := range []string{"", "session:connect"} {
		out, err := c.SignDecision(hubKey, info, hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty", Rule: rule, Secret: sealed}, tk.Created.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		d, err := ticket.VerifyDecision(hubKey.Public().(ed25519.PublicKey), out)
		if err != nil {
			t.Fatalf("hub decision does not verify: %v", err)
		}
		if err := d.Match(tk); err != nil {
			t.Fatalf("decision does not match: %v", err)
		}
		if d.Auto() != (rule != "") || (rule != "" && d.Rule.ID != rule) {
			t.Errorf("rule %+v, want %q", d.Rule, rule)
		}
		var k struct {
			X string `json:"connect_x25519_private"`
		}
		kb, _ := os.ReadFile(filepath.Join(dir, "keys-connect-v2.json"))
		json.Unmarshal(kb, &k)
		privRaw, _ := base64.RawURLEncoding.DecodeString(k.X)
		priv, err := ecdh.X25519().NewPrivateKey(privRaw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.OpenSecret(tk, priv)
		if err != nil || string(got) != "s3cret" {
			t.Errorf("secret %q, %v", got, err)
		}
	}
	// A version-1 ticket's decision names no rule.
	v1, _ := os.ReadFile(filepath.Join(dir, "ticket-v1.json"))
	i1, err := c.VerifyTicket(lockPub, v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignDecision(hubKey, i1, hub.Verdict{Approved: true, ApproverID: "x", Facade: "tty", Rule: "r"}, time.Now()); err == nil {
		t.Error("a version-1 decision named a rule")
	}
}

// A ticket that asks for typed values: the hub sees their names and that
// a sealed box is asked, and relays lox run's box in a decision the lock
// opens to exactly the values typed.
func TestTicketInputs(t *testing.T) {
	lockPub, lock, _ := ed25519.GenerateKey(nil)
	hubPub, hubKey, _ := ed25519.GenerateKey(nil)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewKindTicket(ticket.Source{Lock: "lockfile", Instance: "files", KeyID: ticket.KeyID(lockPub)}, ticket.KindRead,
		ticket.RiskRead, &ticket.Subject{Profile: "dev", Inputs: []string{"needle"}, SecretTo: ticket.EncodeX25519(priv.PublicKey())},
		"sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), time.Now(), time.Hour)
	tk.Flags.NeverAuto = true
	if err := tk.Sign(lock); err != nil {
		t.Fatal(err)
	}
	raw, _ := tk.Marshal()
	var c Codec
	info, err := c.VerifyTicket(lockPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !info.AskInputs || !info.AskSecret || !info.NeverAuto || len(info.Inputs) != 1 || info.Inputs[0] != "needle" {
		t.Fatalf("info %+v: want the inputs asked, sealed, never auto", info)
	}
	box, err := ticket.SealInputs(tk, map[string][]byte{"needle": []byte("alice@example.org")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := json.Marshal(box)
	out, err := c.SignDecision(hubKey, info, hub.Verdict{Approved: true, ApproverID: "host:uid:1000", Facade: "tty", Secret: sealed}, tk.Created.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "alice@example.org") {
		t.Fatal("the decision holds the value in clear")
	}
	d, err := ticket.VerifyDecision(hubPub, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Match(tk); err != nil {
		t.Fatal(err)
	}
	vals, err := d.OpenInputs(tk, priv)
	if err != nil || len(vals) != 1 || string(vals["needle"]) != "alice@example.org" {
		t.Fatalf("opened %q, %v", vals, err)
	}
}
