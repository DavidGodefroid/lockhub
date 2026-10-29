// Package hubtest is a fake ticket codec and a ready-made hub for tests.
// Its wire format is not lockkit's: tests of the real format live with
// the lockkit codec.
package hubtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// Ticket is the fake ticket.
type Ticket struct {
	ID       string `json:"id"`
	Instance string `json:"instance"`
	KeyID    string `json:"key_id"`
	Risk     string `json:"risk"`
	PlanHash string `json:"plan_hash"`
	Created  int64  `json:"created"`
	TTL      int64  `json:"ttl_s"`
	Sig      string `json:"sig,omitempty"`
}

// Decision is the fake decision.
type Decision struct {
	Ticket   string `json:"ticket"`
	Instance string `json:"instance"`
	KeyID    string `json:"key_id"`
	PlanHash string `json:"plan_hash"`
	Approved bool   `json:"approved"`
	Approver string `json:"approver"`
	Facade   string `json:"facade"`
	At       int64  `json:"at"`
	Sig      string `json:"sig,omitempty"`
}

// Codec is the fake codec.
type Codec struct{}

const reqContext = "lockhub-request-v1\x00"

func (Codec) KeyID(k ed25519.PublicKey) string { return "ed25519:" + hex.EncodeToString(k[:16]) }

func requestMessage(method, pq, instance string, at time.Time, nonce string, body []byte) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%x", method, pq, instance, at.Unix(), nonce, sha256.Sum256(body)))
}

func (Codec) VerifyRequest(k ed25519.PublicKey, method, pq, instance string, at time.Time, nonce string, body []byte, sig string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && ed25519.Verify(k, append([]byte(reqContext), requestMessage(method, pq, instance, at, nonce, body)...), raw)
}

func (Codec) VerifyTicket(k ed25519.PublicKey, raw []byte) (hub.Info, error) {
	var t Ticket
	if err := json.Unmarshal(raw, &t); err != nil {
		return hub.Info{}, err
	}
	sig, _ := base64.StdEncoding.DecodeString(t.Sig)
	t.Sig = ""
	b, _ := json.Marshal(t)
	if !ed25519.Verify(k, b, sig) {
		return hub.Info{}, errors.New("bad signature")
	}
	return hub.Info{ID: t.ID, Instance: t.Instance, KeyID: t.KeyID, Risk: t.Risk, PlanHash: t.PlanHash,
		Created: time.Unix(t.Created, 0), TTL: time.Duration(t.TTL) * time.Second}, nil
}

func (Codec) SignDecision(k ed25519.PrivateKey, t hub.Info, v hub.Verdict, at time.Time) ([]byte, error) {
	d := Decision{Ticket: t.ID, Instance: t.Instance, KeyID: t.KeyID, PlanHash: t.PlanHash,
		Approved: v.Approved, Approver: v.ApproverID, Facade: v.Facade, At: at.Unix()}
	b, _ := json.Marshal(d)
	d.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(k, b))
	return json.Marshal(d)
}

// Lock is a fake lock instance.
type Lock struct {
	Instance string
	Pub      ed25519.PublicKey
	Priv     ed25519.PrivateKey
}

// NewLock makes a lock with a fresh key.
func NewLock(instance string) Lock {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return Lock{instance, pub, priv}
}

// Ticket signs a fake ticket.
func (l Lock) Ticket(id, risk string, created time.Time, ttl time.Duration) []byte {
	t := Ticket{ID: id, Instance: l.Instance, KeyID: Codec{}.KeyID(l.Pub), Risk: risk,
		PlanHash: "sha256:" + id, Created: created.Unix(), TTL: int64(ttl / time.Second)}
	b, _ := json.Marshal(t)
	t.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.Priv, b))
	out, _ := json.Marshal(t)
	return out
}

// Sign adds the Lock-* headers to req for body, as of now.
func (l Lock) Sign(req *http.Request, body []byte, now time.Time) {
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce, ts := hex.EncodeToString(nb), strconv.FormatInt(now.Unix(), 10)
	sig := ed25519.Sign(l.Priv, append([]byte(reqContext), requestMessage(req.Method, req.URL.RequestURI(), l.Instance, now, nonce, body)...))
	req.Header.Set("Lock-Instance", l.Instance)
	req.Header.Set("Lock-Time", ts)
	req.Header.Set("Lock-Nonce", nonce)
	req.Header.Set("Lock-Sig", base64.RawURLEncoding.EncodeToString(sig))
}

// Clock is a settable clock.
type Clock struct{ T time.Time }

func (c *Clock) Now() time.Time { return c.T }

// Env is a hub on temp storage.
type Env struct {
	Hub   *hub.Hub
	Store *store.Store
	Audit string
	Clock *Clock
	Pub   ed25519.PublicKey
}

// New builds a hub for locks, MaxPending max (0: default).
func New(t testing.TB, max int, locks ...Lock) Env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ap := filepath.Join(dir, "tickets.jsonl")
	al, err := audit.Open(ap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := map[string]ed25519.PublicKey{}
	for _, l := range locks {
		m[l.Instance] = l.Pub
	}
	clk := &Clock{T: time.Unix(1_800_000_000, 0)}
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: Codec{}, Key: priv, Locks: m, MaxPending: max, Now: clk.Now})
	return Env{Hub: h, Store: st, Audit: ap, Clock: clk, Pub: pub}
}
