package loxrun

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
)

const (
	cliToken  = "hvs.cli-token-0123456789abcdef"
	vaultAddr = "http://host.docker.internal:58200"
)

// fakeVaultCLI is the host's Vault CLI: Token gives cliToken (or fail),
// and keeps every copy it handed out, to check the session wiped them.
type fakeVaultCLI struct {
	mu     sync.Mutex
	fail   error
	calls  int
	handed [][]byte
}

func (f *fakeVaultCLI) vault(locks ...string) *VaultCLI {
	m := map[string]bool{}
	for _, l := range locks {
		m[l] = true
	}
	return &VaultCLI{Address: vaultAddr, Locks: m, Token: func(ctx context.Context, instance string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if f.fail != nil {
			return nil, f.fail
		}
		b := []byte(cliToken)
		f.handed = append(f.handed, b)
		return b, nil
	}}
}

func (f *fakeVaultCLI) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// wiped: every token handed to the session was cleared once used.
func (f *fakeVaultCLI) wiped(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		dirty := false
		for _, b := range f.handed {
			if bytes.Contains(b, []byte("hvs.")) {
				dirty = true
			}
		}
		f.mu.Unlock()
		if !dirty {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a token handed to the session was not wiped")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// wide draws frames wide enough for a card's reason and prompt.
func wide(s *Session) {
	s.Size = func() (int, int) { return 200, 50 }
	s.Style = Style{Unicode: true}
}

// noEvent fails if an event of kind comes within d.
func (h *harness) noEvent(kind EventKind, d time.Duration) {
	h.t.Helper()
	to := time.After(d)
	for {
		select {
		case e := <-h.events:
			if e.Kind == kind {
				h.t.Fatalf("unexpected %s: %+v\n%s", kind, e, h.output())
			}
		case <-to:
			return
		}
	}
}

// With vault_token: cli, the console's Vault token prompt for the
// reviewed address is answered with the CLI's token: no card, the feed
// says so, the journal is told cli.
func TestVaultCLIAnswersTheConsolePrompt(t *testing.T) {
	cons := newFakeConsoles()
	fv := &fakeVaultCLI{}
	h := start(t, newFakeHub(), nil, func(s *Session) { s.Consoles = cons; s.Vault = fv.vault("shop") })
	cons.ask("shop", "Vault token for "+vaultAddr+": ")
	if a := h.typedAt(cons); a != cliToken {
		t.Fatalf("typed %q", a)
	}
	if e := h.wait(EvVaultToken, ""); e.Instance != "shop" || e.VaultToken != VaultFromCLI {
		t.Fatalf("journal event %+v", e)
	}
	waitOutput(t, h, "vault token: from CLI")
	fv.wiped(t)
	if strings.Contains(h.output(), cliToken) {
		t.Fatalf("the token on screen:\n%s", h.output())
	}

	// The next question is the console's own: shown as ever.
	cons.ask("shop", `Type "continue" to proceed:`)
	h.wait(EvQuestion, "")
	typeIn(h, "continue")
	if a := h.typedAt(cons); a != "continue" {
		t.Fatalf("typed %q", a)
	}
}

// Another address, another lock, or no Vault CLI set: the human answers.
func TestVaultCLIOnlyForItsPrompt(t *testing.T) {
	for name, c := range map[string]struct {
		instance, prompt string
		locks            []string
	}{
		"other address": {"shop", "Vault token for https://vault.evil.example: ", []string{"shop"}},
		"prefix":        {"shop", "Vault token for " + vaultAddr + "/x: ", []string{"shop"}},
		"ask lock":      {"shop", "Vault token for " + vaultAddr + ": ", []string{"other"}},
		"password":      {"shop", "Password for shop@db:", []string{"shop"}},
	} {
		t.Run(name, func(t *testing.T) {
			cons := newFakeConsoles()
			fv := &fakeVaultCLI{}
			h := start(t, newFakeHub(), nil, func(s *Session) { s.Consoles = cons; s.Vault = fv.vault(c.locks...) })
			cons.ask(c.instance, c.prompt)
			h.wait(EvQuestion, "")
			typeIn(h, "typed-by-human")
			if a := h.typedAt(cons); a != "typed-by-human" {
				t.Fatalf("typed %q", a)
			}
			if fv.count() != 0 {
				t.Errorf("the CLI's token was read for %q", c.prompt)
			}
		})
	}
}

// An unusable CLI token: the card comes, saying why; the human's token
// is typed and the journal says typed.
func TestVaultCLIFallsBackToTheHuman(t *testing.T) {
	cons := newFakeConsoles()
	fv := &fakeVaultCLI{fail: errors.New("the Vault CLI's token is expired or revoked (vault login again)")}
	h := start(t, newFakeHub(), nil, func(s *Session) { s.Consoles = cons; s.Vault = fv.vault("shop"); wide(s) })
	cons.ask("shop", "Vault token for "+vaultAddr+": ")
	h.wait(EvQuestion, "")
	waitOutput(t, h, "the Vault CLI's token cannot be used: the Vault CLI's token is expired or revoked")
	typeIn(h, "hvs.typed")
	if a := h.typedAt(cons); a != "hvs.typed" {
		t.Fatalf("typed %q", a)
	}
	if e := h.wait(EvVaultToken, ""); e.VaultToken != VaultTyped {
		t.Fatalf("journal event %+v", e)
	}
}

// The console asks again right after the CLI's token: it refused it,
// and the human is asked, told so.
func TestVaultCLIRefusedByTheLock(t *testing.T) {
	cons := newFakeConsoles()
	fv := &fakeVaultCLI{}
	h := start(t, newFakeHub(), nil, func(s *Session) { s.Consoles = cons; s.Vault = fv.vault("shop"); wide(s) })
	cons.ask("shop", "Vault token for "+vaultAddr+": ")
	if a := h.typedAt(cons); a != cliToken {
		t.Fatalf("typed %q", a)
	}
	cons.ask("shop", "Vault token for "+vaultAddr+": ")
	h.wait(EvQuestion, "")
	waitOutput(t, h, "the Vault CLI's token cannot be used: the lock refused it")
	if fv.count() != 1 {
		t.Errorf("CLI read %d times", fv.count())
	}
}

func vaultConnectItem(t *testing.T, k lockKey, priv *ecdh.PrivateKey) api.QueueItem {
	return k.item(t, ticket.KindConnect, ticket.RiskRead, "inventory", "connect", func(tk *ticket.Ticket) {
		tk.Subject.Endpoint = "db.internal:5432"
		tk.Subject.Credential = ticket.CredentialVault
		tk.Subject.SecretTo = ticket.EncodeX25519(priv.PublicKey())
	})
}

func x25519(t *testing.T) *ecdh.PrivateKey {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A vault connect (the lock's token expired) keeps its y/n; on y the
// CLI's token is read again and sealed, no prompt shown. Unusable, the
// prompt comes with the reason; typed, it is sealed.
func TestVaultCLIConnectTicket(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	fv := &fakeVaultCLI{}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) { s.Vault = fv.vault("shop"); wide(s) })

	k1 := x25519(t)
	c1 := vaultConnectItem(t, lk, k1)
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	if fv.count() != 0 {
		t.Fatal("the CLI's token read before y")
	}
	h.keys <- R('y')
	h.wait(EvDecided, c1.ID)
	if s := sealed(t, hub, lk, c1, k1); s != cliToken {
		t.Fatalf("sealed %q", s)
	}
	if e := h.wait(EvVaultToken, c1.ID); e.VaultToken != VaultFromCLI {
		t.Fatalf("journal %+v", e)
	}
	if strings.Contains(h.output(), "Vault token for") {
		t.Fatalf("a prompt was shown:\n%s", h.output())
	}
	fv.wiped(t)

	fv.mu.Lock()
	fv.fail = errors.New("the Vault CLI's token lacks read on secret/data/shop")
	fv.mu.Unlock()
	k2 := x25519(t)
	c2 := vaultConnectItem(t, lk, k2)
	hub.push(c2)
	h.wait(EvQuestion, c2.ID)
	h.keys <- R('y')
	waitOutput(t, h, "(its token expired; the Vault CLI's token lacks read on secret/data/shop):")
	typeIn(h, "hvs.typed-token")
	h.wait(EvDecided, c2.ID)
	if s := sealed(t, hub, lk, c2, k2); s != "hvs.typed-token" {
		t.Fatalf("sealed %q", s)
	}
	if e := h.wait(EvVaultToken, c2.ID); e.VaultToken != VaultTyped {
		t.Fatalf("journal %+v", e)
	}
}

// With vault_token: ask (no VaultCLI for the lock), the vault connect
// asks the token as before.
func TestVaultAskConnectUnchanged(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	fv := &fakeVaultCLI{}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) { s.Vault = fv.vault("other"); wide(s) })
	k1 := x25519(t)
	c1 := vaultConnectItem(t, lk, k1)
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	waitOutput(t, h, "Vault token for shop/inventory (db.internal:5432) (its token expired):")
	typeIn(h, "hvs.typed")
	h.wait(EvDecided, c1.ID)
	if s := sealed(t, hub, lk, c1, k1); s != "hvs.typed" {
		t.Fatalf("sealed %q", s)
	}
	if fv.count() != 0 {
		t.Error("the CLI's token read for an ask lock")
	}
	h.noEvent(EvVaultToken, 100*time.Millisecond)
}

// The CLI's token is nowhere but in the sealed box: not on the screen
// (frames drawn), the feed, the events the journal is told, nor the
// hub's decisions outside their sealed box.
func TestVaultCLITokenLeaksNowhere(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	cons := newFakeConsoles()
	fv := &fakeVaultCLI{}
	var evMu sync.Mutex
	var events []Event
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		s.Consoles = cons
		s.Vault = fv.vault("shop")
		s.Size = func() (int, int) { return 120, 40 }
		s.Style = Style{Unicode: true, Color: true}
		obs := s.Observe
		s.Observe = func(e Event) {
			evMu.Lock()
			events = append(events, e)
			evMu.Unlock()
			obs(e)
		}
	})
	cons.ask("shop", "Vault token for "+vaultAddr+": ")
	h.typedAt(cons)
	h.wait(EvVaultToken, "")
	k1 := x25519(t)
	c1 := vaultConnectItem(t, lk, k1)
	hub.push(c1)
	h.wait(EvQuestion, c1.ID)
	h.keys <- R('y')
	h.wait(EvDecided, c1.ID)
	h.wait(EvVaultToken, c1.ID)
	waitOutput(t, h, "vault token: from CLI")
	fv.wiped(t)

	if strings.Contains(h.output(), cliToken) {
		t.Errorf("the token on screen")
	}
	evMu.Lock()
	ej, _ := json.Marshal(events)
	evMu.Unlock()
	if strings.Contains(string(ej), cliToken) {
		t.Errorf("the token in an event: %s", ej)
	}
	d, _ := hub.decision(c1.ID)
	box := d.Secret
	d.Secret = nil
	dj, _ := json.Marshal(d)
	if strings.Contains(string(dj), cliToken) || bytes.Contains(box, []byte(cliToken)) || bytes.Contains(box, []byte("hvs.")) {
		t.Errorf("the token in the hub's request: %s / %s", dj, box)
	}
	if s := sealed(t, hub, lk, c1, k1); s != cliToken {
		t.Errorf("sealed %q", s)
	}
}
