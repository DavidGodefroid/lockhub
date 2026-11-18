package loxrun

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// unattended is a lox live session: no keys, no terminal, facade live.
func unattended(s *Session) {
	s.Unattended, s.Facade, s.Keys = true, route.Live, nil
}

// waitLeft waits until ticket id was left to a human's facade.
func (h *harness) waitLeft(id string) Event {
	h.t.Helper()
	return h.wait(EvLeft, id)
}

// A lox live session decides what a rule decides, under facade live, and
// leaves everything else pending at the hub: no card, no question, no
// decision.
func TestUnattendedDecidesByRuleOnly(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	rules := ProfileRules{ActConnect: Allow, ActRead: Allow, ActWrite: Deny}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		unattended(s)
		s.Rules = func(lock, instance, profile string) ProfileRules {
			if profile == "prod" {
				return rules
			}
			return nil
		}
	})

	read := lk.item(t, ticket.KindRead, ticket.RiskRead, "prod", "SELECT 1", nil)
	hub.push(read)
	if d := h.wait(EvDecided, read.ID); !d.Approved || d.Rule != "profile:read" {
		t.Fatalf("read: %+v", d)
	}
	if d, _ := hub.decision(read.ID); d.Facade != route.Live || d.Rule != "profile:read" || !d.Approved || d.Asked != "" {
		t.Fatalf("read decision sent as %+v", d)
	}
	// connect = auto in the profile's rules: no question per session.
	conn := lk.item(t, ticket.KindConnect, ticket.RiskRead, "prod", "connect", func(tk *ticket.Ticket) {
		tk.Subject.Endpoint, tk.Subject.Credential = "db:5432", ticket.CredentialVault
	})
	hub.push(conn)
	if d := h.wait(EvDecided, conn.ID); !d.Approved || d.Rule != "profile:connect" {
		t.Fatalf("connect: %+v", d)
	}
	// A deny rule refuses, by the rule.
	wr := lk.item(t, ticket.KindWrite, ticket.RiskWrite, "prod", "DELETE", nil)
	hub.push(wr)
	if d := h.wait(EvDecided, wr.ID); d.Approved || d.Rule != "deny:write" {
		t.Fatalf("write: %+v", d)
	}
	if d, _ := hub.decision(wr.ID); d.Facade != route.Live || d.Approved {
		t.Fatalf("write decision sent as %+v", d)
	}

	// Everything a human decides is left pending: a connect of a profile
	// with no rule (asked once per session in lox run), a write, a DDL, a
	// grant, a never-auto read, a typed name, typed values, a policy
	// loosening, a ticket lox live cannot check.
	other := newLockKey()
	left := []api.QueueItem{
		lk.item(t, ticket.KindConnect, ticket.RiskRead, "dev", "connect", func(tk *ticket.Ticket) {
			tk.Subject.Endpoint, tk.Subject.Credential = "db:5432", ticket.CredentialVault
		}),
		lk.item(t, ticket.KindWrite, ticket.RiskWrite, "dev", "UPDATE", nil),
		lk.item(t, ticket.KindDDL, ticket.RiskWrite, "dev", "DROP", nil),
		lk.item(t, ticket.KindRead, ticket.RiskGrant, "prod", "grant", func(tk *ticket.Ticket) { tk.Flags.NeverAuto = true }),
		lk.item(t, ticket.KindRead, ticket.RiskRead, "prod", "SELECT", func(tk *ticket.Ticket) { tk.Flags.NeverAuto = true }),
		lk.item(t, ticket.KindPolicy, ticket.RiskPolicyLoosen, "prod", "policy", nil),
		lk.item(t, ticket.KindRead, ticket.RiskReadPII, "prod", "unmask", func(tk *ticket.Ticket) { tk.Flags.NeverAuto = true }),
	}
	retype := lk.item(t, ticket.KindRead, ticket.RiskRead, "prod", "SELECT 2", func(tk *ticket.Ticket) { tk.Flags.Production = true })
	retype.Retype = "shop"
	left = append(left, retype)
	for _, it := range left {
		hub.push(it)
		h.waitLeft(it.ID)
	}
	_ = other
	time.Sleep(100 * time.Millisecond)
	for _, it := range left {
		if d, ok := hub.decision(it.ID); ok {
			t.Errorf("lox live decided %s: %+v", it.ID, d)
		}
	}
	out := h.output()
	for _, bad := range []string{"answer: y approve", "\a", "╭", "+--"} {
		if strings.Contains(out, bad) {
			t.Errorf("a question was shown (%q):\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "left to a human") {
		t.Errorf("the log does not say the tickets are left to a human:\n%s", out)
	}
}

// The hub wants a human after all (needs_human): left, never asked here.
func TestUnattendedHubWantsAHuman(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	hub.refuse = func(id string, req api.DecideRequest) error {
		return &approve.HubError{Status: 409, Kind: "needs_human", Message: "never decided by an auto rule"}
	}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, unattended)
	it := lk.item(t, ticket.KindRead, ticket.RiskRead, "prod", "SELECT 1", nil)
	hub.push(it)
	h.waitLeft(it.ID)
	if _, ok := hub.decision(it.ID); ok {
		t.Fatal("decided")
	}
}

// A ticket that does not verify under the pinned lock key is refused with
// the reason, under facade live, as lox run refuses it.
func TestUnattendedRefusesUnreadable(t *testing.T) {
	lk, other := newLockKey(), newLockKey()
	hub := newFakeHub()
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": other.pub}, unattended)
	it := lk.item(t, ticket.KindRead, ticket.RiskRead, "prod", "SELECT 1", nil)
	hub.push(it)
	h.wait(EvDecided, it.ID)
	if d, _ := hub.decision(it.ID); d.Approved || d.Facade != route.Live || d.Rule != "" || !strings.Contains(d.Reason, "ticket rejected") {
		t.Fatalf("refusal sent as %+v", d)
	}
}

// consoleStatus waits for the status of instance's console that has
// blocked (any when "").
func (h *harness) consoleStatus(instance, blocked string) ConsoleStatus {
	h.t.Helper()
	to := time.After(5 * time.Second)
	for {
		select {
		case e := <-h.events:
			if e.Kind == EvConsole && e.Instance == instance && e.Console != nil && e.Console.Blocked == blocked {
				return *e.Console
			}
		case <-to:
			h.t.Fatalf("no console status %q for %s; output:\n%s", blocked, instance, h.output())
		}
	}
}

// lox live types nothing at a console but the Vault token: a password, a
// production name, a policy to review and a host key to trust stay
// unanswered, and the lock's state says which.
func TestUnattendedNeverAnswersAConsole(t *testing.T) {
	cons := newFakeConsoles()
	fv := &fakeVaultCLI{}
	h := start(t, newFakeHub(), nil, func(s *Session) { unattended(s); s.Consoles = cons; s.Vault = fv.vault("vaulted") })
	for _, c := range []struct {
		prompt  string
		context []string
		want    string
	}{
		{"Password for app@db.internal: ", nil, BlockedSecret},
		{"Passphrase for /home/lockssh/.ssh/id: ", nil, BlockedSecret},
		{"User: ", nil, BlockedSecret},
		{"Vault token for https://other.example:8200: ", nil, BlockedSecret},
		{`Type the profile name "prod" to continue: `, []string{"  ⚠ PRODUCTION profile prod (db.internal)"}, BlockedEnrolment},
		{"Approve this policy? [y/N] ", []string{"First start of profile dev: review its policy."}, BlockedEnrolment},
		{`Apply? Type the profile name "prod" to apply: `, []string{"The policy of profile prod changed since it was approved:", "  + allow write"}, BlockedEnrolment},
		{"Apply these changes? [y/N] ", []string{"The policy of profile dev changed since it was approved:"}, BlockedEnrolment},
		{"Trust this host key? [yes/N] ", []string{"The authenticity of host web1 can't be established."}, BlockedRefused},
		{"Type the last 8 characters of the fingerprint to trust it: ", nil, BlockedRefused},
		{"Save in OS keychain? [y/N] ", nil, BlockedRefused},
	} {
		cons.ask("shop", c.prompt, c.context...)
		st := h.consoleStatus("shop", c.want)
		if st.State != ConsoleWaiting || st.Detail == "" {
			t.Errorf("%q: status %+v", c.prompt, st)
		}
	}
	// A lock without vault_token: cli is never handed the host's token.
	cons.ask("shop", "Vault token for "+vaultAddr+": ")
	h.consoleStatus("shop", BlockedSecret)
	select {
	case a := <-cons.typed:
		t.Fatalf("lox live typed %q at a console", a)
	case <-time.After(150 * time.Millisecond):
	}
	if fv.count() != 0 {
		t.Error("the host's Vault token was read for a question that is not its lock's")
	}
	if out := h.output(); strings.Contains(out, "answer: type it") || strings.Contains(out, "\a") {
		t.Errorf("a question was shown:\n%s", out)
	}
	// It serves again once a human answered at the console (lox attach).
	cons.state("shop", ConsoleServing, "")
	if st := h.consoleStatus("shop", ""); st.State != ConsoleServing {
		t.Errorf("status %+v", st)
	}
}

// clock is a settable time for a session.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// The Vault token question of a vault_token: cli lock is answered with
// the host's token, again each time the console asks (a restart, an
// expiry). A token the host cannot give, or one the lock refused, is not
// typed again and again: the lock is missing_secret, and it is tried
// again later.
func TestUnattendedVaultTokenPrompt(t *testing.T) {
	cons := newFakeConsoles()
	fv := &fakeVaultCLI{}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	h := start(t, newFakeHub(), nil, func(s *Session) {
		unattended(s)
		s.Consoles, s.Vault, s.Now, s.VaultRetry = cons, fv.vault("shop"), clk.now, time.Minute
	})
	prompt := "Vault token for " + vaultAddr + ": "
	cons.ask("shop", prompt)
	if a := h.typedAt(cons); a != cliToken {
		t.Fatalf("typed %q", a)
	}
	fv.wiped(t)
	cons.state("shop", ConsoleServing, "")
	h.consoleStatus("shop", "")

	// Much later the console restarts and asks again: answered again.
	clk.add(2 * time.Hour)
	cons.ask("shop", prompt)
	if a := h.typedAt(cons); a != cliToken {
		t.Fatalf("typed %q the second time", a)
	}
	// Asked again at once: the lock refused the token. Not typed again
	// right away.
	cons.ask("shop", prompt)
	if st := h.consoleStatus("shop", BlockedSecret); !strings.Contains(st.Detail, "refused") {
		t.Errorf("status %+v", st)
	}
	if n := fv.count(); n != 2 {
		t.Fatalf("the token was read %d times", n)
	}
	// After VaultRetry it is read and typed again (Vault Agent may have
	// written a new one).
	clk.add(2 * time.Minute)
	if a := h.typedAt(cons); a != cliToken {
		t.Fatalf("typed %q after the retry delay", a)
	}

	// The host has no usable token: missing_secret with the reason, tried
	// again after the delay.
	fv.mu.Lock()
	fv.fail = errors.New("no Vault CLI token on this host (~/.vault-token)")
	fv.mu.Unlock()
	clk.add(2 * time.Hour)
	cons.ask("shop", prompt)
	if st := h.consoleStatus("shop", BlockedSecret); !strings.Contains(st.Detail, "no Vault CLI token") {
		t.Errorf("status %+v", st)
	}
	fv.mu.Lock()
	fv.fail = nil
	fv.mu.Unlock()
	clk.add(2 * time.Minute)
	if a := h.typedAt(cons); a != cliToken {
		t.Fatalf("typed %q once the token is back", a)
	}
	if strings.Contains(h.output(), cliToken) {
		t.Fatalf("the token in the log:\n%s", h.output())
	}
}

// A connect whose rule is auto and whose lock asks for its Vault token
// again (it expired) is approved by the rule with the host's token sealed
// to the lock. Without a usable token, or for a password, it is left to
// a human.
func TestUnattendedVaultConnect(t *testing.T) {
	lk := newLockKey()
	hub := newFakeHub()
	fv := &fakeVaultCLI{}
	h := start(t, hub, map[string]ed25519.PublicKey{"shop": lk.pub}, func(s *Session) {
		unattended(s)
		s.Vault = fv.vault("shop")
		s.Rules = func(lock, instance, profile string) ProfileRules { return ProfileRules{ActConnect: Allow} }
	})
	k1 := x25519(t)
	c1 := vaultConnectItem(t, lk, k1)
	hub.push(c1)
	if d := h.wait(EvDecided, c1.ID); !d.Approved || d.Rule != "profile:connect" {
		t.Fatalf("connect: %+v", d)
	}
	if d, _ := hub.decision(c1.ID); d.Facade != route.Live || d.Rule != "profile:connect" {
		t.Fatalf("sent as %+v", d)
	}
	if s := sealed(t, hub, lk, c1, k1); s != cliToken {
		t.Fatalf("sealed %q", s)
	}
	fv.wiped(t)

	fv.mu.Lock()
	fv.fail = errors.New("the Vault CLI's token expired")
	fv.mu.Unlock()
	c2 := vaultConnectItem(t, lk, x25519(t))
	hub.push(c2)
	h.waitLeft(c2.ID)

	// A password (credentials: ask) is a human's to type.
	k3 := x25519(t)
	c3 := lk.connectItem(t, "inventory", k3)
	hub.push(c3)
	h.waitLeft(c3.ID)
	time.Sleep(100 * time.Millisecond)
	for _, it := range []api.QueueItem{c2, c3} {
		if _, ok := hub.decision(it.ID); ok {
			t.Errorf("%s decided", it.ID)
		}
	}
}
