package loxrun

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeConsoles is the locks' consoles in memory: the answers typed at
// them are recorded.
type fakeConsoles struct {
	ch      chan ConsoleEvent
	mu      sync.Mutex
	answers []string
	seq     map[string]int
	typed   chan string
}

func newFakeConsoles() *fakeConsoles {
	return &fakeConsoles{ch: make(chan ConsoleEvent, 16), seq: map[string]int{}, typed: make(chan string, 16)}
}

func (f *fakeConsoles) Events() <-chan ConsoleEvent { return f.ch }

func (f *fakeConsoles) Answer(instance string, seq int, answer []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seq[instance] != seq {
		return errors.New("the console no longer asks this question")
	}
	a := string(answer)
	f.answers = append(f.answers, instance+"="+a)
	f.typed <- a
	return nil
}

// ask makes instance's console ask prompt, with the lines above it.
func (f *fakeConsoles) ask(instance, prompt string, context ...string) {
	f.mu.Lock()
	f.seq[instance]++
	seq := f.seq[instance]
	f.mu.Unlock()
	f.ch <- ConsoleEvent{Instance: instance, Lock: "locksql", State: ConsoleWaiting,
		Question: &ConsoleQuestion{Seq: seq, Prompt: prompt, Context: context}}
}

func (f *fakeConsoles) state(instance string, s ConsoleState, msg string) {
	f.ch <- ConsoleEvent{Instance: instance, Lock: "locksql", State: s, Err: msg}
}

func (h *harness) typedAt(f *fakeConsoles) string {
	h.t.Helper()
	select {
	case a := <-f.typed:
		return a
	case <-time.After(5 * time.Second):
		h.t.Fatalf("nothing typed at the console; output:\n%s", h.output())
	}
	return ""
}

func TestClassify(t *testing.T) {
	for _, c := range []struct{ prompt, kind, yes string }{
		{"Apply these changes? [y/N]", cqYesNo, "y"},
		{"Trust this key and add it to /home/locksql/.ssh/known_hosts? [yes/N]", cqYesNo, "yes"},
		{`Type the profile name "shop-prod" to continue:`, cqTyped, ""},
		{"Type the last 8 characters of the fingerprint to trust it:", cqTyped, ""},
		{"Passphrase for /home/locksql/.ssh/bastion_key:", cqSecret, ""},
		{"Password for app_ro@10.0.0.5:", cqSecret, ""},
		{"Vault token for https://vault:8200:", cqSecret, ""},
		{"Type your password:", cqSecret, ""},
		{"Something new:", cqSecret, ""}, // unknown: never shown in clear
	} {
		if k, y := classify(c.prompt); k != c.kind || y != c.yes {
			t.Errorf("%q: %s %q, want %s %q", c.prompt, k, y, c.kind, c.yes)
		}
	}
}

// A fresh production lock with an SSH bastion: every start question of
// its console is a card in lox run, answered there, typed at the
// console's terminal; the header says what it waits for; a secret shows
// as dots only.
func TestConsoleStartQuestions(t *testing.T) {
	cons := newFakeConsoles()
	h := start(t, newFakeHub(), nil, func(s *Session) {
		s.Consoles = cons
		s.Size = func() (int, int) { return 120, 40 }
		s.Style = Style{Unicode: true}
	})
	cons.state("shop-prod", ConsoleStarting, "")

	cons.ask("shop-prod", "Apply these changes? [y/N]", "PRODUCTION profile shop-prod", "  limits.idle_timeout  10m -> 60m")
	h.wait(EvQuestion, "")
	waitOutput(t, h, "waiting for you: Apply these changes? [y/N]")
	waitOutput(t, h, "idle_timeout  10m -> 60m")
	waitOutput(t, h, "PRODUCTION")
	h.keys <- R('y')
	if a := h.typedAt(cons); a != "y" {
		t.Fatalf("policy review: typed %q", a)
	}

	cons.ask("shop-prod", `Type the profile name "shop-prod" to continue:`)
	h.wait(EvQuestion, "")
	waitOutput(t, h, "Type the profile name")
	typeIn(h, "shop-prod")
	if a := h.typedAt(cons); a != "shop-prod" {
		t.Fatalf("retype: typed %q", a)
	}

	cons.ask("shop-prod", "Trust this key and add it to /home/locksql/.ssh/known_hosts? [yes/N]", "ED25519 key fingerprint is SHA256:abcdefgh12345678")
	h.wait(EvQuestion, "")
	waitOutput(t, h, "SHA256:abcdefgh12345678")
	h.keys <- R('y')
	if a := h.typedAt(cons); a != "yes" {
		t.Fatalf("host key: typed %q", a)
	}

	cons.ask("shop-prod", "Passphrase for /home/locksql/.ssh/bastion_key:")
	h.wait(EvQuestion, "")
	for _, r := range "s3cret-pass" {
		h.keys <- R(r)
	}
	waitOutput(t, h, "•••••••••••")
	h.keys <- Key{Code: KeyEnter}
	if a := h.typedAt(cons); a != "s3cret-pass" {
		t.Fatalf("passphrase: typed %q", a)
	}

	cons.ask("shop-prod", "Password for app_ro@10.0.0.5:")
	h.wait(EvQuestion, "")
	typeIn(h, "db-pw-123")
	if a := h.typedAt(cons); a != "db-pw-123" {
		t.Fatalf("password: typed %q", a)
	}
	cons.state("shop-prod", ConsoleServing, "")
	waitOutput(t, h, "shop-prod serving")

	out := h.output()
	for _, secret := range []string{"s3cret-pass", "db-pw-123"} {
		if strings.Contains(out, secret) {
			t.Errorf("the secret %q is on lox run's screen", secret)
		}
	}
}

// The console restarted after its idle end asks the same things again:
// Enter alone gives this session's answers, a policy review is always
// answered anew, and an answer the console refused (asked again at once)
// is dropped.
func TestConsoleRestartReusesAnswers(t *testing.T) {
	cons := newFakeConsoles()
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	h := start(t, newFakeHub(), nil, func(s *Session) {
		s.Consoles, s.Now, s.Size = cons, clock, func() (int, int) { return 140, 40 }
	})

	cons.ask("shop-prod", `Type the profile name "shop-prod" to continue:`)
	h.wait(EvQuestion, "")
	typeIn(h, "shop-prod")
	h.typedAt(cons)
	cons.ask("shop-prod", "Password for app_ro@10.0.0.5:")
	h.wait(EvQuestion, "")
	typeIn(h, "db-pw-123")
	h.typedAt(cons)
	cons.state("shop-prod", ConsoleServing, "")

	// Idle end: it exits, Docker starts it again, it asks again.
	advance(11 * time.Minute)
	cons.state("shop-prod", ConsoleStopped, "session ended: idle for 10m0s")
	cons.ask("shop-prod", `Type the profile name "shop-prod" to continue:`)
	h.wait(EvQuestion, "")
	waitOutput(t, h, "(Enter alone: this session's)")
	h.keys <- Key{Code: KeyEnter}
	if a := h.typedAt(cons); a != "shop-prod" {
		t.Fatalf("retype again: %q", a)
	}
	cons.ask("shop-prod", "Password for app_ro@10.0.0.5:")
	h.wait(EvQuestion, "")
	h.keys <- Key{Code: KeyEnter}
	if a := h.typedAt(cons); a != "db-pw-123" {
		t.Fatalf("password again: %q", a)
	}
	// Refused (the password changed): asked again at once, Enter alone
	// gives nothing now.
	advance(time.Second)
	cons.ask("shop-prod", "Password for app_ro@10.0.0.5:")
	h.wait(EvQuestion, "")
	h.keys <- Key{Code: KeyEnter}
	waitOutput(t, h, "empty")
	h.keys <- Key{Code: KeyEsc}
	h.keys <- R('y')
	typeIn(h, "new-pw")
	if a := h.typedAt(cons); a != "new-pw" {
		t.Fatalf("new password: %q", a)
	}
	// A policy review is never answered for the human.
	cons.ask("shop-prod", "Apply these changes? [y/N]")
	h.wait(EvQuestion, "")
	h.keys <- Key{Code: KeyEnter}
	select {
	case a := <-cons.typed:
		t.Fatalf("Enter answered a policy review: %q", a)
	case <-time.After(100 * time.Millisecond):
	}
	h.keys <- R('n')
	if a := h.typedAt(cons); a != "n" {
		t.Fatalf("review: %q", a)
	}
}

// A question answered at the console's terminal (lox attach) or a console
// that stopped takes its card away; x forgets the answers kept.
func TestConsoleCardGoes(t *testing.T) {
	cons := newFakeConsoles()
	h := start(t, newFakeHub(), nil, func(s *Session) {
		s.Consoles = cons
		s.Size = func() (int, int) { return 120, 30 }
	})
	cons.ask("shop", "Password for app@db:")
	h.wait(EvQuestion, "")
	cons.state("shop", ConsoleServing, "")
	waitOutput(t, h, "shop serving")
	cons.state("shop", ConsoleStopped, "console: cannot connect: password authentication failed")
	waitOutput(t, h, "stopped: console: cannot connect")
	typeIn(h, "late")
	select {
	case a := <-cons.typed:
		t.Fatalf("typed into a card that went away: %q", a)
	case <-time.After(100 * time.Millisecond):
	}

	cons.ask("shop", "Password for app@db:")
	h.wait(EvQuestion, "")
	typeIn(h, "pw1")
	h.typedAt(cons)
	cons.ask("shop", "Password for app@db:")
	h.wait(EvQuestion, "")
	h.keys <- Key{Code: KeyEsc}
	h.keys <- R('x')
	waitOutput(t, h, "forgot the answers typed to shop's console")
	h.keys <- R('y')
	h.keys <- Key{Code: KeyEnter}
	waitOutput(t, h, "empty")
	cons.mu.Lock()
	defer cons.mu.Unlock()
	if !slices.Equal(cons.answers, []string{"shop=pw1"}) {
		t.Errorf("answers: %q", cons.answers)
	}
}

func waitOutput(t *testing.T, h *harness, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(h.output(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q on screen:\n%s", want, h.output())
}
