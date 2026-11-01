package family

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// upReview runs lox up in w's workspace with the given options.
func upReview(w ws, ctx context.Context, in io.Reader, review bool, f *fake) (string, error) {
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
		Run: f, In: bufio.NewReader(in), Out: &out, Review: review}
	err := u.Do(ctx)
	return out.String(), err
}

func TestHubOnlyFirstUpAsksNothing(t *testing.T) {
	w := newWS(t, hubOnly)
	f := newFake()
	out, err := upReview(w, context.Background(), strings.NewReader(""), false, f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "Apply? [y/N]") {
		t.Errorf("asked a question:\n%s", out)
	}
	if !strings.Contains(out, "Hub only, no lock: nothing can reach a credential yet; applied without a question (--review shows everything and asks)") {
		t.Errorf("no notice:\n%s", out)
	}
	if !f.ran("up -d") {
		t.Errorf("not applied: %v", f.calls)
	}
}

func TestHubOnlyReviewFlagAsks(t *testing.T) {
	w := newWS(t, hubOnly)
	f := newFake()
	out, err := upReview(w, context.Background(), strings.NewReader("n\n"), true, f)
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "Apply? [y/N]") || f.ran("up -d") {
		t.Errorf("--review: %v %v\n%s", err, f.calls, out)
	}
}

func TestRemoveLastLockStillAsks(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(w.file, []byte(hubOnly), 0o644)
	f2 := &fake{keys: f.keys}
	out, err := upReview(w, context.Background(), strings.NewReader("n\n"), false, f2)
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "- lock crm-prod type locksql") || f2.ran("up -d") {
		t.Errorf("removing the last lock: %v %v\n%s", err, f2.calls, out)
	}
}

func TestUpInterruptedAtReviewAppliesNothing(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	var mu sync.Mutex
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
		Run: f, In: bufio.NewReader(pr), Out: &lockedWriter{&mu, &out}}
	// Cancel only once the review is on screen and waiting for the answer.
	go func() {
		for {
			mu.Lock()
			asked := strings.Contains(out.String(), "Apply? [y/N]")
			mu.Unlock()
			if asked {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	err := u.Do(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	if f.ran("up -d") {
		t.Errorf("applied: %v", f.calls)
	}
	if _, err := os.Stat(filepath.Join(w.dir, "state", "applied.json")); err == nil {
		t.Error("applied.json written")
	}
}

// lockedWriter lets a test read the output while Up is still writing it.
type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func tomlProfile(lines ...string) *Profile {
	p := &Profile{Fingerprint: "sha256:abc"}
	for i, l := range lines {
		p.Lines = append(p.Lines, "config.toml:"+strconv.Itoa(i+1)+" "+l)
	}
	return p
}

func TestProfileFacts(t *testing.T) {
	p := tomlProfile(
		`[profiles.shop]`,
		`engine = "mysql"`,
		`host = "other.example.com"`,
		`production = true`,
		``,
		`[profiles.orders]`,
		`engine = "postgres"`,
		`host = "host.docker.internal"`,
		`port = 55432`,
		`database = "orders"   # the orders database`,
		`credentials = "vault"`,
		`vault_path = "database/creds/orders"`,
		`production = false`,
	)
	f := ProfileFacts(p, "locksql", "orders")
	want := Facts{Target: "postgres host.docker.internal:55432, database orders", Credentials: "vault",
		VaultPath: "database/creds/orders", Production: false, Profile: ".locksql/ [profiles.orders] sha256:abc"}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("orders: %+v, want %+v", f, want)
	}
	if s := ProfileFacts(p, "locksql", "shop"); !s.Production || strings.Contains(s.Target, "orders") {
		t.Errorf("shop: %+v", s)
	}
	mq := ProfileFacts(tomlProfile(`[profiles.events]`, `url = "amqp://mq.example.com:5672"`, `vhosts = ["a", "b"]`), "lockmq", "")
	if mq.Target != "amqp://mq.example.com:5672, vhosts a,b" {
		t.Errorf("lockmq: %q", mq.Target)
	}
	if n := ProfileFacts(p, "locksql", ""); n.Target != "" {
		t.Errorf("two profiles and none named: %+v", n)
	}
}

// A value the block cannot show exactly is shown as the profile says it.
func TestProfileFactsOddValues(t *testing.T) {
	for _, c := range []struct {
		name, typ string
		lines     []string
		check     func(Facts) bool
	}{
		{"production string", "locksql", []string{`[profiles.p]`, `production = "yes"`}, func(f Facts) bool { return !f.Production && f.Odd["production"] == `production = "yes"` }},
		{"production number", "locksql", []string{`[profiles.p]`, `production = 1`}, func(f Facts) bool { return !f.Production && f.Odd["production"] != "" }},
		{"multi-line vhosts", "lockmq", []string{`[profiles.p]`, `url = "amqp://mq.example.com"`, `vhosts = [`, `  "a",`, `]`}, func(f Facts) bool {
			return f.Odd["vhosts"] == "vhosts = [" && strings.Contains(f.Target, "? (vhosts = [ in the profile)")
		}},
		{"escaped quote", "locksql", []string{`[profiles.p]`, `database = "or\"ders"`}, func(f Facts) bool {
			return f.Odd["database"] != "" && !strings.Contains(f.Target, "database or") && strings.Contains(f.Target, "? (database = ")
		}},
		{"credentials number", "locksql", []string{`[profiles.p]`, `credentials = 3`}, func(f Facts) bool { return f.Odd["credentials"] != "" }},
		{"exact", "locksql", []string{`[profiles.p]`, `production = true  # yes`, `database = 'orders'`}, func(f Facts) bool { return f.Production && f.Odd == nil && f.Target == "database orders" }},
	} {
		if f := ProfileFacts(tomlProfile(c.lines...), c.typ, "p"); !c.check(f) {
			t.Errorf("%s: %+v", c.name, f)
		}
	}
	// The block prints the raw text, never a wrong fact.
	c := &Config{Locks: map[string]Lock{"o": {Type: "locksql", Image: sqlImg}}}
	var out strings.Builder
	renderShort(&out, c, "", map[string]Facts{"o": ProfileFacts(tomlProfile(`[profiles.p]`, `production = "yes"`), "locksql", "p")}, true, nil)
	if !strings.Contains(out.String(), `  production   ? (production = "yes" in the profile)`) {
		t.Errorf("production row:\n%s", out.String())
	}
}

func TestShortReviewFocus(t *testing.T) {
	c := &Config{Hub: Hub{Image: hubImg}, Vault: &Vault{Address: "https://vault.example.com:8200"}, Locks: map[string]Lock{
		"orders": {Type: "locksql", Image: sqlImg, Vault: true},
		"events": {Type: "lockmq", Image: mqImg},
	}}
	facts := map[string]Facts{"orders": {Target: "postgres host.docker.internal:55432, database orders", Credentials: "vault",
		VaultPath: "database/creds/orders", Profile: ".locksql/ sha256:abc"}, "events": {Target: "never shown"}}
	var out strings.Builder
	renderShort(&out, c, "orders", facts, true, []string{"+ lock events routed only to tty"})
	got := out.String()
	for _, want := range []string{
		"lock orders (locksql)\n",
		"  image        " + sqlImg + " (signature verified)\n",
		"  target       postgres host.docker.internal:55432, database orders\n",
		"  environment  VAULT_ADDR=https://vault.example.com:8200\n",
		"  credentials  vault, database/creds/orders\n",
		"  production   no\n",
		"  profile      .locksql/ sha256:abc  (lox up --review prints it in full)\n",
		"Other changes since the last lox up:\n  + lock events routed only to tty\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "config.toml:") || strings.Contains(got, "lock events (") || strings.Contains(got, "never shown") {
		t.Errorf("shows more than the focus lock:\n%s", got)
	}
}

const shortConf = `version: 1
hub:
  image: ` + hubImg + `
locks:
  orders:
    type: locksql
    image: ` + sqlImg + `
    profile: orders
`

// A hand-edited routing line and a profile line no block renders are
// listed; the profile's other lines are shown only by --review.
func TestShortReviewNeverHidesAChange(t *testing.T) {
	w := newWS(t, shortConf)
	toml := filepath.Join(w.dir, "projects", ".locksql", "config.toml")
	os.WriteFile(toml, []byte("[profiles.orders]\nengine = \"postgres\"\nhost = \"host.docker.internal\"\nreadonly = false\n"), 0o644)
	f := newFake()
	f.keys["orders"] = f.keys["crm-prod"]
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "lock orders (locksql)") || !strings.Contains(out, "target       postgres host.docker.internal\n") {
		t.Errorf("no short block:\n%s", out)
	}
	if strings.Contains(out, "lock orders type locksql") || strings.Contains(out, "lock orders image") || strings.Contains(out, "lock orders profile") {
		t.Errorf("rendered lines repeated:\n%s", out)
	}
	// The profile is not dumped: its block line stands for it.
	if strings.Contains(out, "config.toml:") || strings.Contains(out, "profile locksql ") || strings.Contains(out, "Other changes") || !strings.Contains(out, "Also applied:") {
		t.Errorf("the profile is dumped without --review:\n%s", out)
	}
	if !strings.Contains(out, "profile      .locksql/ [profiles.orders] sha256:") {
		t.Errorf("no profile line:\n%s", out)
	}
	os.WriteFile(w.file, []byte(strings.Replace(shortConf, "hub:\n", "hub:\n  routing:\n    orders: [tty]\n", 1)), 0o644)
	f2 := &fake{keys: f.keys}
	out, err = w.up("n\n", f2)
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "Other changes since the last lox up:") || !strings.Contains(out, "+ lock orders routed only to tty") {
		t.Errorf("edited routing line: %v\n%s", err, out)
	}
}

func TestReviewFlagPrintsProfile(t *testing.T) {
	w := newWS(t, shortConf)
	toml := filepath.Join(w.dir, "projects", ".locksql", "config.toml")
	os.WriteFile(toml, []byte("[profiles.orders]\nengine = \"postgres\"\n"), 0o644)
	f := newFake()
	f.keys["orders"] = f.keys["crm-prod"]
	out, err := upReview(w, context.Background(), strings.NewReader("y\n"), true, f)
	if err != nil || !strings.Contains(out, "config.toml:2 engine = \"postgres\"") {
		t.Fatalf("first --review: %v\n%s", err, out)
	}
	// A later --review prints the profile too, change or not.
	os.WriteFile(toml, []byte("[profiles.orders]\nengine = \"mysql\"\n"), 0o644)
	out, err = upReview(w, context.Background(), strings.NewReader("n\n"), true, &fake{keys: f.keys})
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "config.toml:2 engine = \"mysql\"") {
		t.Errorf("--review after a change: %v\n%s", err, out)
	}
}

func TestVaultCAChangeNote(t *testing.T) {
	w := newWS(t, shortConf)
	f := newFake()
	f.keys["orders"] = f.keys["crm-prod"]
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ca := filepath.Join(w.dir, "ca.pem")
	os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o644)
	conf := strings.Replace(shortConf, "locks:", "vault:\n  address: https://vault.example.com:8200\n  ca_file: "+ca+"\nlocks:", 1) + "    vault: true\n"
	os.WriteFile(w.file, []byte(conf), 0o644)
	out, err := w.up("n\n", &fake{keys: f.keys})
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "vault CA changed: the locks with vault: true restart (lox attach NAME for what they ask)") {
		t.Errorf("CA note: %v\n%s", err, out)
	}
}

func TestShortReviewFoldsTheProfile(t *testing.T) {
	conf := strings.Replace(shortConf, "locks:\n", "locks:\n  gate:\n    type: lockhttp\n    image: ghcr.io/davidgodefroid/lockhttp@sha256:4444444444444444444444444444444444444444444444444444444444444444\n", 1)
	w := newWS(t, conf)
	proj := filepath.Join(w.dir, "projects")
	os.WriteFile(filepath.Join(proj, ".locksql", "config.toml"), []byte("[profiles.orders]\nengine = \"postgres\"\nreadonly = false\n"), 0o644)
	os.Mkdir(filepath.Join(proj, ".lockhttp"), 0o755)
	var pol strings.Builder
	for i := 0; i < 70; i++ {
		pol.WriteString("[[rule]]\nhost = \"api.example.com\"\n")
	}
	os.WriteFile(filepath.Join(proj, ".lockhttp", "policy.toml"), []byte(pol.String()), 0o644)
	f := newFake()
	f.keys["orders"], f.keys["gate"] = pubKey(), pubKey()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, no := range []string{"config.toml:", "policy.toml:", "profile locksql ", "profile lockhttp "} {
		if strings.Contains(out, no) {
			t.Errorf("%q printed without --review:\n%s", no, out)
		}
	}
	if !strings.Contains(out, "profile      .lockhttp/ sha256:") {
		t.Errorf("no lockhttp profile line:\n%s", out)
	}
	// A changed profile says so; --review prints every line.
	os.WriteFile(filepath.Join(proj, ".locksql", "config.toml"), []byte("[profiles.orders]\nengine = \"mysql\"\n"), 0o644)
	out, err = w.up("n\n", &fake{keys: f.keys})
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "(changed since the last lox up; lox up --review shows the lines)") || strings.Contains(out, "+ profile locksql config.toml") {
		t.Errorf("changed profile: %v\n%s", err, out)
	}
	out, _ = upReview(w, context.Background(), strings.NewReader("n\n"), true, &fake{keys: f.keys})
	if !strings.Contains(out, "config.toml:2 engine = \"mysql\"") {
		t.Errorf("--review lacks the lines:\n%s", out)
	}
}

func TestUnknownFocusRefusedEvenUnchanged(t *testing.T) {
	w := newWS(t, shortConf)
	f := newFake()
	f.keys["orders"] = pubKey()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
		Run: &fake{keys: f.keys}, In: bufio.NewReader(strings.NewReader("")), Out: &out, Focus: "nope"}
	if err := u.Do(context.Background()); err == nil || !strings.Contains(err.Error(), "no lock nope") {
		t.Errorf("focus: %v", err)
	}
}
