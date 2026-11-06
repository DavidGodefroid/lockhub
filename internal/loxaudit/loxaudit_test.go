package loxaudit

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/route"
	"github.com/DavidGodefroid/lockhub/internal/store"
	"github.com/DavidGodefroid/lockhub/internal/ticketcodec"
)

// The clear values of the fixtures: none may ever show.
var secrets = []string{"jane.doe@example.com", "hunter2-db-password", "4111111111111111", "SECRET-ROW-VALUE"}

// Fixture is a hub data directory with the exchanges of one afternoon:
// a production connect approved by a human and consumed, an auto read
// carrying personal data (masked on its screen, a clear copy sealed for
// a device, the agent's note quoting it), a write denied on telegram, a
// DDL waiting, a version-1 ticket of an instance with no pinned key,
// withdrawn.
type Fixture struct {
	Data     string
	HubPub   ed25519.PublicKey
	LockKeys map[string]ed25519.PublicKey
	IDs      map[string]string
}

func NewFixture(t *testing.T) Fixture {
	t.Helper()
	f := Fixture{Data: t.TempDir(), IDs: map[string]string{}}
	crmPub, crmPriv, _ := ed25519.GenerateKey(rand.Reader)
	shopPub, shopPriv, _ := ed25519.GenerateKey(rand.Reader)
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	f.HubPub, f.LockKeys = hubPub, map[string]ed25519.PublicKey{"crm": crmPub}
	st, err := store.Open(filepath.Join(f.Data, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	al, err := audit.OpenSigned(filepath.Join(f.Data, "tickets.jsonl"), hubPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	h := hub.New(hub.Config{Store: st, Audit: al, Codec: ticketcodec.Codec{}, Key: hubPriv,
		Locks: map[string]ed25519.PublicKey{"crm": crmPub, "shop": shopPub}, Routes: route.Rules{Enabled: []string{"tty", "telegram"}}})
	ctx := context.Background()
	now := time.Now().Add(-3 * time.Minute).UTC().Truncate(time.Millisecond)
	ph := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	push := func(name, inst string, priv ed25519.PrivateKey, tk *ticket.Ticket) string {
		t.Helper()
		tk.Source.Instance = inst
		tk.Workspace, tk.Requester = "~/shop", ticket.Requester{Agent: "dev-1", Session: "s1"}
		if err := tk.Sign(priv); err != nil {
			t.Fatal(name, err)
		}
		raw, _ := tk.Marshal()
		if _, _, err := h.Push(ctx, inst, raw); err != nil {
			t.Fatal(name, err)
		}
		f.IDs[name] = tk.ID
		return tk.ID
	}
	decide := func(inst, id string, v hub.Verdict) {
		t.Helper()
		if _, err := h.Decide(ctx, store.Ref{Instance: inst, ID: id}, v); err != nil {
			t.Fatal(id, err)
		}
	}
	at := func(s int) time.Time { return now.Add(time.Duration(s) * time.Second) }

	conn, err := ticket.NewConnectTicket(ticket.Source{Lock: "locksql"}, ticket.RiskRead,
		ticket.Subject{Profile: "prod", Endpoint: "db.internal:5432/crm", Credential: ticket.CredentialKeychain}, ph("2"), at(0), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	conn.Flags.Production = true
	conn.Screen = ticket.Screen{Header: "crm / prod · connect", Body: []string{"endpoint: db.internal:5432/crm", "credentials: keychain"}}
	id := push("connect", "crm", crmPriv, conn)
	decide("crm", id, hub.Verdict{Approved: true, ApproverID: "host:uid:1000", ApproverDisplay: "david", Facade: "tty"})
	if err := h.Consumed(ctx, "crm", id); err != nil {
		t.Fatal(err)
	}

	dev, _ := ecdh.X25519().GenerateKey(rand.Reader)
	box, err := ticket.Seal(dev.PublicKey(), []byte("email = "+secrets[0]+" card "+secrets[2]), nil)
	if err != nil {
		t.Fatal(err)
	}
	read := ticket.NewKindTicket(ticket.Source{Lock: "locksql"}, ticket.KindRead, ticket.RiskReadPII,
		&ticket.Subject{Profile: "prod", Target: "customers"}, ph("1"), ph("2"), at(5), time.Hour)
	read.Flags.Production = true
	read.Screen = ticket.Screen{Header: "crm / prod · read", Note: "look up " + secrets[0] + " pw " + secrets[1],
		Body: []string{"SELECT id FROM customers WHERE email = j***(20) AND card = 4***(16)"}}
	read.PII = ticket.PII{Touched: []string{"email", "card"}, ClearSealed: box}
	id = push("read", "crm", crmPriv, read)
	decide("crm", id, hub.Verdict{Approved: true, Facade: "tty", ApproverID: "host:uid:1000", Rule: "default:read"})
	if err := h.Consumed(ctx, "crm", id); err != nil {
		t.Fatal(err)
	}

	write := ticket.NewKindTicket(ticket.Source{Lock: "locksql"}, ticket.KindWrite, ticket.RiskWrite,
		&ticket.Subject{Profile: "dev", Target: "customers"}, ph("3"), ph("2"), at(30), time.Hour)
	write.Screen = ticket.Screen{Header: "crm / dev · write", Body: []string{"UPDATE customers SET email = <redacted> WHERE id = 4***(3)"}}
	id = push("write", "crm", crmPriv, write)
	decide("crm", id, hub.Verdict{Approved: false, Reason: "not now", ApproverID: "telegram:42", ApproverDisplay: "alice", Facade: "telegram"})

	ddl := ticket.NewKindTicket(ticket.Source{Lock: "locksql"}, ticket.KindDDL, ticket.RiskWrite,
		&ticket.Subject{Profile: "dev", Target: "sessions"}, ph("4"), ph("2"), at(60), time.Hour)
	ddl.Screen = ticket.Screen{Header: "crm / dev · ddl", Body: []string{"DROP TABLE sessions"}}
	push("ddl", "crm", crmPriv, ddl)

	v1 := ticket.NewTicket(ticket.Source{Lock: "lockmq"}, ticket.RiskRead, ph("5"), ph("2"), at(90), time.Hour)
	v1.Screen = ticket.Screen{Header: "shop · peek", Body: []string{"PEEK orders.created (10 messages)"}}
	id = push("v1", "shop", shopPriv, v1)
	if err := h.Withdraw(ctx, "shop", id, "the agent gave up"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f Fixture) Source() Source {
	return Source{Data: f.Data, HubKeys: []ed25519.PublicKey{f.HubPub}, LockKeys: f.LockKeys}
}

func load(t *testing.T, src Source) []loxrun.Exchange {
	t.Helper()
	xs, _, err := Load(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	return xs
}

func byName(t *testing.T, f Fixture, xs []loxrun.Exchange, name string) loxrun.Exchange {
	t.Helper()
	x, err := Find(xs, f.IDs[name])
	if err != nil {
		t.Fatal(name, err)
	}
	return x
}

func TestLoad(t *testing.T) {
	f := NewFixture(t)
	xs := load(t, f.Source())
	if len(xs) != 5 {
		t.Fatalf("%d exchanges, want 5", len(xs))
	}
	for i := 1; i < len(xs); i++ {
		if xs[i].At.Before(xs[i-1].At) {
			t.Error("not oldest first")
		}
	}
	c := byName(t, f, xs, "connect")
	if c.Status != loxrun.Approved || c.Decision() != "human" || c.Facade != "tty" || c.Approver != "david" || c.Result != loxrun.ResRan ||
		!c.Connected() || !c.Production || c.Profile != "prod" || c.Agent != "dev-1" || c.Lock != "locksql" || c.Sig != loxrun.SigOK {
		t.Errorf("connect: %+v", c)
	}
	r := byName(t, f, xs, "read")
	if r.Status != loxrun.AutoApproved || r.Rule != "default:read" || r.Decision() != "auto" || r.State != "consumed" || r.Decided.IsZero() {
		t.Errorf("read: %+v", r)
	}
	w := byName(t, f, xs, "write")
	if w.Status != loxrun.Denied || !w.ByHuman() || w.Facade != "telegram" || w.Approver != "alice" || !w.Write() {
		t.Errorf("write: %+v", w)
	}
	d := byName(t, f, xs, "ddl")
	if d.Decision() != "pending" || d.Status != loxrun.Waiting || !d.Write() || !d.Decided.IsZero() {
		t.Errorf("ddl: %+v", d)
	}
	v := byName(t, f, xs, "v1")
	if v.Status != loxrun.Undecided || v.Result != loxrun.ResWithdrawn || v.Decision() != "none" || v.Sig != loxrun.SigUnchecked ||
		!strings.Contains(v.SigNote, "no pinned key for shop") || v.Kind != ticket.KindRead || v.Lock != "lockmq" {
		t.Errorf("v1: %+v", v)
	}
	// Newest N, still oldest first.
	src := f.Source()
	src.Limit = 2
	if xs := load(t, src); len(xs) != 2 || xs[1].ID != f.IDs["v1"] || xs[0].ID != f.IDs["ddl"] {
		t.Errorf("limit 2: %v", xs)
	}
	src.Limit, src.Since = 0, time.Now().Add(time.Hour)
	if xs := load(t, src); len(xs) != 0 {
		t.Errorf("since the future: %d", len(xs))
	}
}

// No key: nothing checked, still listed. A wrong hub key or lock key: a
// bad signature, said so.
func TestSignatures(t *testing.T) {
	f := NewFixture(t)
	for _, x := range load(t, Source{Data: f.Data}) {
		if x.Sig != loxrun.SigUnchecked {
			t.Errorf("%s: %v without keys", x.ID, x.Sig)
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	src := f.Source()
	src.HubKeys = []ed25519.PublicKey{other}
	if x := byName(t, f, load(t, src), "write"); x.Sig != loxrun.SigBad || !strings.Contains(x.SigNote, "does not verify under the hub's") || x.Approver != "alice" {
		t.Errorf("wrong hub key: %+v", x)
	}
	// A rotated hub key: the old one still verifies the old decisions.
	src.HubKeys = []ed25519.PublicKey{f.HubPub, other}
	if x := byName(t, f, load(t, src), "write"); x.Sig != loxrun.SigOK {
		t.Errorf("rotated keys: %v %s", x.Sig, x.SigNote)
	}
	src = f.Source()
	src.LockKeys = map[string]ed25519.PublicKey{"crm": other}
	if x := byName(t, f, load(t, src), "read"); x.Sig != loxrun.SigBad || !strings.Contains(x.SigNote, "lock's pinned key") || x.Rule != "default:read" {
		t.Errorf("wrong lock key: %+v", x)
	}
}

// Whatever lox audit prints of the PII-bearing fixtures (listing, detail,
// JSON, in colour or not), no clear value shows: only the lock's masks.
// The sealed copy and the agent's note are never read out.
func TestNoClearValue(t *testing.T) {
	f := NewFixture(t)
	xs := load(t, f.Source())
	var out bytes.Buffer
	for _, st := range []loxrun.Style{{Color: true, Unicode: true}, {}} {
		out.WriteString(strings.Join(loxrun.AuditListing(xs, nil, time.UTC, 200, st), "\n"))
		for _, x := range xs {
			out.WriteString(strings.Join(loxrun.AuditDetail(x, time.UTC, 200, st), "\n"))
			out.WriteString(loxrun.AuditLine(x, time.UTC, 200, st))
		}
	}
	for _, x := range xs {
		for _, d := range []bool{false, true} {
			b, _ := json.Marshal(RecordOf(x, d))
			out.Write(b)
		}
	}
	got := out.String()
	for _, s := range append(secrets, "look up", "clear_sealed", "sealed") {
		if strings.Contains(got, s) {
			t.Errorf("output holds %q", s)
		}
	}
	r := byName(t, f, xs, "read")
	if b, _ := json.Marshal(RecordOf(r, true)); !strings.Contains(string(b), "j***(20)") || !strings.Contains(string(b), `"touched":["email","card"]`) {
		t.Errorf("masked screen missing from the detail record: %s", b)
	}
	if !strings.Contains(got, "‹j***(20)›") {
		t.Error("masked value not shown masked")
	}
}

func TestFilter(t *testing.T) {
	f := NewFixture(t)
	xs := load(t, f.Source())
	ids := func(fl Filter) string {
		var names []string
		for _, x := range fl.Apply(xs) {
			for n, id := range f.IDs {
				if id == x.ID {
					names = append(names, n)
				}
			}
		}
		return strings.Join(names, ",")
	}
	for _, c := range []struct {
		f    Filter
		want string
	}{
		{Filter{}, "connect,read,write,ddl,v1"},
		{Filter{Decision: "denied"}, "write"},
		{Filter{Decision: "human"}, "connect,write"},
		{Filter{Decision: "auto"}, "read"},
		{Filter{Decision: "pending"}, "ddl"},
		{Filter{Writes: true}, "write,ddl"},
		{Filter{Lock: "shop"}, "v1"},
		{Filter{Lock: "lockmq"}, "v1"},
		{Filter{Lock: "locksql", Profile: "prod"}, "connect,read"},
		{Filter{Agent: "dev-1", Profile: "dev", Writes: true}, "write,ddl"},
		{Filter{Agent: "nobody"}, ""},
		{Filter{Since: xs[2].At}, "write,ddl,v1"},
	} {
		if got := ids(c.f); got != c.want {
			t.Errorf("%+v: %s, want %s", c.f, got, c.want)
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                     {},
		"30m":                  now.Add(-30 * time.Minute),
		"2h":                   now.Add(-2 * time.Hour),
		"7d":                   now.AddDate(0, 0, -7),
		"2026-11-01":           time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		"2026-11-01T10:00:00Z": time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC),
	} {
		got, err := ParseSince(in, now, time.UTC)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"yesterday", "-2h", "xd"} {
		if _, err := ParseSince(bad, now, time.UTC); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFind(t *testing.T) {
	xs := []loxrun.Exchange{{Entry: loxrun.Entry{Instance: "crm", ID: "01KAB"}}, {Entry: loxrun.Entry{Instance: "shop", ID: "01KAC"}},
		{Entry: loxrun.Entry{Instance: "shop", ID: "01KAB"}}}
	if x, err := Find(xs, "shop/01KAB"); err != nil || x.Instance != "shop" {
		t.Errorf("%v %v", x, err)
	}
	if x, err := Find(xs, "01KAC"); err != nil || x.Instance != "shop" {
		t.Errorf("%v %v", x, err)
	}
	if x, err := Find(xs, "crm/01K"); err != nil || x.ID != "01KAB" || x.Instance != "crm" {
		t.Errorf("prefix: %v %v", x, err)
	}
	if _, err := Find(xs, "01KA"); err == nil || !strings.Contains(err.Error(), "names 3") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := Find(xs, "nope"); err == nil {
		t.Error("found nothing")
	}
}

func TestChanges(t *testing.T) {
	seen := map[string]string{}
	x := loxrun.Exchange{Entry: loxrun.Entry{Instance: "crm", ID: "1", Status: loxrun.Waiting}, State: "pending"}
	if n := len(Changes(seen, []loxrun.Exchange{x})); n != 1 {
		t.Fatal(n)
	}
	if n := len(Changes(seen, []loxrun.Exchange{x})); n != 0 {
		t.Fatal("unchanged printed again")
	}
	x.Status, x.State = loxrun.Approved, "approved"
	y := loxrun.Exchange{Entry: loxrun.Entry{Instance: "crm", ID: "2"}}
	if got := Changes(seen, []loxrun.Exchange{x, y}); len(got) != 2 {
		t.Fatalf("%d", len(got))
	}
}

func TestRuns(t *testing.T) {
	p := filepath.Join(t.TempDir(), RunsFile)
	if rs, err := ReadRuns(p, time.Time{}); err != nil || rs != nil {
		t.Fatal(rs, err)
	}
	t1 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	for _, e := range []loxrun.RunEvent{{At: t1, Event: loxrun.RunStart, User: "david\x1b[31m", Mode: "AUTO"},
		{At: t1.Add(time.Minute), Event: loxrun.RunMode, Mode: "MANUAL"}, {At: t1.Add(2 * time.Minute), Event: loxrun.RunStop}} {
		if err := AppendRun(p, e); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json\n{\"at\":\"2026-11-06T10:03:00Z\",\"event\":\"other\"}\n")
	f.Close()
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	rs, err := ReadRuns(p, time.Time{})
	if err != nil || len(rs) != 3 || rs[0].User != "david[31m" || rs[1].Mode != "MANUAL" {
		t.Fatalf("%+v %v", rs, err)
	}
	if rs, _ := ReadRuns(p, t1.Add(30*time.Second)); len(rs) != 2 {
		t.Errorf("since: %d", len(rs))
	}
}
