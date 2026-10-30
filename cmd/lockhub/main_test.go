package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/facade/chat"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

func TestRun(t *testing.T) {
	for _, c := range []struct {
		args     []string
		code     int
		out, err string
	}{
		{nil, 2, "", "Usage:"},
		{[]string{"version"}, 0, "lockhub dev", ""},
		{[]string{"help"}, 0, "lockhub serve", ""},
		{[]string{"bogus"}, 2, "", `unknown command "bogus"`},
		{[]string{"serve", "--nope"}, 2, "", "flag provided but not defined"},
	} {
		var out, errb bytes.Buffer
		code := run(context.Background(), c.args, &out, &errb)
		if code != c.code || !strings.Contains(out.String(), c.out) || !strings.Contains(errb.String(), c.err) {
			t.Errorf("run(%q) = %d, out %q, err %q", c.args, code, out.String(), errb.String())
		}
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	data := t.TempDir()
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"keygen", "--data", data}, &out, &errb); code != 0 {
		t.Fatalf("keygen = %d: %s", code, errb.String())
	}
	if code := run(context.Background(), []string{"keygen", "--data", data}, &out, &errb); code != 1 {
		t.Errorf("second keygen = %d, want 1 (no overwrite)", code)
	}
	l := hubtest.NewLock("crm-prod")
	os.WriteFile(filepath.Join(data, "locks.json"), []byte(`{"locks":{"crm-prod":{"public_key":"`+keys.Public(l.Pub)+`"}}}`), 0o644)

	codec = nil
	if code := serve(context.Background(), []string{"--listen", "127.0.0.1:0", "--data", data}, &errb); code != 1 || !strings.Contains(errb.String(), "ticket codec") {
		t.Errorf("serve without codec = %d: %s", code, errb.String())
	}
	codec = hubtest.Codec{}
	t.Cleanup(func() { codec = nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	errb.Reset()
	go func() { done <- serve(ctx, []string{"--listen", "127.0.0.1:0", "--data", data}, &errb) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve = %d, stderr %q", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(data, "tickets.jsonl")); err != nil {
		t.Error("audit log not created")
	}
}

func TestServeRefusesMissingConfig(t *testing.T) {
	codec = hubtest.Codec{}
	t.Cleanup(func() { codec = nil })
	var errb bytes.Buffer
	if code := serve(context.Background(), []string{"--listen", "127.0.0.1:0", "--data", t.TempDir()}, &errb); code != 1 || !strings.Contains(errb.String(), "keygen") {
		t.Errorf("serve on an empty dir = %d: %s", code, errb.String())
	}
}

func TestFacadeSocketGuards(t *testing.T) {
	codec = hubtest.Codec{}
	t.Cleanup(func() { codec = nil })
	data := t.TempDir()
	var out, errb bytes.Buffer
	run(context.Background(), []string{"keygen", "--data", data}, &out, &errb)
	l := hubtest.NewLock("crm")
	os.WriteFile(filepath.Join(data, "locks.json"), []byte(`{"locks":{"crm":{"public_key":"`+keys.Public(l.Pub)+`"}}}`), 0o644)
	h, closeHub, err := openHub(data)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHub()
	dir, _ := os.MkdirTemp("", "fs")
	defer os.RemoveAll(dir)
	errc := make(chan error, 4)

	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o755)
	if _, err := listenFacade(h, filepath.Join(open, "f.sock"), "0600", errc); err == nil {
		t.Error("socket in a directory open to others accepted")
	}
	priv := filepath.Join(dir, "priv")
	os.Mkdir(priv, 0o700)
	sock := filepath.Join(priv, "f.sock")
	srv, err := listenFacade(h, sock, "0600", errc)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
	if _, err := listenFacade(h, sock, "0600", errc); err == nil || !strings.Contains(err.Error(), "another hub") {
		t.Errorf("took over a live socket: %v", err)
	}
	if _, err := listenFacade(h, filepath.Join(priv, "g.sock"), "0606", errc); err == nil {
		t.Error("mode open to others accepted")
	}
}

func TestLoadRoutes(t *testing.T) {
	l := hubtest.NewLock("crm")
	locks := map[string]ed25519.PublicKey{"crm": l.Pub}
	dir := t.TempDir()
	p := filepath.Join(dir, "routing.json")
	if r, err := loadRoutes(p, locks); err != nil || len(r.Enabled) != 0 {
		t.Errorf("missing file: %+v %v", r, err)
	}
	os.WriteFile(p, []byte(`{"facades":["tty"],"only":{"crm":["tty"]}}`), 0o600)
	r, err := loadRoutes(p, locks)
	if err != nil || r.Allowed("crm", "deck", "read") == nil || r.Allowed("crm", "tty", "read") != nil {
		t.Errorf("rules %+v %v", r, err)
	}
	for _, bad := range []string{`{"facades":["fax"]}`, `{"only":{"nope":["tty"]}}`, `{"x":1}`} {
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := loadRoutes(p, locks); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestChatFacades(t *testing.T) {
	codec = hubtest.Codec{}
	t.Cleanup(func() { codec = nil })
	data := t.TempDir()
	var out, errb bytes.Buffer
	run(context.Background(), []string{"keygen", "--data", data}, &out, &errb)
	l := hubtest.NewLock("crm")
	os.WriteFile(filepath.Join(data, "locks.json"), []byte(`{"locks":{"crm":{"public_key":"`+keys.Public(l.Pub)+`"}}}`), 0o644)
	open := func() ([]*chat.Facade, error) {
		h, closeHub, err := openHub(data)
		if err != nil {
			t.Fatal(err)
		}
		defer closeHub()
		return chatFacades(h, data, io.Discard)
	}
	w := func(name, s string, mode os.FileMode) { os.WriteFile(filepath.Join(data, name), []byte(s), mode) }
	// Slack not enabled: no facade, and its secrets are never read.
	w("slack-bot-token", "xoxb-1", 0o644)
	if fs, err := open(); err != nil || len(fs) != 0 {
		t.Fatalf("default: %v %v", fs, err)
	}
	w("chat.json", `{"slack":{"team":"T01","channel":"C02","users":["U03"]}}`, 0o600)
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("slack configured, not enabled: %v", err)
	}
	w("routing.json", `{"facades":["tty","slack"]}`, 0o600)
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "lock add slack") {
		t.Errorf("missing app token: %v", err)
	}
	w("slack-app-token", "xapp-1", 0o600)
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("readable bot token: %v", err)
	}
	os.Chmod(filepath.Join(data, "slack-bot-token"), 0o600)
	if fs, err := open(); err != nil || len(fs) != 1 || fs[0].T.Facade() != "slack" {
		t.Errorf("slack: %v %v", fs, err)
	}
	w("routing.json", `{"facades":["tty","slack","telegram"]}`, 0o600)
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "no telegram section") {
		t.Errorf("telegram enabled without settings: %v", err)
	}
	w("chat.json", `{"slack":{"team":"T01","channel":"C02","users":["U03"]},"telegram":{"chats":[{"chat":42,"from":42}]}}`, 0o600)
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "lock add telegram") {
		t.Errorf("missing telegram token: %v", err)
	}
	w("telegram-bot-token", "123:abc", 0o600)
	if fs, err := open(); err != nil || len(fs) != 2 || fs[1].T.Facade() != "telegram" {
		t.Errorf("both: %v %v", fs, err)
	}
	os.Remove(filepath.Join(data, "chat.json"))
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "chat.json") {
		t.Errorf("enabled without settings: %v", err)
	}
}

// The hub starts only once the outbox is in the log, and never signs a
// record it did not make.
func TestStartFlushesOutbox(t *testing.T) {
	codec = hubtest.Codec{}
	t.Cleanup(func() { codec = nil })
	data := t.TempDir()
	var out, errb bytes.Buffer
	run(context.Background(), []string{"keygen", "--data", data}, &out, &errb)
	l := hubtest.NewLock("crm")
	os.WriteFile(filepath.Join(data, "locks.json"), []byte(`{"locks":{"crm":{"public_key":"`+keys.Public(l.Pub)+`"}}}`), 0o644)
	key, err := keys.Load(filepath.Join(data, "hub.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(data, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	queue := func(k ed25519.PrivateKey, ticket string) {
		rec := []byte(`{"seq":0,"at":"2027-01-01T00:00:00Z","event":"push","ticket":"` + ticket + `","instance":"crm","state":"pending","prev":"","hash":""}`)
		if err := st.Tx(context.Background(), func(tx *store.Tx) error {
			return tx.QueueAudit(rec, func(id int64) string { return audit.SignOutbox(k, id, rec) })
		}); err != nil {
			t.Fatal(err)
		}
	}
	queue(key, "T1")
	_, closeHub, err := openHub(data)
	if err != nil {
		t.Fatal(err)
	}
	closeHub()
	if b, _ := os.ReadFile(filepath.Join(data, "tickets.jsonl")); !strings.Contains(string(b), `"ticket":"T1"`) {
		t.Fatalf("outbox not logged at start:\n%s", b)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	queue(other, "T2")
	st.Close()
	if _, _, err := openHub(data); err == nil || !strings.Contains(err.Error(), "not signed by the hub key") {
		t.Fatalf("started past a forged outbox record: %v", err)
	}
}

func TestServeMobilePushCreatesVAPIDKey(t *testing.T) {
	var errb bytes.Buffer
	if code := serve(context.Background(), []string{"--mobile-push"}, &errb); code != 2 || !strings.Contains(errb.String(), "--mobile-push needs") {
		t.Errorf("--mobile-push alone = %d: %s", code, errb.String())
	}
	data := t.TempDir()
	var out bytes.Buffer
	if code := run(context.Background(), []string{"keygen", "--data", data}, &out, &errb); code != 0 {
		t.Fatalf("keygen = %d: %s", code, errb.String())
	}
	l := hubtest.NewLock("crm-prod")
	os.WriteFile(filepath.Join(data, "locks.json"), []byte(`{"locks":{"crm-prod":{"public_key":"`+keys.Public(l.Pub)+`"}}}`), 0o644)
	codec = hubtest.Codec{}
	t.Cleanup(func() { codec = nil })
	args := []string{"--listen", "127.0.0.1:0", "--data", data, "--mobile-listen", "127.0.0.1:0", "--mobile-origin", "https://hub.example.net", "--mobile-push"}
	for range 2 { // created once, then the same key
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int)
		errb.Reset()
		go func() { done <- serve(ctx, args, &errb) }()
		time.Sleep(100 * time.Millisecond)
		cancel()
		if code := <-done; code != 0 || !strings.Contains(errb.String(), "web push: true") {
			t.Fatalf("serve = %d, stderr %q", code, errb.String())
		}
		fi, err := os.Stat(filepath.Join(data, keys.VAPIDFile))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("vapid key: %v %v", fi, err)
		}
	}
}
