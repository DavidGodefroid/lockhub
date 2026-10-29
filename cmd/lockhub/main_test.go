package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/keys"
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
