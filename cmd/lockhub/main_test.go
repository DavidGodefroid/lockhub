package main

import (
	"bytes"
	"context"
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
