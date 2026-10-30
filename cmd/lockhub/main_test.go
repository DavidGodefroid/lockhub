package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
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
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	var errb bytes.Buffer
	go func() { done <- serve(ctx, []string{"--listen", "127.0.0.1:0"}, &errb) }()
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve = %d, stderr %q", code, errb.String())
	}
}
