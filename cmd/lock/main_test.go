package main

import (
	"bytes"
	"os"
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
		{[]string{"version"}, 0, "lock dev", ""},
		{[]string{"help"}, 0, "lock approve", ""},
		{[]string{"down"}, 2, "", `unknown command "down"`},
		{[]string{"approve", "--bogus"}, 2, "", "flag provided but not defined"},
		{[]string{"audit"}, 2, "", "usage: lock audit verify"},
		{[]string{"up", "--nope"}, 2, "", "flag provided but not defined"},
		{[]string{"up"}, 1, "", "stdin is not one"},
		{[]string{"audit", "verify"}, 2, "", "are required"},
	} {
		var out, errb bytes.Buffer
		code := run(c.args, devNull(t), &out, &errb)
		if code != c.code || !strings.Contains(out.String(), c.out) || !strings.Contains(errb.String(), c.err) {
			t.Errorf("run(%q) = %d, out %q, err %q", c.args, code, out.String(), errb.String())
		}
	}
}

// devNull is an empty, non-terminal stdin.
func devNull(t *testing.T) *os.File {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return r
}

func TestApproveRefusesNonTerminal(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	w.Close()
	var out, errb bytes.Buffer
	if code := run([]string{"approve", "--socket", "/nonexistent"}, r, &out, &errb); code != 1 || !strings.Contains(errb.String(), "not a terminal") {
		t.Errorf("piped stdin: %d %q", code, errb.String())
	}
}
