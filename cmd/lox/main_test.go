package main

import (
	"bytes"
	"os"
	"path/filepath"
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
		{[]string{"version"}, 0, "lox dev", ""},
		{[]string{"help"}, 0, "lox approve", ""},
		{[]string{"down"}, 2, "", `unknown command "down"`},
		{[]string{"approve", "--bogus"}, 2, "", "flag provided but not defined"},
		{[]string{"audit"}, 2, "", "usage: lox audit verify"},
		{[]string{"up", "--nope"}, 2, "", "flag provided but not defined"},
		{[]string{"up"}, 1, "", "stdin is not one"},
		{[]string{"up", "--dry-run", "extra"}, 2, "", "unexpected arguments"},
		{[]string{"help"}, 0, "--rotate hub|INSTANCE|all", ""},
		{[]string{"audit", "verify"}, 2, "", "are required"},
		{[]string{"add", "slack", "--team", "T01"}, 2, "", "usage: lox add slack"},
		{[]string{"add", "slack", "--team", "T01", "--channel", "#gen", "--user", "U1x"}, 2, "", "slack.channel"},
		{[]string{"add", "slack", "--team", "T01", "--channel", "C01", "--user", "U01"}, 1, "", "stdin is not one"},
		{[]string{"add", "telegram", "--chat", "42"}, 2, "", "usage: lox add telegram"},
		{[]string{"add", "telegram", "--chat", "42", "--from", "0"}, 2, "", "telegram.chats"},
		{[]string{"add", "telegram", "--chat", "42", "--from", "42"}, 1, "", "stdin is not one"},
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

const (
	hubImg = "ghcr.io/davidgodefroid/lockhub@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	sqlImg = "ghcr.io/davidgodefroid/locksql@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	mqImg  = "ghcr.io/davidgodefroid/lockmq@sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestAddImportDoctor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	file := filepath.Join(dir, "lockfamily.yaml")
	call := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(args, devNull(t), &out, &errb)
		return code, out.String(), errb.String()
	}
	if code, _, e := call("add", "locksql"); code != 2 || !strings.Contains(e, "usage: lox add") {
		t.Errorf("add without instance: %d %q", code, e)
	}
	// Flags after the positional arguments, as people type them.
	if code, o, e := call("add", "locksql", "crm", "--file", file, "--image", sqlImg, "--hub-image", hubImg); code != 0 || !strings.Contains(o, "lox up") {
		t.Fatalf("add: %d %q %q", code, o, e)
	}
	if code, _, e := call("add", "locksql", "crm", "--file", file, "--image", sqlImg); code != 1 || !strings.Contains(e, "already declared") {
		t.Errorf("add twice: %d %q", code, e)
	}
	sub := filepath.Join(dir, "billing")
	os.MkdirAll(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "lockfamily.yaml"), []byte("version: 1\nhub:\n  image: "+hubImg+"\nlocks:\n  events:\n    type: lockmq\n    image: "+mqImg+"\n"), 0o644)
	// No argument: every sub-project's lockfamily.yaml.
	if code, o, e := call("import", "--file", file); code != 0 || !strings.Contains(o, "adds lock events") || !strings.Contains(o, "lox up") {
		t.Fatalf("import: %d %q %q", code, o, e)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), "events:") || !strings.Contains(string(b), "crm:") {
		t.Errorf("file:\n%s", b)
	}
	if code, o, _ := call("doctor", "--file", file); code != 1 || !strings.Contains(o, "run lox up") {
		t.Errorf("doctor before lox up: %d %q", code, o)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "lockfamily")); !os.IsNotExist(err) {
		t.Error("doctor created the state directory")
	}
}
