package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// attachWorld is a scratch HOME, state and workspace with a PATH whose
// docker runs script (docker compose attach).
func attachWorld(t *testing.T, script string) (file string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\n"+script), 0o755)
	t.Setenv("PATH", bin)
	ws := filepath.Join(dir, "shop")
	os.MkdirAll(filepath.Join(ws, ".lockfamily"), 0o700)
	return filepath.Join(ws, ".lockfamily", "lockfamily.yaml")
}

// The attach hint does not claim which question is pending: on a restart
// of a production profile it is the profile name, not the policy review.
func TestAttachHintNamesEveryStartQuestion(t *testing.T) {
	file := attachWorld(t, "exit 0\n")
	var out, errb bytes.Buffer
	if err := attachConsole(file, "orders", devNull(t), &out, &errb); err != nil {
		t.Fatalf("attach: %v\n%s", err, errb.String())
	}
	hint := out.String()
	for _, want := range []string{"attached to lock orders", "not shown again", "Apply these changes? [y/N]",
		`Type the profile name "orders" to continue:`, "password", "Ctrl-P Ctrl-Q"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint lacks %q:\n%s", want, hint)
		}
	}
	if strings.Contains(hint, "it is the policy review") {
		t.Errorf("hint still claims the policy review:\n%s", hint)
	}
}

// Detaching (Ctrl-P Ctrl-Q) ends docker's attach with status 1 and "read
// escape sequence": that is a success, the console keeps running.
func TestAttachDetachIsSuccess(t *testing.T) {
	file := attachWorld(t, "echo 'read escape sequence' >&2\nexit 1\n")
	var out, errb bytes.Buffer
	if err := attachConsole(file, "orders", devNull(t), &out, &errb); err != nil {
		t.Fatalf("detach reported as an error: %v", err)
	}
	if !strings.HasSuffix(out.String(), "detached from orders: its console keeps running\n") {
		t.Fatalf("output:\n%s", out.String())
	}
}

// Any other end of a failed attach stays an error.
func TestAttachFailureIsError(t *testing.T) {
	file := attachWorld(t, "echo 'no such service' >&2\nexit 1\n")
	var out, errb bytes.Buffer
	if err := attachConsole(file, "orders", devNull(t), &out, &errb); err == nil {
		t.Fatal("a failed attach reported no error")
	}
	if !strings.Contains(errb.String(), "no such service") {
		t.Fatalf("docker's error not shown: %q", errb.String())
	}
	if strings.Contains(out.String(), "detached from") {
		t.Fatalf("a failure read as a detach:\n%s", out.String())
	}
}
