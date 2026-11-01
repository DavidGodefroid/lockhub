package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// interruptWorld is a scratch HOME, state and workspace with a PATH whose
// docker sends SIGINT to lox (its parent) at its first run, as Ctrl-C at
// the terminal does.
func interruptWorld(t *testing.T) (file string) {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep command")
	}
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nkill -INT $PPID\nexec "+sleep+" 5\n"), 0o755)
	t.Setenv("PATH", bin)
	ws := filepath.Join(dir, "shop")
	os.MkdirAll(filepath.Join(ws, ".lockfamily"), 0o700)
	return filepath.Join(ws, ".lockfamily", "lockfamily.yaml")
}

// Ctrl-C ends lox up and lox init as it ends lox add and lox remove:
// exit 130 and one "interrupted" line.
func TestUpAndInitInterruptedExit130(t *testing.T) {
	for name, args := range map[string][]string{
		"up":   {"up", "--dry-run"},
		"init": {"init", "--hub-image", "ghcr.io/davidgodefroid/lockhub@sha256:" + strings.Repeat("a", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			file := interruptWorld(t)
			conf := "version: 1\nhub:\n  image: ghcr.io/davidgodefroid/lockhub@sha256:" + strings.Repeat("a", 64) + "\nlocks: {}\n"
			if err := os.WriteFile(file, []byte(conf), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			code := run(append(args, "--file", file), devNull(t), &out, &errb)
			if code != exitInterrupted {
				t.Fatalf("code %d, want 130\n%s\n%s", code, out.String(), errb.String())
			}
			if want := "lox " + name + ": interrupted\n"; errb.String() != want {
				t.Fatalf("stderr = %q, want %q", errb.String(), want)
			}
		})
	}
}
