package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/creack/pty"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

// A workspace the group can write (umask 002) is refused by lox add, for
// every lock type and both forms, with the chmod to run; nothing is
// written into it.
func TestAddRefusesGroupWritableWorkspace(t *testing.T) {
	for _, typ := range family.Types {
		t.Run(typ, func(t *testing.T) {
			ws, file, verbs := addWorld(t)
			if err := os.Chmod(ws, 0o775); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{
				{"add", typ, "--non-interactive", "--file", file, "--host", "db.example.com"},
				{"add", typ, "x1", "--file", file, "--image", "ghcr.io/davidgodefroid/" + typ + "@sha256:" + strings.Repeat("a", 64), "--hub-image", hubImg},
			} {
				var out, errb bytes.Buffer
				if code := run(args, devNull(t), &out, &errb); code != 1 || !strings.Contains(errb.String(), "chmod go-w "+ws) {
					t.Fatalf("%q: code %d\n%s\n%s", args, code, out.String(), errb.String())
				}
			}
			if len(verbs.calls) != 0 {
				t.Fatalf("launchers ran: %q", verbs.calls)
			}
			if _, err := os.Lstat(filepath.Join(ws, family.Dir)); !os.IsNotExist(err) {
				t.Fatalf("%s written: %v", family.Dir, err)
			}
		})
	}
}

// A 0755 workspace is accepted.
func TestAddAcceptsPrivateWorkspace(t *testing.T) {
	ws, file, _ := addWorld(t)
	if err := os.Chmod(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"add", "locksql", "crm", "--file", file, "--image", sqlImg, "--hub-image", hubImg}, devNull(t), &out, &errb); code != 0 {
		t.Fatalf("code %d\n%s", code, errb.String())
	}
}

// lox run refuses a group-writable workspace, and so does --no-start
// (the rules it serves come from the workspace).
func TestRunRefusesGroupWritableWorkspace(t *testing.T) {
	ws, file, _ := addWorld(t)
	var out, errb bytes.Buffer
	if code := run([]string{"add", "locksql", "crm", "--file", file, "--image", sqlImg, "--hub-image", hubImg}, devNull(t), &out, &errb); code != 0 {
		t.Fatalf("code %d\n%s", code, errb.String())
	}
	user, tty, err := pty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer user.Close()
	defer tty.Close()
	for _, d := range []string{ws, filepath.Join(ws, family.Dir)} {
		os.Chmod(ws, 0o755)
		os.Chmod(filepath.Join(ws, family.Dir), 0o755)
		if err := os.Chmod(d, 0o775); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"run", "--file", file}, {"run", "--no-start", "--file", file}} {
			out.Reset()
			errb.Reset()
			if code := run(args, tty, &out, &errb); code != 1 || !strings.Contains(errb.String(), "lox run: "+d+" is writable by someone else than you (mode 0775)") ||
				!strings.Contains(errb.String(), "chmod go-w "+d) {
				t.Fatalf("%s 0775, %q: code %d\n%s\n%s", d, args, code, out.String(), errb.String())
			}
		}
	}
}
