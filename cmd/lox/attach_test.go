package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
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

// lockYAML declares lock orders of type locksql in file.
func lockYAML(t *testing.T, file string) {
	t.Helper()
	y := "version: 1\nhub:\n  image: ghcr.io/davidgodefroid/lockhub@sha256:" + strings.Repeat("a", 64) + "\nlocks:\n  orders:\n    type: locksql\n" +
		"    image: ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("b", 64) + "\n    profile: shop\n"
	if err := os.WriteFile(file, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
}

// question is the find -name of orders' question file in the world of
// file: <workspace hash>-shop.question (lockkit's QuestionPath).
func question(file string) string {
	return strings.TrimPrefix(family.Project(family.Workspace(file)), "lockfamily-") + "-shop.question"
}

const (
	unixHead   = "Num       RefCount Protocol Flags    Type St Inode Path\n"
	unixListen = unixHead + "0000000000000000: 00000002 00000000 00010000 0001 01 4242 /run/locksql/1a2b3c4d-shop.sock\n"
	unixNone   = unixHead + "0000000000000000: 00000003 00000000 00000000 0001 03 4243 /run/locksql/1a2b3c4d-shop.sock\n"
)

// questionWorld is attachWorld whose docker answers /proc/net/unix with
// table, and the question read with out when its arguments name the
// file of orders (its name, the console's uid 10001, mode 0600 exactly).
func questionWorld(t *testing.T, table, out string) (file string) {
	t.Helper()
	file = attachWorld(t, "")
	lockYAML(t, file)
	script := `case "$*" in
*" exec -T lock-orders cat /proc/net/unix") printf '%s' '` + table + `' ;;
*" exec -T lock-orders sh -c "*"-perm 0600 "*" lox /run/locksql ` + question(file) + ` 10001") printf '%s' '` + out + `' ;;
*" exec "*) exit 9 ;;
*) exit 0 ;;
esac
`
	os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(file)), "..", "bin", "docker"), []byte("#!/bin/sh\n"+script), 0o755)
	return file
}

func attachOut(t *testing.T, file string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if err := attachConsole(file, "orders", devNull(t), &out, &errb); err != nil {
		t.Fatalf("attach: %v\n%s", err, errb.String())
	}
	return out.String()
}

// A console that records its question (lockkit's question file): lox
// attach shows that question, quoted as the console's, and only it (#119).
func TestAttachShowsTheRecordedQuestion(t *testing.T) {
	file := questionWorld(t, unixNone, "question: Vault token for https://vault.example.com:8200:\033[2J\u202e\u200b\n")
	hint := attachOut(t, file)
	want := `attached to lock orders: the console asks "Vault token for https://vault.example.com:8200:\x1b[2J\u202e\u200b"` + "\n"
	if !strings.Contains(hint, want) {
		t.Fatalf("hint:\n%q\nwant %q", hint, want)
	}
	for _, not := range []string{"profile name", "Apply these changes", "\033", "\u202e", "\u200b"} {
		if strings.Contains(hint, not) {
			t.Errorf("hint has %q:\n%q", not, hint)
		}
	}
}

// A long question is cut.
func TestAttachCutsALongQuestion(t *testing.T) {
	file := questionWorld(t, unixNone, "question: "+strings.Repeat("x", 600)+"\n")
	hint := attachOut(t, file)
	if !strings.Contains(hint, `"`+strings.Repeat("x", 200)+`…"`) || strings.Contains(hint, strings.Repeat("x", 201)) {
		t.Fatalf("hint:\n%s", hint)
	}
}

// A console that listens serves, whatever question file is left next to
// its socket (a console killed while it asked): stale, never shown.
func TestAttachServingConsoleIgnoresAStaleQuestion(t *testing.T) {
	file := questionWorld(t, unixListen, "question: Type the profile name \"shop\" to continue:\n")
	hint := attachOut(t, file)
	if !strings.Contains(hint, "attached to lock orders: it serves and asks nothing now") || strings.Contains(hint, "profile name") {
		t.Fatalf("hint:\n%s", hint)
	}
}

// Two question files for the console (it cannot be both), or none of its
// own (wrong name, owner or mode: find returns nothing), or a container
// that cannot be read: the question is unknown, and the hint names what
// it may ask without claiming which (#119).
func TestAttachHintWhenTheQuestionIsUnknown(t *testing.T) {
	for name, out := range map[string]string{
		"several": "question: Vault token for x:\nquestion: User:\n",
		"none":    "",
	} {
		t.Run(name, func(t *testing.T) {
			hint := attachOut(t, questionWorld(t, unixNone, out))
			for _, want := range []string{"attached to lock orders", "does not tell which one", "Apply these changes? [y/N]",
				"Type the profile name", "Vault token", "Ctrl-P Ctrl-Q"} {
				if !strings.Contains(hint, want) {
					t.Errorf("hint lacks %q:\n%s", want, hint)
				}
			}
			// The instance is not the profile: never quoted as its name.
			if strings.Contains(hint, `"orders" to continue`) || strings.Contains(hint, "the console asks") {
				t.Errorf("hint:\n%s", hint)
			}
		})
	}
	file := attachWorld(t, "case \"$*\" in *\" exec \"*) exit 1 ;; *) exit 0 ;; esac\n")
	lockYAML(t, file)
	if hint := attachOut(t, file); !strings.Contains(hint, "does not tell which one") {
		t.Errorf("exec fails: hint:\n%s", hint)
	}
}

// What lox attach asks for, by lock: the uid of its kind, the workspace
// hash for a project-keyed console, "user" otherwise, lockfile's default
// profile; names that are not a console's run nothing.
func TestPendingQuestionAsksForTheConsolesOwnFile(t *testing.T) {
	var got []string
	exec := func(args ...string) (string, error) {
		got = append(got, strings.Join(args, " "))
		return "", nil
	}
	pendingQuestion(console{typ: "lockfile", profile: "default", key: "user", uid: "10031"}, exec)
	if len(got) != 2 || got[0] != "cat /proc/net/unix" || !strings.HasSuffix(got[1], " lox /run/lockfile user-default.question 10031") {
		t.Fatalf("calls %q", got)
	}
	got = nil
	pendingQuestion(console{typ: "locksql", key: "1a2b3c4d", uid: "10001"}, exec)
	if len(got) != 2 || !strings.HasSuffix(got[1], " lox /run/locksql 1a2b3c4d-*.question 10001") {
		t.Fatalf("no profile: calls %q", got)
	}
	for _, c := range []console{
		{typ: "lock sql;x", key: "user", uid: "10001"},
		{typ: "locksql", key: "user", uid: "10001", profile: "a*"},
		{typ: "locksql", key: "../x", uid: "10001"},
		{typ: "locksql", key: "user", uid: ""},
	} {
		got = nil
		if p := pendingQuestion(c, exec); p != (pending{}) || len(got) != 0 {
			t.Errorf("%+v: pending %+v, calls %q", c, p, got)
		}
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
