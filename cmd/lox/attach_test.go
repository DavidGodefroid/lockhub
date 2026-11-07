package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

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
// table, the question read with out when its arguments name the file of
// orders (its name, the console's uid 10001, mode 0600 exactly), and
// docker compose ps with ps.
func questionWorld(t *testing.T, table, out, ps string) (file string) {
	t.Helper()
	file = attachWorld(t, "")
	lockYAML(t, file)
	script := `case "$*" in
*" exec -T lock-orders cat /proc/net/unix") printf '%s' '` + table + `' ;;
*" exec -T lock-orders sh -c "*"-perm 0600 "*" lox /run/locksql ` + question(file) + ` 10001") printf '%s' '` + out + `' ;;
*" exec "*) exit 9 ;;
*" ps -a --format {{.State}} {{.ExitCode}} lock-orders") printf '%s' '` + ps + `' ;;
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

// guesses are the words of the former list of what a console may ask:
// never printed again (#143).
var guesses = []string{"Apply these changes", "Type the profile name", "a credential its profile", "does not tell which one"}

func noGuess(t *testing.T, hint string) {
	t.Helper()
	for _, g := range guesses {
		if strings.Contains(hint, g) {
			t.Errorf("hint guesses (%q):\n%s", g, hint)
		}
	}
}

// A console that records its question (lockkit's question file): lox
// attach shows that question, escaped, and only it (#119, #143).
func TestAttachShowsTheRecordedQuestion(t *testing.T) {
	file := questionWorld(t, unixNone, "question: Vault token for https://vault.example.com:8200:\033[2J\u202e\u200b\n", "")
	hint := attachOut(t, file)
	want := `lock orders waits for: Vault token for https://vault.example.com:8200:\x1b[2J\u202e\u200b (typed, not shown)` + "\n  type the answer"
	if !strings.Contains(hint, want) {
		t.Fatalf("hint:\n%q\nwant %q", hint, want)
	}
	for _, not := range []string{"\033", "\u202e", "\u200b"} {
		if strings.Contains(hint, not) {
			t.Errorf("hint has %q:\n%q", not, hint)
		}
	}
	noGuess(t, hint)
}

// The question of a restarted production lock behind an SSH bastion with
// an encrypted key: its passphrase, typed without echo (#143). A question
// that is not a secret is not said to be.
func TestAttachShowsTheSSHPassphrase(t *testing.T) {
	hint := attachOut(t, questionWorld(t, unixNone, "question: Passphrase for /home/locksql/.ssh/bastion_key:\n", ""))
	if !strings.Contains(hint, "lock orders waits for: Passphrase for /home/locksql/.ssh/bastion_key: (typed, not shown)\n") {
		t.Fatalf("hint:\n%s", hint)
	}
	noGuess(t, hint)
	hint = attachOut(t, questionWorld(t, unixNone, `question: Type the profile name "shop" to continue:`+"\n", ""))
	if !strings.Contains(hint, `lock orders waits for: Type the profile name "shop" to continue:`+"\n") || strings.Contains(hint, "typed, not shown") {
		t.Fatalf("hint:\n%s", hint)
	}
}

// A long question is cut.
func TestAttachCutsALongQuestion(t *testing.T) {
	file := questionWorld(t, unixNone, "question: "+strings.Repeat("x", 600)+"\n", "")
	hint := attachOut(t, file)
	if !strings.Contains(hint, "waits for: "+strings.Repeat("x", 200)+"…\n") || strings.Contains(hint, strings.Repeat("x", 201)) {
		t.Fatalf("hint:\n%s", hint)
	}
}

// A console that listens serves, whatever question file is left next to
// its socket (a console killed while it asked): stale, never shown.
func TestAttachServingConsoleIgnoresAStaleQuestion(t *testing.T) {
	file := questionWorld(t, unixListen, "question: Type the profile name \"shop\" to continue:\n", "running 0")
	hint := attachOut(t, file)
	if !strings.Contains(hint, "lock orders is serving: nothing to answer\n") || strings.Contains(hint, "profile name") {
		t.Fatalf("hint:\n%s", hint)
	}
}

// No question recorded and no socket: lox attach says what the container
// does (starting, stopped with its exit status, or unknown), never a list
// of what the console may ask (#143). Two question files for the console
// (it cannot be both) are no question.
func TestAttachHintWhenNoQuestionIsRecorded(t *testing.T) {
	for name, c := range map[string]struct{ out, ps, want string }{
		"starting":   {"", "running 0\n", "lock orders is starting: its console asks nothing yet\n  its questions show here"},
		"several":    {"question: Vault token for x:\nquestion: User:\n", "running 0\n", "lock orders is starting"},
		"restarting": {"", "restarting 1\n", "lock orders is stopped (restarting, exit status 1): its console keeps no log"},
		"exited":     {"", "exited 2\n", "lock orders is stopped (exited, exit status 2)"},
		"created":    {"", "created 0\n", "lock orders is created: its console asks nothing yet"},
		"no ps":      {"", "", "lock orders: its console's state cannot be read"},
		"odd ps":     {"", "running 0 x;y\n", "lock orders: its console's state cannot be read"},
	} {
		t.Run(name, func(t *testing.T) {
			hint := attachOut(t, questionWorld(t, unixNone, c.out, c.ps))
			if !strings.Contains(hint, c.want) || strings.Contains(hint, "waits for") {
				t.Errorf("hint:\n%s\nwant %q", hint, c.want)
			}
			noGuess(t, hint)
		})
	}
	file := attachWorld(t, "case \"$*\" in *\" exec \"*) exit 1 ;; *) exit 0 ;; esac\n")
	lockYAML(t, file)
	if hint := attachOut(t, file); !strings.Contains(hint, "state cannot be read") {
		t.Errorf("exec fails: hint:\n%s", hint)
	}
}

// When the console ends under the attach (a wrong passphrase: it exits,
// its container restarts it), lox attach shows its next question, polled
// until it asks one, so the next attach is not blind (#143).
func TestAfterExitShowsTheNextQuestion(t *testing.T) {
	attachStep = time.Millisecond
	t.Cleanup(func() { attachStep = 500 * time.Millisecond })
	n := 0
	ask := func() pending {
		n++
		if n < 3 {
			return pending{state: "restarting", exit: "1"}
		}
		return pending{question: "Passphrase for /home/locksql/.ssh/bastion_key:"}
	}
	got := afterExit("orders", ask, 10)
	if n != 3 || !strings.Contains(got, "the console of lock orders ended; now lock orders waits for: Passphrase for /home/locksql/.ssh/bastion_key: (typed, not shown)\n  lox attach orders") {
		t.Fatalf("%d asks: %s", n, got)
	}
	n = 0
	got = afterExit("orders", func() pending { n++; return pending{state: "exited", exit: "1"} }, 3)
	if n != 3 || !strings.Contains(got, "now lock orders is stopped (exited, exit status 1)") {
		t.Fatalf("%d asks: %s", n, got)
	}
	noGuess(t, got)
}

// A console that ends under the attach: lox attach fails, and says what
// it does now.
func TestAttachConsoleEndsShowsWhatNext(t *testing.T) {
	attachTries, attachStep = 1, time.Millisecond
	t.Cleanup(func() { attachTries, attachStep = 10, 500*time.Millisecond })
	file := questionWorld(t, unixNone, "question: Passphrase for /k:\n", "")
	script, _ := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(file)), "..", "bin", "docker"))
	os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(file)), "..", "bin", "docker"),
		[]byte(strings.Replace(string(script), "*) exit 0 ;;", "*\" attach \"*) echo 'console: ssh.key: /k: the passphrase is incorrect'; exit 1 ;;\n*) exit 0 ;;", 1)), 0o755)
	var out, errb bytes.Buffer
	if err := attachConsole(file, "orders", devNull(t), &out, &errb); err == nil {
		t.Fatal("an ended console reported no error")
	}
	if strings.Count(out.String(), "lock orders waits for: Passphrase for /k: (typed, not shown)") != 2 ||
		!strings.Contains(out.String(), "the passphrase is incorrect\nthe console of lock orders ended; now lock orders waits for") {
		t.Fatalf("output:\n%s", out.String())
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

// ttyWorld is attachWorld with a lockfamily.yaml naming lock orders
// (locksql), a fake docker that answers `compose exec ... cat
// /proc/net/unix` with a listening socket of locksql once marks/served
// exists and runs attach for `compose attach`, and a pseudo-terminal
// standing for the user's: lox gets its terminal end, the test types and
// reads at the other.
func ttyWorld(t *testing.T, attach func(marks string) string) (file, marks string, user, tty *os.File) {
	t.Helper()
	marks = t.TempDir()
	file = attachWorld(t, `case " $* " in
*" exec "*)
	[ -f `+marks+`/served ] && echo '0000000000000000: 00000002 00000000 00010000 0001 01 4242 /run/locksql/abcd-orders.sock'
	exit 0 ;;
*" ps "*) exit 0 ;;
esac
echo "$@" >`+marks+`/args
`+attach(marks))
	t.Setenv("PATH", filepath.Dir(filepath.Dir(filepath.Dir(file)))+"/bin:/usr/bin:/bin")
	if err := os.WriteFile(file, []byte(removeYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	user, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { user.Close(); tty.Close() })
	step, grace := serveStep, readyGrace
	serveStep, readyGrace = 5*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { serveStep, readyGrace = step, grace })
	return file, marks, user, tty
}

// screen collects what the user's terminal shows; on is called with each
// chunk.
type screen struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *screen) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.buf.String() }

func watch(user *os.File, on func(string)) *screen {
	s := &screen{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := user.Read(b)
			if n > 0 {
				s.mu.Lock()
				s.buf.Write(b[:n])
				s.mu.Unlock()
				on(string(b[:n]))
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

// Once the start question is answered and the console serves, lox attach
// types the detach keys itself and returns with a clear message, the
// console still running (#144).
func TestAttachDetachesOnceServes(t *testing.T) {
	file, marks, user, tty := ttyWorld(t, func(m string) string {
		return "stty raw -echo\necho asking\nhead -c 2 >" + m + "/typed\ntouch " + m +
			"/served\nhead -c 2 | od -An -tx1 >" + m + "/keys\necho 'read escape sequence' >&2\nexit 1\n"
	})
	var once sync.Once
	shown := watch(user, func(s string) {
		if strings.Contains(s, "asking") {
			once.Do(func() { user.WriteString("y\r") })
		}
	})
	var errb bytes.Buffer
	if err := attachConsole(file, "orders", tty, tty, &errb); err != nil {
		t.Fatalf("attach: %v\n%s", err, errb.String())
	}
	if b, _ := os.ReadFile(marks + "/typed"); string(b) != "y\r" {
		t.Fatalf("console got %q from the user, want %q", b, "y\r")
	}
	// BSD od (macOS) pads its columns: compare the bytes, not the spacing.
	if b, _ := os.ReadFile(marks + "/keys"); strings.Join(strings.Fields(string(b)), " ") != "10 11" {
		t.Fatalf("console got %q once serving, want the detach keys 10 11", b)
	}
	waitShown(t, shown, "lock orders serves: detached, its console keeps running")
	if s := shown.String(); !strings.Contains(s, detachLine) {
		t.Fatalf("the detach keys are not on screen:\n%s", s)
	}
}

// Ctrl-P Ctrl-Q typed by the user before the console serves is a success.
func TestAttachUserDetachAtTerminal(t *testing.T) {
	file, _, user, tty := ttyWorld(t, func(m string) string {
		return "stty raw -echo\necho asking\nhead -c 2 | od -An -tx1 >" + m + "/keys\necho 'read escape sequence' >&2\nexit 1\n"
	})
	var once sync.Once
	shown := watch(user, func(s string) {
		if strings.Contains(s, "asking") {
			once.Do(func() { user.WriteString(detachKeys) })
		}
	})
	if err := attachConsole(file, "orders", tty, tty, io.Discard); err != nil {
		t.Fatalf("detach reported as an error: %v", err)
	}
	waitShown(t, shown, "detached from orders: its console keeps running")
	if strings.Contains(shown.String(), "serves: detached") {
		t.Fatalf("a user's detach read as lox's:\n%s", shown.String())
	}
}

// Attached to a console that already serves (to use its commands), lox
// does not detach by itself.
func TestAttachToServingConsoleStays(t *testing.T) {
	file, marks, user, tty := ttyWorld(t, func(string) string { return "exit 0\n" })
	if err := os.WriteFile(marks+"/served", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	shown := watch(user, func(string) {})
	if err := attachConsole(file, "orders", tty, tty, io.Discard); err != nil {
		t.Fatalf("attach: %v", err)
	}
	waitShown(t, shown, detachLine)
	if strings.Contains(shown.String(), "serves: detached") {
		t.Fatalf("lox detached from a console that already served:\n%s", shown.String())
	}
}

// A closed terminal (a hang-up) or a signal to lox never reaches the
// console: the attach does not proxy signals, and names its detach keys.
func TestAttachDoesNotProxySignals(t *testing.T) {
	marks := t.TempDir()
	file := attachWorld(t, "echo \"$@\" >"+marks+"/args\nexit 0\n")
	var out bytes.Buffer
	if err := attachConsole(file, "orders", devNull(t), &out, io.Discard); err != nil {
		t.Fatalf("attach: %v", err)
	}
	b, _ := os.ReadFile(marks + "/args")
	if !strings.Contains(string(b), " attach --sig-proxy=false --detach-keys ctrl-p,ctrl-q lock-orders") {
		t.Fatalf("docker args: %q", b)
	}
	if !strings.Contains(out.String(), detachLine) {
		t.Fatalf("the detach keys are not said:\n%s", out.String())
	}
}

func TestUnixListening(t *testing.T) {
	table := "Num       RefCount Protocol Flags    Type St Inode Path\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 11 /run/locksql/a.sock\n" +
		"0000000000000000: 00000003 00000000 00000000 0001 03 12 /run/lockmq/b.sock\n"
	for tool, want := range map[string]bool{"locksql": true, "lockmq": false, "lockfile": false, "": false} {
		if got := unixListening(table, tool); got != want {
			t.Errorf("unixListening(%q) = %v, want %v", tool, got, want)
		}
	}
}

func waitShown(t *testing.T, s *screen, want string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(s.String(), want) {
			return
		}
	}
	t.Fatalf("not shown: %q\n%s", want, s.String())
}
