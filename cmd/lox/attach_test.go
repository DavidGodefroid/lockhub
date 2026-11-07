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
