//go:build linux || darwin

package lockconsoles

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// fakeConsole is a console's terminal played by a shell script on the
// bridge's pty: it records its question as lockkit does (a .question
// file), reads the answer, and ends as an idle session does; Docker
// starts it again.
const fakeConsole = `
D=$1
stty icrnl 2>/dev/null
ask() { printf '%s ' "$1"; printf '%s\n' "$1" > "$D/c.question"; IFS= read -r a; rm -f "$D/c.question"; printf '\n'; }
printf '\033[1;31mPRODUCTION\033[0m profile shop-prod\n  limits.idle_timeout  10m -> 60m\n'
ask 'Apply these changes? [y/N]'; echo "$a" >> "$D/answers"
ask 'Password for app_ro@db:'; echo "$a" >> "$D/answers"
echo serving
sleep 1
echo 'session ended: idle for 10m0s'
touch "$D/exited"
`

type fakeDocker struct{ dir string }

func (f fakeDocker) Container(context.Context, string) (string, bool, error) {
	if err := os.Remove(filepath.Join(f.dir, "exited")); err == nil {
		return "c1", false, nil // stopped once, then started again
	}
	return "c1", true, nil
}

func (f fakeDocker) Question(_ context.Context, _, _ string) (string, error) {
	b, err := os.ReadFile(filepath.Join(f.dir, "c.question"))
	if os.IsNotExist(err) {
		return "", nil
	}
	q, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return q, err
}

func (f fakeDocker) Attach(ctx context.Context, _ string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", fakeConsole, "sh", f.dir)
}

func next(t *testing.T, b *Bridge, want loxrun.ConsoleState) loxrun.ConsoleEvent {
	t.Helper()
	to := time.After(10 * time.Second)
	for {
		select {
		case e := <-b.Events():
			if e.State == want {
				return e
			}
		case <-to:
			t.Fatalf("no %s event", want)
		}
	}
}

// The bridge reads a console's question and the lines above it from its
// terminal, types the answers there, sees it serve, stop at its idle end
// (its last line), and follows it again once Docker started it again. A
// secret typed never comes back from the terminal.
func TestBridge(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("no stty")
	}
	defer func(p, s, r time.Duration) { poll, settle, retry = p, s, r }(poll, settle, retry)
	poll, settle, retry = 50*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := Start(ctx, fakeDocker{dir}, []Lock{{Instance: "shop-prod", Type: "locksql"}})
	defer b.Close()

	e := next(t, b, loxrun.ConsoleWaiting)
	q := e.Question
	if q.Prompt != "Apply these changes? [y/N]" || e.Instance != "shop-prod" || e.Lock != "locksql" {
		t.Fatalf("first question: %+v %+v", e, q)
	}
	if ctx := strings.Join(q.Context, "\n"); !strings.Contains(ctx, "PRODUCTION profile shop-prod") || !strings.Contains(ctx, "10m -> 60m") {
		t.Fatalf("context: %q", q.Context)
	}
	if err := b.Answer("shop-prod", q.Seq+1, []byte("y")); err == nil {
		t.Fatal("an answer to another question was typed")
	}
	if err := b.Answer("shop-prod", q.Seq, []byte("y")); err != nil {
		t.Fatal(err)
	}
	e = next(t, b, loxrun.ConsoleWaiting)
	if e.Question.Prompt != "Password for app_ro@db:" || e.Question.Seq == q.Seq {
		t.Fatalf("second question: %+v", e.Question)
	}
	if strings.Contains(strings.Join(e.Question.Context, "\n"), "Apply") {
		t.Errorf("the answered question is in the next one's context: %q", e.Question.Context)
	}
	if err := b.Answer("shop-prod", e.Question.Seq, []byte("pw-secret-1")); err != nil {
		t.Fatal(err)
	}
	next(t, b, loxrun.ConsoleServing)
	e = next(t, b, loxrun.ConsoleStopped)
	if e.Err != "session ended: idle for 10m0s" {
		t.Errorf("stopped: %q", e.Err)
	}
	e = next(t, b, loxrun.ConsoleWaiting)
	if e.Question.Prompt != "Apply these changes? [y/N]" {
		t.Fatalf("after the restart: %+v", e.Question)
	}
	if strings.Contains(strings.Join(e.Question.Context, "\n"), "pw-secret-1") {
		t.Error("the secret came back from the terminal")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "answers"))
	if string(got) != "y\npw-secret-1\n" {
		t.Errorf("answers typed: %q", got)
	}
}

// feedConsole serves (its status row drawn as lockkit draws it), prints
// two refusals, and writes the lines typed at it (its commands).
const feedConsole = `
D=$1
stty icrnl 2>/dev/null
printf '\033[1;32m✗\033[0m refused [E_COST]: weight check\n'
E=$(printf '\033')
printf '%s' "${E}7${E}[24;1H${E}[2KSHOP-PROD · policy change pending :review${E}8"
printf '✗ refused [E_COST]: weight check\n'
while IFS= read -r l; do echo "$l" >> "$D/typed"; echo "typed $l"; done
`

type feedDocker struct{ fakeDocker }

func (f feedDocker) Attach(ctx context.Context, _ string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", feedConsole, "sh", f.dir)
}

func (f feedDocker) Logs(context.Context, string, time.Time, int) ([]byte, error) {
	return []byte("changes refused: the last approved policy applies\r\n"), nil
}

// The bridge hands lox run what a console printed: its backlog (docker
// logs) first, then its lines and status row as they come; it types
// :status once the console serves, and a command lox run asks for.
func TestBridgeFeed(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("no stty")
	}
	defer func(p, s, r time.Duration) { poll, settle, retry = p, s, r }(poll, settle, retry)
	poll, settle, retry = 50*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := Start(ctx, feedDocker{fakeDocker{dir}}, []Lock{{Instance: "shop", Type: "locksql"}})
	defer b.Close()

	var lines []string
	var status string
	backlog := false
	to := time.After(10 * time.Second)
	for !strings.Contains(strings.Join(lines, "\n"), "typed :status") {
		select {
		case e := <-b.Events():
			if e.Feed == nil {
				continue
			}
			if e.Feed.Backlog {
				backlog = len(lines) == 0 && strings.Contains(strings.Join(e.Feed.Lines, "\n"), "changes refused")
			}
			lines = append(lines, e.Feed.Lines...)
			if e.Feed.StatusSet {
				status = e.Feed.Status
			}
		case <-to:
			t.Fatalf("no :status typed; lines %q", lines)
		}
	}
	if !backlog {
		t.Errorf("the backlog did not come first: %q", lines)
	}
	n := 0
	for _, l := range lines {
		if strings.Contains(l, "refused [E_COST]: weight check") {
			n++
		}
		if strings.Contains(l, "\x1b") {
			t.Errorf("an escape in a feed line: %q", l)
		}
	}
	if n != 2 || status != "SHOP-PROD · policy change pending :review" {
		t.Errorf("refusals %d status %q; lines %q", n, status, lines)
	}
	if err := b.Command("shop", ":review"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := os.ReadFile(filepath.Join(dir, "typed"))
		if string(got) == ":status\n:review\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("typed: %q", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := b.Command("nope", ":review"); err == nil {
		t.Error("a command typed at an unknown console")
	}
}
