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
