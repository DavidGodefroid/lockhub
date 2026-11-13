package lockconsoles

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// fileDocker is a console whose question file is file.
type fileDocker struct{ file *string }

func (fileDocker) Container(context.Context, string) (string, bool, error) { return "c1", true, nil }

func (d fileDocker) Question(context.Context, string, string) (string, error) { return *d.file, nil }

func (fileDocker) Attach(ctx context.Context, _ string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

// attached is a bridge on one console attached (its terminal a pipe) that
// printed screen, its question file read from *file.
func attached(t *testing.T, file *string, screen string) (*Bridge, *console) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	c := &console{Lock: Lock{Instance: "shop", Type: "locksql"}, master: w, id: "c1"}
	c.scr.Write([]byte(screen))
	b := &Bridge{d: fileDocker{file}, events: make(chan loxrun.ConsoleEvent, 8), cons: map[string]*console{"shop": c}}
	return b, c
}

// question is the question of the last event look sent, nil when it sent
// none.
func question(b *Bridge, c *console) *loxrun.ConsoleQuestion {
	b.look(context.Background(), c, "c1")
	select {
	case e := <-b.Events():
		return e.Question
	default:
		return nil
	}
}

// A question file with context (lockkit v0.16.0 or later): the prompt is
// its first line, the context its recorded lines, whatever the screen
// shows.
func TestLookRecordedContext(t *testing.T) {
	file := "Approve? [y/N] \n--- printed above the question ---\nPRODUCTION\n+ allow write"
	b, c := attached(t, &file, "a result row 42\nApprove? [y/N] ")
	q := question(b, c)
	if q == nil {
		t.Fatal("no question")
	}
	if q.Prompt != "Approve? [y/N]" {
		t.Errorf("prompt %q", q.Prompt)
	}
	if want := []string{"PRODUCTION", "+ allow write"}; !slices.Equal(q.Context, want) {
		t.Errorf("context %q, want %q", q.Context, want)
	}

	// The same prompt with other context lines is the same question.
	file = "Approve? [y/N]\n--- printed above the question ---\nsomething else"
	if q2 := question(b, c); q2 != nil {
		t.Errorf("a new question for the same prompt: %+v", q2)
	}
	if c.question.Seq != q.Seq || !slices.Equal(c.question.Context, q.Context) {
		t.Errorf("question changed: %+v", c.question)
	}

	file = "Password for app_ro@db:\n"
	if q2 := question(b, c); q2 == nil || q2.Seq != q.Seq+1 || q2.Prompt != "Password for app_ro@db:" {
		t.Errorf("next question: %+v", q2)
	}
}

// A question file with its prompt only (an older lockkit): the context is
// read from the screen, the prompt left out.
func TestLookScreenContext(t *testing.T) {
	file := "Approve? [y/N]\n"
	b, c := attached(t, &file, "PRODUCTION profile shop-prod\n  limits.idle_timeout  10m -> 60m\nApprove? [y/N]\n")
	q := question(b, c)
	if q == nil {
		t.Fatal("no question")
	}
	if want := []string{"PRODUCTION profile shop-prod", "  limits.idle_timeout  10m -> 60m"}; q.Prompt != "Approve? [y/N]" || !slices.Equal(q.Context, want) {
		t.Errorf("question %+v, want context %q", q, want)
	}
}

// The recorded lines are the lock's output: their escapes and control
// characters never reach the card, and the card shows the last 16.
func TestLookRecordedContextCleaned(t *testing.T) {
	lines := []string{"\x1b[1;31mRED\x1b[0m\x07 bell", "\x1b]0;title\x07osc", "back\bspace\r"}
	for i := range 20 {
		lines = append(lines, "line "+strconv.Itoa(i))
	}
	file := "Approve? [y/N]\n--- printed above the question ---\n" + strings.Join(lines, "\n")
	b, c := attached(t, &file, "")
	q := question(b, c)
	if q == nil || len(q.Context) != maxContext || q.Context[maxContext-1] != "line 19" {
		t.Fatalf("question %+v", q)
	}
	for _, l := range recorded(lines[:3]) {
		for _, r := range l {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
				t.Errorf("a control character in %q", l)
			}
		}
	}
}
