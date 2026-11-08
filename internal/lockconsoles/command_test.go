package lockconsoles

import (
	"context"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// promptDocker plays a console that starts asking while its question
// file is read: it prints its prompt, the file still empty.
type promptDocker struct {
	b *Bridge
	c *console
}

func (promptDocker) Container(context.Context, string) (string, bool, error) { return "c1", true, nil }

func (d promptDocker) Question(context.Context, string, string) (string, error) {
	d.b.mu.Lock()
	d.c.printed++
	d.b.mu.Unlock()
	return "", nil
}

func (promptDocker) Attach(ctx context.Context, _ string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

// A line is not typed when the console printed something while its
// question file was read: it may be the prompt of a question.
func TestCommandConsolePrintedMeanwhile(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c := &console{Lock: Lock{Instance: "shop", Type: "locksql"}, master: w, state: loxrun.ConsoleServing, id: "c1"}
	b := &Bridge{cons: map[string]*console{"shop": c}}
	b.d = promptDocker{b, c}
	if err := b.Command("shop", ":status"); err == nil {
		t.Error("a line typed although the console printed meanwhile")
	}
	w.Close()
	if got, _ := io.ReadAll(r); len(got) != 0 {
		t.Errorf("typed %q", got)
	}
}
