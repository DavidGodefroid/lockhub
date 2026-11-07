//go:build linux || darwin

package lockconsoles

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// dockerConsole is a console's start in a container with a terminal, as
// lox run runs a lock (tty, stdin_open): it records its questions next
// to its socket as lockkit does and reads the answers at its terminal,
// the secret with echo off.
const dockerConsole = `
mkdir -p /run/locksql
ask() { printf '%s ' "$1"; printf '%s\n' "$1" > /run/locksql/k-prod.question; IFS= read -r a; rm -f /run/locksql/k-prod.question; printf '\r\n'; }
printf 'PRODUCTION profile shop-prod\r\n'
ask 'Type the profile name "shop-prod" to continue:'; echo "$a" > /tmp/a1
stty -echo; ask 'Password for app_ro@db:'; stty echo; echo "$a" > /tmp/a2
printf 'serving\r\n'
sleep 600
`

// containerDocker is Exec on one container (no compose project).
type containerDocker struct {
	Exec
	id string
}

func (d containerDocker) Container(ctx context.Context, _ string) (string, bool, error) {
	st, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", d.id).Output()
	if err != nil {
		return "", false, err
	}
	return d.id, strings.TrimSpace(string(st)) == "true", nil
}

// The docker CLI's attach on lox run's pty, and docker exec for the
// question file: LOCKCONSOLES_DOCKER=1 runs it (it pulls alpine).
func TestDockerAttach(t *testing.T) {
	if os.Getenv("LOCKCONSOLES_DOCKER") != "1" {
		t.Skip("LOCKCONSOLES_DOCKER=1 runs it")
	}
	rnd := make([]byte, 4)
	rand.Read(rnd)
	name := "lockconsoles-e2e-" + hex.EncodeToString(rnd)
	out, err := exec.Command("docker", "run", "-d", "-t", "-i", "--name", name, "--log-driver", "none",
		"docker.io/library/alpine:3.22", "sh", "-c", dockerConsole).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := Start(ctx, containerDocker{id: name}, []Lock{{Instance: "shop-prod", Type: "locksql"}})
	e := next(t, b, loxrun.ConsoleWaiting)
	if e.Question.Prompt != `Type the profile name "shop-prod" to continue:` {
		t.Fatalf("first: %+v", e.Question)
	}
	if err := b.Answer("shop-prod", e.Question.Seq, []byte("shop-prod")); err != nil {
		t.Fatal(err)
	}
	e = next(t, b, loxrun.ConsoleWaiting)
	if e.Question.Prompt != "Password for app_ro@db:" {
		t.Fatalf("second: %+v", e.Question)
	}
	if err := b.Answer("shop-prod", e.Question.Seq, []byte("pw-secret-2")); err != nil {
		t.Fatal(err)
	}
	next(t, b, loxrun.ConsoleServing)
	for f, want := range map[string]string{"/tmp/a1": "shop-prod", "/tmp/a2": "pw-secret-2"} {
		var got []byte
		for i := 0; i < 50; i++ {
			got, _ = exec.Command("docker", "exec", name, "cat", f).Output()
			if len(got) > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if strings.TrimSpace(string(got)) != want {
			t.Errorf("%s: %q, want %q", f, got, want)
		}
	}
	b.mu.Lock()
	screen := strings.Join(b.cons["shop-prod"].scr.Last(maxLines), "\n")
	b.mu.Unlock()
	if strings.Contains(screen, "pw-secret-2") {
		t.Errorf("the secret is on the console's screen as lox run read it:\n%s", screen)
	}
	b.Close()
	if st, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output(); strings.TrimSpace(string(st)) != "true" {
		t.Error("stopping lox run stopped the console")
	}
}
