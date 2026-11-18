package servelock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lox run (shared) and lox live (exclusive) never serve one workspace
// together; several lox run may, as before; the lock goes with its
// holder.
func TestServeLock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	run1, err := Acquire(state, Run)
	if err != nil {
		t.Fatal(err)
	}
	run2, err := Acquire(state, Run)
	if err != nil {
		t.Fatalf("a second lox run: %v", err)
	}
	_, err = Acquire(state, Live)
	var he *HeldError
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "a lox at a terminal holds this workspace") {
		t.Fatalf("lox live next to lox run: %v", err)
	}
	run1()
	if _, err := Acquire(state, Live); err == nil {
		t.Fatal("lox live started while a lox run still serves")
	}
	run2()
	live, err := Acquire(state, Live)
	if err != nil {
		t.Fatalf("lox live once lox run stopped: %v", err)
	}
	_, err = Acquire(state, Run)
	if !errors.As(err, &he) || !strings.Contains(err.Error(), "lox live serves this workspace's decisions") || !strings.Contains(err.Error(), "lox approve") ||
		!strings.Contains(err.Error(), "pid ") {
		t.Fatalf("lox run next to lox live: %v", err)
	}
	if _, err := Acquire(state, Live); !errors.As(err, &he) || !strings.Contains(err.Error(), "lox live serves this workspace's decisions") {
		t.Fatalf("a second lox live: %v", err)
	}
	live()
	again, err := Acquire(state, Run)
	if err != nil {
		t.Fatalf("lox run once lox live stopped: %v", err)
	}
	again()
	// The file's text decides nothing: a planted one does not turn a lox
	// run into a lox live, nor hide a lox live.
	os.WriteFile(filepath.Join(state, "serve.lock"), []byte("pid 1\n"), 0o600)
	r1, err := Acquire(state, Run)
	if err != nil {
		t.Fatalf("lox run with a planted pid in the lock file: %v", err)
	}
	if _, err := Acquire(state, Live); !errors.As(err, &he) || !strings.Contains(err.Error(), "a lox at a terminal") {
		t.Fatalf("lox live next to lox run, a planted pid in the file: %v", err)
	}
	r1()
	l2, err := Acquire(state, Live)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(state, "serve.lock"), nil, 0o600)
	if _, err := Acquire(state, Run); !errors.As(err, &he) || !strings.Contains(err.Error(), "lox live serves") {
		t.Fatalf("lox run next to a lox live whose pid was wiped: %v", err)
	}
	l2()
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state directory %v %v", fi, err)
	}
}
