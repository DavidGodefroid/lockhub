package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

const removeYAML = "version: 1\nhub:\n  image: " + hubImg + "\nlocks:\n  orders:\n    type: locksql\n    image: " + sqlImg + "\n    profile: orders\n"

const removeTOML = "[profiles.orders]\nhost = \"db.example.com\"\n\n[profiles.inventory]\nhost = \"inv.example.com\"\n"

func removeWorld(t *testing.T) (ws, file string) {
	t.Helper()
	ws, _ = filepath.EvalSymlinks(t.TempDir())
	file = filepath.Join(ws, ".lockfamily", "lockfamily.yaml")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(removeYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".locksql"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte(removeTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	return ws, file
}

// A "n" at lox up's question puts the lock back: lockfamily.yaml is
// byte for byte what it was, the profile untouched, even with --purge.
func TestRemoveDeclinedRestores(t *testing.T) {
	ws, file := removeWorld(t)
	var out, errb bytes.Buffer
	var sawGone bool
	r := &removal{File: file, Name: "orders", Purge: true, Out: &out, Err: &errb,
		Up: func(_ context.Context, focus string) error {
			c, err := family.Load(file)
			sawGone = err == nil && len(c.Locks) == 0 && focus == "orders"
			return family.ErrNotConfirmed
		}}
	if code := r.run(context.Background()); code != 1 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	if !sawGone {
		t.Error("lox up did not see the lock removed, with the focus on it")
	}
	if b, _ := os.ReadFile(file); string(b) != removeYAML {
		t.Errorf("lockfamily.yaml not restored:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(ws, ".locksql", "config.toml")); string(b) != removeTOML {
		t.Errorf("profile touched:\n%s", b)
	}
	if want := "remove lock orders (locksql): its console stops;"; !strings.Contains(out.String(), want) {
		t.Errorf("no review line:\n%s", out.String())
	}
	if !strings.Contains(errb.String(), "not confirmed: lock orders stays") {
		t.Errorf("stderr: %s", errb.String())
	}
}

// Without --purge the profile stays; the review line says so.
func TestRemoveKeepsTheProfile(t *testing.T) {
	ws, file := removeWorld(t)
	var out, errb bytes.Buffer
	r := &removal{File: file, Name: "orders", Out: &out, Err: &errb, Up: func(context.Context, string) error { return nil }}
	if code := r.run(context.Background()); code != 0 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	if c, err := family.Load(file); err != nil || len(c.Locks) != 0 {
		t.Errorf("locks %v, %v", c, err)
	}
	if b, _ := os.ReadFile(filepath.Join(ws, ".locksql", "config.toml")); string(b) != removeTOML {
		t.Errorf("profile touched:\n%s", b)
	}
	want := "remove lock orders (locksql): its console stops; its profile stays in .locksql/config.toml unless --purge\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("review line:\n%s", out.String())
	}
}

// --purge drops the profile once lox up applied the removal.
func TestRemovePurge(t *testing.T) {
	ws, file := removeWorld(t)
	var out, errb bytes.Buffer
	r := &removal{File: file, Name: "orders", Purge: true, Out: &out, Err: &errb, Up: func(context.Context, string) error { return nil }}
	if code := r.run(context.Background()); code != 0 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	b, _ := os.ReadFile(filepath.Join(ws, ".locksql", "config.toml"))
	if string(b) != "[profiles.inventory]\nhost = \"inv.example.com\"\n" {
		t.Errorf("config.toml:\n%s", b)
	}
}

// A Ctrl-C during lox up rolls back as an interrupt; a lox up failure is
// a failure, restored too.
func TestRemoveInterruptAndFailure(t *testing.T) {
	for name, c := range map[string]struct {
		up   func(cancel context.CancelFunc) error
		code int
	}{
		"interrupt": {func(cancel context.CancelFunc) error { cancel(); return context.Canceled }, exitInterrupted},
		"failure":   {func(context.CancelFunc) error { return errors.New("docker: boom") }, 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, file := removeWorld(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, errb bytes.Buffer
			r := &removal{File: file, Name: "orders", Out: &out, Err: &errb, Up: func(context.Context, string) error { return c.up(cancel) }}
			if code := r.run(ctx); code != c.code {
				t.Errorf("code %d, want %d: %s", code, c.code, errb.String())
			}
			if b, _ := os.ReadFile(file); string(b) != removeYAML {
				t.Errorf("not restored:\n%s", b)
			}
		})
	}
}

// --purge is refused before anything changes when another lock serves
// the same profile, or the lock names none.
func TestRemovePurgeRefusedBeforeChange(t *testing.T) {
	_, file := removeWorld(t)
	two := removeYAML + "  stock:\n    type: locksql\n    image: " + sqlImg + "\n    profile: orders\n"
	os.WriteFile(file, []byte(two), 0o600)
	var out, errb bytes.Buffer
	called := false
	r := &removal{File: file, Name: "orders", Purge: true, Out: &out, Err: &errb, Up: func(context.Context, string) error { called = true; return nil }}
	if code := r.run(context.Background()); code != 1 || called || !strings.Contains(errb.String(), "lock stock serves profile orders") {
		t.Errorf("code %d, called %v: %s", code, called, errb.String())
	}
	if b, _ := os.ReadFile(file); string(b) != two {
		t.Errorf("changed:\n%s", b)
	}
	r.Name = "nope"
	if code := r.run(context.Background()); code != 1 || !strings.Contains(errb.String(), `no lock "nope"`) {
		t.Errorf("unknown lock: %d %s", code, errb.String())
	}
}
