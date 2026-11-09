package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
)

// writeState lays out the state directory lox run leaves for a
// workspace: hub.pub and up.json with the same hub key ("" no key yet).
func writeState(t *testing.T, root, project, workspace, hubKey string) string {
	t.Helper()
	d := filepath.Join(root, project)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if hubKey == "" {
		return d
	}
	if err := os.WriteFile(filepath.Join(d, "hub.pub"), []byte(hubKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	up := `{"version":1,"project":"` + project + `","workspace":"` + workspace + `","hub_key":"` + hubKey + `"}`
	if err := os.WriteFile(filepath.Join(d, family.UpFile), []byte(up), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

// Two workspaces on one host (#172): workspace A's hub serves the shared
// facade socket. Workspace B's lox run (its hub key is another, or it has
// none yet) refuses to serve it, naming A; A's own lox run serves it.
func TestRunRefusesAnotherWorkspacesHub(t *testing.T) {
	w := newTicketsWorld(t)
	w.push(t, "shop", "SELECT * FROM workspace_a_secret")
	root := t.TempDir()
	hubKey := keys.Public(w.h.PublicKey())
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	stateA := writeState(t, root, "lockfamily-aaaa1111", "/home/u/a", hubKey)
	stateB := writeState(t, root, "lockfamily-bbbb2222", "/home/u/b", keys.Public(otherPub))
	fresh := writeState(t, root, "lockfamily-cccc3333", "/home/u/c", "")
	c := approve.Dial(w.sock)
	ctx := context.Background()

	if err := checkHub(ctx, c, w.sock, stateA); err != nil {
		t.Fatalf("A's own hub: %v", err)
	}
	want := "the facade socket " + w.sock + " is served by the hub of workspace /home/u/a (lockfamily-aaaa1111); stop it, or run this workspace with its own XDG_RUNTIME_DIR"
	for name, st := range map[string]string{"another hub key": stateB, "no hub key yet": fresh} {
		var fh *loxrun.ForeignHub
		if err := checkHub(ctx, c, w.sock, st); !errors.As(err, &fh) || fh.Msg != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	// A hub whose workspace is unknown here is still refused.
	if err := os.Remove(filepath.Join(stateA, family.UpFile)); err != nil {
		t.Fatal(err)
	}
	var fh *loxrun.ForeignHub
	if err := checkHub(ctx, c, w.sock, stateB); !errors.As(err, &fh) || !strings.Contains(fh.Msg, "another hub (key "+hubKey+"), not this workspace's") {
		t.Errorf("unknown workspace: %v", err)
	}

	// B's lox run session: it stops with the refusal, A's ticket unseen.
	var out strings.Builder
	s := &loxrun.Session{Hub: c, Keys: make(chan loxrun.Key), Out: &out, Display: "david", KeyArm: -1,
		CheckHub: func(ctx context.Context) error { return checkHub(ctx, c, w.sock, stateB) }}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.Run(rctx); !errors.As(err, &fh) {
		t.Fatalf("B's session: %v, want the refusal", err)
	}
	if strings.Contains(out.String(), "workspace_a_secret") {
		t.Errorf("A's ticket shown to B:\n%s", out.String())
	}
}

// No hub on the socket is the hub unreachable (lox run waits for it); a
// hub before GET /v1/hub cannot say whose it is, and is served (the
// released hubs predate it).
func TestRunCheckHubUnservedAndOldHub(t *testing.T) {
	dir, err := os.MkdirTemp("", "lxf") // a short path: a unix socket's is bounded
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := writeState(t, t.TempDir(), "lockfamily-aaaa1111", "/home/u/a", "")
	sock := filepath.Join(dir, "f.sock")
	var fh *loxrun.ForeignHub
	if err := checkHub(context.Background(), approve.Dial(sock), sock, state); err == nil || errors.As(err, &fh) || !errors.Is(err, family.ErrFacadeUnserved) {
		t.Errorf("no hub: %v, want unreachable", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if err := checkHub(context.Background(), approve.Dial(sock), sock, state); err != nil {
		t.Errorf("old hub: %v, want served", err)
	}
}
