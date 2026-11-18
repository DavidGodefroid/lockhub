package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/hubtest"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/lockconsoles"
	"github.com/DavidGodefroid/lockhub/internal/loxlive"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/peer"
)

// lox live enrol records what is applied only once the human typed each
// production profile's name and said yes.
func TestLiveEnrol(t *testing.T) {
	rev := &family.Reviewed{Fingerprint: "sha256:abc", Images: map[string]string{"img@sha256:1": "v1.0.0"}, Production: map[string]string{"db": "prod"}}
	probe := func(context.Context) (*family.Reviewed, error) { return rev, nil }
	now := time.Unix(1_800_000_000, 0)
	enrol := func(t *testing.T, input string, p func(context.Context) (*family.Reviewed, error)) (int, error, string, *family.Enrolment) {
		t.Helper()
		state := filepath.Join(t.TempDir(), "state")
		os.Mkdir(state, 0o700)
		var out bytes.Buffer
		code, err := liveEnrol(context.Background(), bufio.NewReader(strings.NewReader(input)), &out, p, state, "~/ws", "david",
			map[string]family.Facts{"db": {Credentials: "vault"}, "old": {Credentials: "ask"}}, now)
		e, rerr := family.ReadEnrolment(state)
		if rerr != nil {
			t.Fatal(rerr)
		}
		return code, err, out.String(), e
	}
	code, err, out, e := enrol(t, "prod\ny\n", probe)
	if code != 0 || err != nil || e == nil || e.Fingerprint != "sha256:abc" || e.Production["db"] != "prod" || e.Images["img@sha256:1"] != "v1.0.0" || e.By != "david" {
		t.Fatalf("enrolled: %d %v %+v\n%s", code, err, e, out)
	}
	for _, want := range []string{`Type the profile name "prod"`, "PRODUCTION profile prod", "warning: lock old takes credentials a human types", "Enrol this workspace for lox live? [y/N]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for name, input := range map[string]string{"a wrong name": "production\ny\n", "y for the name": "y\ny\n", "no": "prod\nn\n", "Enter": "prod\n\n", "end of input": "", "end after the name": "prod\n"} {
		if code, _, out, e := enrol(t, input, probe); code == 0 || e != nil {
			t.Errorf("%s: enrolled (%d)\n%s", name, code, out)
		}
	}
	// Not what is applied, or a probe that failed: nothing asked, nothing enrolled.
	if code, err, out, e := enrol(t, "prod\ny\n", func(context.Context) (*family.Reviewed, error) { return nil, nil }); code == 0 || err == nil || e != nil || strings.Contains(out, "[y/N]") {
		t.Errorf("a changed configuration: %d %v\n%s", code, err, out)
	}
	if code, err, _, e := enrol(t, "prod\ny\n", func(context.Context) (*family.Reviewed, error) { return nil, errors.New("image not signed") }); code == 0 || err == nil || e != nil {
		t.Errorf("a failed probe: %d %v", code, err)
	}
	// A production profile the review cannot name is not enrolled blind.
	rev2 := &family.Reviewed{Fingerprint: "sha256:abc", Production: map[string]string{"db": ""}}
	if code, err, _, e := enrol(t, "\ny\n", func(context.Context) (*family.Reviewed, error) { return rev2, nil }); code == 0 || err == nil || e != nil {
		t.Errorf("an unnamed production profile: %d %v", code, err)
	}
}

// lox run refuses to start while lox live serves the workspace, and lox
// live while a lox run does.
func TestRunAndLiveExclude(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	ws := t.TempDir()
	abs := filepath.Join(ws, family.Dir, family.FileName)
	os.MkdirAll(filepath.Dir(abs), 0o755)
	os.WriteFile(abs, []byte("version: 1\nhub:\n  image: ghcr.io/davidgodefroid/lockhub@sha256:"+strings.Repeat("1", 64)+"\n"), 0o644)
	state := stateDir(family.Project(family.Workspace(abs)))

	liveHeld, err := loxlive.Acquire(state, loxlive.Live)
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	if _, ok := serveLock(abs, &errb); ok || !strings.Contains(errb.String(), "lox run: lox live serves this workspace's decisions") || !strings.Contains(errb.String(), "lox approve") {
		t.Fatalf("lox run next to lox live: %q", errb.String())
	}
	liveHeld()

	release, ok := serveLock(abs, &errb)
	if !ok {
		t.Fatal("lox run once lox live stopped")
	}
	var out, errb2 bytes.Buffer
	code := run([]string{"live", "--file", abs, "--status-socket", filepath.Join(t.TempDir(), "s.sock")}, os.Stdin, &out, &errb2)
	if code != 1 || !strings.Contains(errb2.String(), "lox live: lox run serves this workspace's decisions in a terminal") {
		t.Fatalf("lox live next to lox run: %d %q", code, errb2.String())
	}
	release()
}

// lox live status prints the health of the status socket and exits 0
// only when lox live serves.
func TestLiveStatus(t *testing.T) {
	dir, err := os.MkdirTemp("", "loxlive")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "status.sock")
	var out, errb bytes.Buffer
	if code := run([]string{"live", "status", "--json", "--status-socket", sock}, os.Stdin, &out, &errb); code != 1 {
		t.Fatalf("no lox live: exit %d", code)
	}
	var h loxlive.Health
	if err := json.Unmarshal(out.Bytes(), &h); err != nil || h.Serving || h.Locks == nil || !strings.Contains(h.Detail, "does not answer") {
		t.Fatalf("no lox live: %s", out.String())
	}

	e := hubtest.New(t, 0)
	fsock := filepath.Join(dir, "facade.sock")
	fln, err := net.Listen("unix", fsock)
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: api.FacadeHandler(e.Hub), ConnContext: peer.ConnContext}
	go fsrv.Serve(fln)
	defer fsrv.Close()
	tr := loxlive.NewTracker()
	tr.Started([]string{"db"})
	tr.Hub(nil)
	tr.Console("db", loxrun.ConsoleStatus{State: loxrun.ConsoleWaiting, Blocked: loxrun.BlockedSecret, Detail: "its console asks a password"})
	ln, err := loxlive.Listen(sock, "")
	if err != nil {
		t.Fatal(err)
	}
	srv := (&loxlive.Status{Tracker: tr, Hub: approve.Dial(fsock)}).Server()
	go srv.Serve(ln)
	defer srv.Close()

	out.Reset()
	if code := run([]string{"live", "status", "--status-socket", sock}, os.Stdin, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), "not serving") || !strings.Contains(out.String(), "missing_secret") {
		t.Fatalf("a lock blocked: exit %d\n%s", code, out.String())
	}
	tr.Console("db", loxrun.ConsoleStatus{State: loxrun.ConsoleServing})
	out.Reset()
	if code := run([]string{"live", "status", "--json", "--status-socket", sock}, os.Stdin, &out, &errb); code != 0 {
		t.Fatalf("serving: exit %d\n%s", code, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != `{"serving":true,"locks":{"db":"serving"},"pending":0,"detail":"serving"}` {
		t.Fatalf("health JSON: %s", got)
	}
}

// fakeBridge is the consoles of a lox live under test: each lock serves.
type fakeBridge struct{ ch chan loxrun.ConsoleEvent }

func (f *fakeBridge) Events() <-chan loxrun.ConsoleEvent { return f.ch }
func (f *fakeBridge) Answer(string, int, []byte) error   { return errors.New("no question") }

// lox live's loop: with no enrolment, or a start that needs one, nothing
// is started nor decided, the health says needs_enrolment and it keeps
// running; once enrolled it starts, serves this workspace's hub (one
// that takes facade live) and its health is serving; a SIGHUP starts it
// over; a start that fails is retried.
func TestLiveLoop(t *testing.T) {
	old1, old2, old3, old4 := liveEnrolPoll, liveRecheck, liveRetry, liveRetryMax
	liveEnrolPoll, liveRecheck, liveRetry, liveRetryMax = 20*time.Millisecond, time.Hour, 30*time.Millisecond, 30*time.Millisecond
	defer func() { liveEnrolPoll, liveRecheck, liveRetry, liveRetryMax = old1, old2, old3, old4 }()
	dir, err := os.MkdirTemp("", "loxlive")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "xdg"))
	abs := filepath.Join(dir, "ws", family.Dir, family.FileName)
	os.MkdirAll(filepath.Dir(abs), 0o755)
	os.WriteFile(abs, []byte("version: 1\nhub:\n  image: ghcr.io/davidgodefroid/lockhub@sha256:"+strings.Repeat("1", 64)+
		"\nlocks:\n  db:\n    type: locksql\n    image: ghcr.io/davidgodefroid/locksql@sha256:"+strings.Repeat("2", 64)+"\n"), 0o644)
	state := stateDir(family.Project(family.Workspace(abs)))
	os.MkdirAll(state, 0o700)

	// This workspace's hub on a facade socket.
	lock := hubtest.NewLock("db")
	e := hubtest.New(t, 0, lock)
	os.WriteFile(filepath.Join(state, "hub.pub"), []byte(keys.Public(e.Pub)+"\n"), 0o644)
	sock := filepath.Join(dir, "facade.sock")
	fln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fsrv := &http.Server{Handler: api.FacadeHandler(e.Hub), ConnContext: peer.ConnContext}
	go fsrv.Serve(fln)
	defer fsrv.Close()

	var mu sync.Mutex
	starts, startErr := 0, error(nil)
	var out syncWriter
	hup := make(chan os.Signal, 1)
	l := &live{abs: abs, state: state, sock: sock, keysDir: filepath.Join(dir, "keys"), out: &out, stderr: &out,
		tracker: loxlive.NewTracker(), hub: approve.Dial(sock), reload: hup}
	l.start = func(context.Context, *family.Enrolment) error {
		mu.Lock()
		defer mu.Unlock()
		starts++
		return startErr
	}
	l.consoles = func(ctx context.Context, locks []lockconsoles.Lock) (loxrun.Consoles, func()) {
		b := &fakeBridge{ch: make(chan loxrun.ConsoleEvent, 8)}
		for _, lk := range locks {
			b.ch <- loxrun.ConsoleEvent{Instance: lk.Instance, Lock: lk.Type, State: loxrun.ConsoleServing}
		}
		return b, func() {}
	}
	started := func() int { mu.Lock(); defer mu.Unlock(); return starts }
	waitFor := func(what string, ok func(loxlive.Health) bool) loxlive.Health {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			h := l.tracker.Health()
			if ok(h) {
				return h
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: health %+v\n%s", what, h, out.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.loop(ctx) }()
	defer func() { cancel(); <-done }()

	// Not enrolled: nothing started, needs_enrolment, still running.
	h := waitFor("not enrolled", func(h loxlive.Health) bool { return h.Locks["db"] == loxlive.NeedsEnrolment })
	if h.Serving || started() != 0 || !strings.Contains(h.Detail, "not enrolled") {
		t.Fatalf("not enrolled: %+v, %d starts", h, started())
	}

	// Enrolled, but what would start differs: the start applies nothing.
	mu.Lock()
	startErr = &family.NeedsEnrolmentError{Why: "the configuration differs from the one applied: + lock db routed only to tty"}
	mu.Unlock()
	if err := family.WriteEnrolment(state, &family.Enrolment{Version: 1, Fingerprint: "sha256:abc", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	h = waitFor("a changed configuration", func(h loxlive.Health) bool { return strings.Contains(h.Detail, "routed only to tty") })
	if h.Serving || h.Locks["db"] != loxlive.NeedsEnrolment || started() != 1 {
		t.Fatalf("changed configuration: %+v, %d starts", h, started())
	}
	time.Sleep(100 * time.Millisecond)
	if started() != 1 {
		t.Fatalf("checked again with nothing changed: %d starts", started())
	}

	// A SIGHUP checks again; a start that fails otherwise is retried.
	mu.Lock()
	startErr = errors.New("Cannot connect to the Docker daemon")
	mu.Unlock()
	hup <- os.Interrupt
	h = waitFor("docker down", func(h loxlive.Health) bool {
		return h.Locks["db"] == loxlive.Down && strings.Contains(h.Detail, "Docker daemon")
	})
	if h.Serving {
		t.Fatalf("docker down: %+v", h)
	}
	n := started()
	mu.Lock()
	startErr = nil
	mu.Unlock()
	waitFor("serving", func(h loxlive.Health) bool { return h.Serving && h.Locks["db"] == loxlive.Serving })
	if started() <= n {
		t.Fatal("the failed start was not retried")
	}

	// A new enrolment starts it over.
	n = started()
	time.Sleep(20 * time.Millisecond)
	if err := family.WriteEnrolment(state, &family.Enrolment{Version: 1, Fingerprint: "sha256:def", At: time.Now().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for started() == n {
		if time.Now().After(deadline) {
			t.Fatalf("a new enrolment did not start it over\n%s", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitFor("serving again", func(h loxlive.Health) bool { return h.Serving })
	if o := out.String(); strings.Contains(o, "\x1b[") || !strings.Contains(o, "lox live: needs enrolment, nothing started") || !strings.Contains(o, "lox live: serving the decisions its rules take") {
		t.Errorf("log:\n%s", o)
	}
}

type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncWriter) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
