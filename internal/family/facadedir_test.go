package family

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// foreign makes the directory at d look owned by another account (as a
// directory Docker made as root would) while its mode is not 0700: a
// directory made again in its place, 0700, is the user's, and so is every
// other file. (Not by inode: a directory made again can reuse it.)
func foreign(t *testing.T, d string) func(os.FileInfo) bool {
	t.Helper()
	if fi, err := os.Lstat(d); err != nil || fi.Mode().Perm() == 0o700 {
		t.Fatalf("%s: want a directory not 0700 (%v)", d, err)
	}
	return func(fi os.FileInfo) bool { return fi.Name() != filepath.Base(d) || fi.Mode().Perm() == 0o700 }
}

// facadePath is lockhub in a fresh runtime directory of the user's, 0700
// (a test's temporary directory follows the umask).
func facadePath(t *testing.T) string {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	return filepath.Join(dir, "lockhub")
}

func mine(os.FileInfo) bool { return true }

func TestFacadeDirMissingIsMade(t *testing.T) {
	d := facadePath(t)
	made, note, err := readyFacadeDir(d, ownedByMe)
	if err != nil || note != "" || !made {
		t.Fatalf("made %v, note %q, err %v", made, note, err)
	}
	if err := checkPrivate(d); err != nil {
		t.Error(err)
	}
}

func TestFacadeDirReadyIsKept(t *testing.T) {
	d := facadePath(t)
	os.Mkdir(d, 0o700)
	os.WriteFile(filepath.Join(d, "facade.sock"), nil, 0o600)
	made, note, err := readyFacadeDir(d, ownedByMe)
	if err != nil || note != "" || made {
		t.Fatalf("made %v, note %q, err %v", made, note, err)
	}
	if _, err := os.Stat(filepath.Join(d, "facade.sock")); err != nil {
		t.Error("the directory was made again")
	}
}

// The user's directory with a mode open to others (a rootless engine makes
// a missing bind source as the user, 0755) is closed.
func TestFacadeDirOwnOpenModeIsClosed(t *testing.T) {
	d := facadePath(t)
	os.Mkdir(d, 0o700)
	os.Chmod(d, 0o755)
	made, note, err := readyFacadeDir(d, ownedByMe)
	if err != nil || !made {
		t.Fatal(made, err)
	}
	if !strings.Contains(note, "0755") || !strings.Contains(note, "0700") {
		t.Errorf("note %q", note)
	}
	if err := checkPrivate(d); err != nil {
		t.Error(err)
	}
}

// An empty directory of another account (Docker made it as root) is
// removed and made again, the user's, 0700.
func TestFacadeDirForeignEmptyIsRemade(t *testing.T) {
	d := facadePath(t)
	os.Mkdir(d, 0o755)
	made, note, err := readyFacadeDir(d, foreign(t, d))
	if err != nil || !made {
		t.Fatal(made, err)
	}
	if !strings.Contains(note, d) || !strings.Contains(note, "made again") {
		t.Errorf("note %q", note)
	}
	if err := checkPrivate(d); err != nil {
		t.Error(err)
	}
}

// A directory of another account that holds something is left alone: the
// error says what to run.
func TestFacadeDirForeignNotEmptyNamesTheFix(t *testing.T) {
	d := facadePath(t)
	os.Mkdir(d, 0o755)
	os.WriteFile(filepath.Join(d, "x"), nil, 0o600)
	_, _, err := readyFacadeDir(d, foreign(t, d))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"sudo ls -la " + d, "sudo rm -r " + d + " && mkdir -m 700 " + d, "lox up"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(d, "x")); err != nil {
		t.Error("removed what the directory held")
	}
}

// When lox cannot remove the directory (its parent is not writable), the
// error says what to run.
func TestFacadeDirForeignUnremovableNamesTheFix(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root removes it anyway")
	}
	parent := filepath.Dir(facadePath(t))
	d := filepath.Join(parent, "lockhub")
	os.MkdirAll(d, 0o755)
	os.Chmod(parent, 0o500)
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	_, _, err := readyFacadeDir(d, foreign(t, d))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"sudo rmdir " + d + " && mkdir -m 700 " + d, "lox up"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

// A link in its place is never followed nor removed.
func TestFacadeDirLinkRefused(t *testing.T) {
	d := facadePath(t)
	dir := filepath.Dir(d)
	os.Mkdir(filepath.Join(dir, "elsewhere"), 0o700)
	os.Symlink(filepath.Join(dir, "elsewhere"), d)
	_, _, err := readyFacadeDir(d, mine)
	if err == nil || !strings.Contains(err.Error(), "lox up") {
		t.Fatalf("err %v", err)
	}
	if fi, _ := os.Lstat(d); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced")
	}
}

// lox up repairs the facade directory before it starts anything, says so,
// and creates the hub again on it.
func TestUpRepairsFacadeDir(t *testing.T) {
	w := newWS(t, hubOnly)
	run := filepath.Join(w.dir, "run", "lockhub")
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	os.Chmod(run, 0o755)
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(run); err != nil {
		t.Error(err)
	}
	if !strings.Contains(out, "facade directory") {
		t.Errorf("no note:\n%s", out)
	}
	if !f.ran("up -d --no-deps --force-recreate lockhub") {
		t.Errorf("hub not created again: %v", f.calls)
	}
	// Ready: nothing to repair, the hub is left to compose.
	f = newFake()
	out, err = w.up("y\n", f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "facade directory") || f.ran("--force-recreate lockhub") {
		t.Errorf("repaired a ready directory:\n%s\n%v", out, f.calls)
	}
}

// A facade directory gone since the last lox up (wiped at logout or
// reboot) is made again, and the existing hub, which binds the deleted
// one, is created again: compose up alone leaves it, without a socket.
// The first lox up has no hub to create again.
func TestUpRemakesHubWhenFacadeDirWasMissing(t *testing.T) {
	w := newWS(t, hubOnly)
	run := filepath.Join(w.dir, "run", "lockhub")
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	if f.ran("--force-recreate lockhub") {
		t.Errorf("first lox up created the hub twice: %v", f.calls)
	}
	os.Remove(run)
	f = newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(run); err != nil {
		t.Error(err)
	}
	if !f.ran("up -d --no-deps --force-recreate lockhub") {
		t.Errorf("hub not created again: %v", f.calls)
	}
}

// lox init's "nothing changed" probe does not take a facade directory
// Docker made as root for ready: lox up must run and repair it.
func TestProbeFacadeDirNotReady(t *testing.T) {
	w := newWS(t, hubOnly)
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	probe := func() bool {
		u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: newFake(), Out: io.Discard, Probe: true}
		if err := u.Do(context.Background()); err != nil {
			t.Fatal(err)
		}
		return u.Same
	}
	if !probe() {
		t.Fatal("unchanged workspace not same")
	}
	os.Chmod(filepath.Join(w.dir, "run", "lockhub"), 0o755)
	if probe() {
		t.Error("a facade directory open to others probed as unchanged")
	}
}

// The parent must be the user's and writable by no one else (the fallback
// under the shared temporary directory, made by another account): nothing
// is made or removed there.
func TestFacadeDirParentRefused(t *testing.T) {
	for name, set := range map[string]func(parent string) func(os.FileInfo) bool{
		"another account's": func(parent string) func(os.FileInfo) bool {
			os.Chmod(parent, 0o755)
			return func(fi os.FileInfo) bool { return fi.Name() != filepath.Base(parent) }
		},
		"writable by others": func(parent string) func(os.FileInfo) bool {
			os.Chmod(parent, 0o777)
			return ownedByMe
		},
	} {
		t.Run(name, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "lockhub-1000")
			d := filepath.Join(parent, "lockhub")
			os.MkdirAll(d, 0o755)
			mine := set(parent)
			t.Cleanup(func() { os.Chmod(parent, 0o700) })
			_, _, err := readyFacadeDir(d, mine)
			if err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") {
				t.Fatalf("err %v", err)
			}
			if fi, err := os.Lstat(d); err != nil || fi.Mode().Perm() != 0o755 {
				t.Error("touched the facade directory")
			}
		})
	}
	// A missing parent is made, 0700.
	parent := filepath.Join(t.TempDir(), "lockhub-1000")
	if _, _, err := readyFacadeDir(filepath.Join(parent, "lockhub"), ownedByMe); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(parent); err != nil {
		t.Error(err)
	}
}

// The old hub restarted by its engine can make the directory again, as
// root, between lox's removal and its mkdir: lox tries once more, then
// says to run lox up again.
func TestFacadeDirRace(t *testing.T) {
	t.Cleanup(func() { facadeDirRace = nil })
	for _, times := range []int{1, 100} {
		d := facadePath(t)
		os.Mkdir(d, 0o755)
		n := 0
		facadeDirRace = func(d string) {
			if n < times {
				n++
				os.Mkdir(d, 0o755)
			}
		}
		made, _, err := readyFacadeDir(d, foreign(t, d))
		switch {
		case times == 1 && (err != nil || !made || checkPrivate(d) != nil):
			t.Errorf("once: made %v, err %v", made, err)
		case times > 1 && (err == nil || !strings.Contains(err.Error(), "run lox up again")):
			t.Errorf("always: err %v", err)
		}
	}
}

// A file of another account in its place: the fix says sudo.
func TestFacadeDirForeignFileSaysSudo(t *testing.T) {
	d := facadePath(t)
	os.WriteFile(d, nil, 0o644)
	_, _, err := readyFacadeDir(d, func(fi os.FileInfo) bool { return fi.IsDir() })
	if err == nil || !strings.Contains(err.Error(), "sudo rm "+d) {
		t.Fatalf("err %v", err)
	}
}

// Docker never makes the facade directory: a missing one fails the hub's
// start instead of being made as root.
func TestComposeFacadeBindNotCreated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	os.WriteFile(p, []byte(hubOnly), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out := Compose(c, Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", Workspace: "/w", User: "0:0"})
	want := "        source: \"/r/lockhub\"\n        target: /run/lockhub-facade\n        bind:\n          create_host_path: false\n"
	if !strings.Contains(out, want) {
		t.Errorf("compose lacks %q:\n%s", want, out)
	}
}
