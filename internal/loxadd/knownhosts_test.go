package loxadd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

// lockfileSFTP is a lockfile sftp lock whose known hosts file is the host
// file kh (lockhub#174).
func lockfileSFTP(t *testing.T, kh string) (Lock, Answers) {
	t.Helper()
	a := Answers{"source": "sftp", "host": "sftp.example.com", "port": "22", "user": "shop", "auth": "password",
		"known-hosts": kh, "credentials": CredAsk, "name": "orders"}
	l, err := Build("lockfile", a)
	if err != nil {
		t.Fatal(err)
	}
	return l, a
}

// newFileWorld is an Apply world that pins a lockfile image.
func newFileWorld(t *testing.T) *applyWorld {
	t.Helper()
	w := newApplyWorld(t)
	w.steps.PinImage = func(context.Context, string, bool) (string, error) {
		return "ghcr.io/davidgodefroid/lockfile@sha256:" + strings.Repeat("d", 64), nil
	}
	return w
}

// The known hosts file of a lockfile sftp source is copied into
// .lockfile/ before profile add, which names the path the console sees.
func TestBuildLockfileKnownHostsCopied(t *testing.T) {
	l, _ := lockfileSFTP(t, "/home/u/.ssh/known_hosts")
	if !slices.Equal(l.Copies, []ProfileCopy{{Src: "/home/u/.ssh/known_hosts", Name: "known_hosts"}}) {
		t.Fatalf("copies = %+v", l.Copies)
	}
	if i := slices.Index(l.Target, "--known-hosts"); i < 0 || l.Target[i+1] != "~/.config/lockfile/known_hosts" {
		t.Fatalf("target = %q", l.Target)
	}
	// lockssh's known_hosts is a path in the lock's home: kept as typed.
	s, err := Build("lockssh", Answers{"host": "h", "user": "u", "auth": "password", "known-hosts": "~/.ssh/kh", "credentials": CredAsk, "name": "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Copies) != 0 || !slices.Contains(s.Target, "~/.ssh/kh") {
		t.Fatalf("lockssh: copies %+v, target %q", s.Copies, s.Target)
	}
}

func TestApplyCopiesKnownHosts(t *testing.T) {
	w := newFileWorld(t)
	kh := filepath.Join(t.TempDir(), "known_hosts_sftp")
	writeTestFile(t, kh, "[sftp.example.com]:22 ssh-ed25519 AAAA\n")
	var seen string
	w.steps.Up = func(context.Context, string) error {
		seen = readOr(t, filepath.Join(w.root, ".lockfile", "known_hosts"))
		return nil
	}
	l, a := lockfileSFTP(t, kh)
	if err := w.steps.Apply(context.Background(), l, a); err != nil {
		t.Fatal(err)
	}
	if seen != "[sftp.example.com]:22 ssh-ed25519 AAAA\n" {
		t.Fatalf("lox up saw .lockfile/known_hosts = %q", seen)
	}
	if !strings.Contains(w.out.String(), kh+" copied to .lockfile/known_hosts") {
		t.Fatalf("output:\n%s", w.out.String())
	}
	if fi, err := os.Stat(filepath.Join(w.root, ".lockfile", "known_hosts")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("copy: %v %v", fi, err)
	}
	if w.fake.log[0] != "lockfile profile add" {
		t.Fatalf("log = %q", w.fake.log)
	}
}

// A decline puts .lockfile/known_hosts back as it was: absent, its
// directory too; or the earlier file, byte for byte.
func TestApplyDeclinedRestoresKnownHosts(t *testing.T) {
	for _, before := range []string{"", "old host keys\n"} {
		w := newFileWorld(t)
		dst := filepath.Join(w.root, ".lockfile", "known_hosts")
		if before != "" {
			writeTestFile(t, dst, before)
		}
		kh := filepath.Join(t.TempDir(), "kh")
		writeTestFile(t, kh, "new host keys\n")
		w.steps.Up = func(context.Context, string) error { return family.ErrNotConfirmed }
		l, a := lockfileSFTP(t, kh)
		if err := w.steps.Apply(context.Background(), l, a); !errors.Is(err, ErrNothingKept) {
			t.Fatalf("err = %v", err)
		}
		want := before
		if want == "" {
			want = "<absent>"
			if _, err := os.Stat(filepath.Dir(dst)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf(".lockfile left behind: %v", err)
			}
		}
		if got := readOr(t, dst); got != want {
			t.Fatalf("known_hosts = %q, want %q", got, want)
		}
	}
}

// A known hosts file already at .lockfile/known_hosts is not copied onto
// itself; one that is not a regular file stops lox add before profile add.
func TestApplyKnownHostsInPlaceOrRefused(t *testing.T) {
	w := newFileWorld(t)
	dst := filepath.Join(w.root, ".lockfile", "known_hosts")
	writeTestFile(t, dst, "keys\n")
	l, a := lockfileSFTP(t, dst)
	if err := w.steps.Apply(context.Background(), l, a); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.out.String(), "copied") || readOr(t, dst) != "keys\n" {
		t.Fatalf("copied onto itself:\n%s", w.out.String())
	}

	w = newFileWorld(t)
	l, a = lockfileSFTP(t, t.TempDir())
	if err := w.steps.Apply(context.Background(), l, a); !errors.Is(err, ErrNothingKept) {
		t.Fatalf("err = %v", err)
	}
	if len(w.fake.log) != 0 || !strings.Contains(w.out.String(), "copy failed: ") {
		t.Fatalf("log %q, output:\n%s", w.fake.log, w.out.String())
	}
}
