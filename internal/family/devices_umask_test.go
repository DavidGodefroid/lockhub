//go:build unix

package family

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

// The locks' console accounts read the devices snapshot through a bind
// mount of the file (the 0700 state directory is not on their path): it
// is 0644 even under the human's umask 077, or no lock could start.
func TestDevicesSnapshotReadableUnderStrictUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	w := newWS(t, mobileYAML())
	state := filepath.Join(w.dir, "state")
	a := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	if err := PinDevice(state, a.Device()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	snaps, _ := filepath.Glob(filepath.Join(state, "devices-*.json"))
	if len(snaps) != 1 {
		t.Fatalf("snapshots %v", snaps)
	}
	fi, err := os.Stat(snaps[0])
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode().Perm(); m != 0o644 {
		t.Fatalf("snapshot mode %v, want 0644", m)
	}
}
