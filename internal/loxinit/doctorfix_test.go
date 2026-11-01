package loxinit

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// versionRunner answers `<lock> version` with stdout and code per lock,
// and records every call.
type versionRunner struct {
	calls   []string
	version map[string]string
	code    map[string]int
}

func (f *versionRunner) Verb(_ context.Context, _, name string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if len(args) == 1 && args[0] == "version" {
		out := f.version[name]
		if out == "" && f.code[name] != 0 {
			return nil, []byte(name + ": docker is required\n"), f.code[name], nil
		}
		return []byte(out), nil, f.code[name], nil
	}
	return nil, nil, 0, nil
}

// doctor --fix runs only with a launcher and an image at or after the
// release whose --fix leaves the lock's directory as lox up reads it;
// older (or unknown), the advisory doctor and a note saying why. A
// launcher from a clone ("dev") is judged by its image. The versions are
// asked once per lock type.
func TestDoctorArgsNeedsFixedLauncher(t *testing.T) {
	for _, c := range []struct {
		name     string
		version  string // locksql version's stdout
		code     int
		fix      bool
		wantNote string
	}{
		{"fixed release", "locksql launcher 0.13.1 (image x)\nlocksql v0.13.1\n", 0, true, ""},
		{"later release", "locksql launcher 0.14.0 (image x)\nlocksql v0.14.0\n", 0, true, ""},
		{"clone, fixed image", "locksql launcher dev (image x)\nlocksql v0.13.1\n", 0, true, ""},
		{"older release", "locksql launcher 0.13.0 (image x)\nlocksql v0.13.0\n", 0, false, "launcher 0.13.0 is older than v0.13.1"},
		{"clone, older image", "locksql launcher dev (image x)\nlocksql v0.13.0\n", 0, false, "image v0.13.0 is older than v0.13.1"},
		{"pre-release image", "locksql launcher 0.13.1 (image x)\nlocksql v0.13.1-rc1\n", 0, false, "image v0.13.1-rc1 is older than v0.13.1"},
		{"image does not answer", "locksql launcher 0.13.1 (image x)\n", 1, false, "image of unknown version is older than v0.13.1"},
		{"no version at all", "", 2, false, "locksql version did not say its versions"},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := &versionRunner{version: map[string]string{"locksql": c.version}, code: map[string]int{"locksql": c.code}}
			cache := map[string]LauncherVersions{}
			want := []string{"doctor", "--json"}
			note := ""
			if c.fix {
				want = []string{"doctor", "--fix", "--yes", "--json"}
			} else {
				note = "lox add runs locksql doctor without --fix: " + c.wantNote + ", whose doctor --fix gives .locksql/ to the console account (lox up then refuses it); update locksql to v0.13.1 or later, then run locksql doctor --fix"
			}
			for range 2 {
				args, got := DoctorArgs(context.Background(), run, "/project", "locksql", cache)
				if !slices.Equal(args, want) || got != note {
					t.Errorf("args %q note %q, want %q %q", args, got, want, note)
				}
			}
			if len(run.calls) != 1 || run.calls[0] != "locksql version" {
				t.Errorf("calls %q, want locksql version once", run.calls)
			}
		})
	}
}

// lockmq's fixed release is v0.6.1: v0.6.0 gets the advisory doctor.
// lockhttp's --fix needs no version; lockfile's doctor never runs with
// --fix (its only repair wires every installed agent for the account).
func TestDoctorArgsPerLock(t *testing.T) {
	run := &versionRunner{version: map[string]string{"lockmq": "lockmq launcher 0.6.0 (image x)\nlockmq v0.6.0\n"}}
	args, note := DoctorArgs(context.Background(), run, "/project", "lockmq", nil)
	if !slices.Equal(args, []string{"doctor", "--json"}) || !strings.HasPrefix(note, "lox add runs lockmq doctor without --fix: launcher 0.6.0 is older than v0.6.1") {
		t.Errorf("lockmq: %q %q", args, note)
	}
	for lock, want := range map[string][]string{
		"lockhttp": {"doctor", "--fix", "--yes", "--json"},
		"lockfile": {"doctor", "--json"},
	} {
		run.calls = nil
		args, note := DoctorArgs(context.Background(), run, "/project", lock, nil)
		if !slices.Equal(args, want) || note != "" || len(run.calls) != 0 {
			t.Errorf("%s: %q %q, calls %q", lock, args, note, run.calls)
		}
	}
}

func TestAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		want   bool
	}{
		{"0.13.1", "0.13.1", true}, {"v0.13.1", "0.13.1", true}, {"0.13.10", "0.13.1", true},
		{"1.0.0", "0.13.1", true}, {"0.14.0", "0.13.1", true},
		{"0.13.0", "0.13.1", false}, {"0.12.9", "0.13.1", false}, {"v0.13.1-rc1", "0.13.1", false},
		{"dev", "0.13.1", false}, {"", "0.13.1", false}, {"0.13", "0.13.1", false},
	} {
		if got := atLeast(c.v, c.min); got != c.want {
			t.Errorf("atLeast(%q, %q) = %v", c.v, c.min, got)
		}
	}
}

func TestParseVersions(t *testing.T) {
	got := parseVersions("lockmq", []byte("lockmq launcher dev (image ghcr.io/davidgodefroid/lockmq:0.6.1)\nlockmq v0.6.1\n"))
	if got != (LauncherVersions{Launcher: "dev", Image: "v0.6.1"}) {
		t.Errorf("%+v", got)
	}
	if got := parseVersions("locksql", []byte("lockmq launcher 0.6.1 (image x)\nlockmq v0.6.1\n")); got != (LauncherVersions{}) {
		t.Errorf("another lock's lines read: %+v", got)
	}
}
