package family

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/servelock"
)

// upLive is one Up of w with mod applied, its input closed (nobody
// answers), on runner f.
func (w ws) upLive(f *fake, mod func(*Up)) (string, *Up, error) {
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: f, Out: &out,
		RuntimeGIDs: func() []int { return nil }}
	if mod != nil {
		mod(u)
	}
	err := u.Do(context.Background())
	return out.String(), u, err
}

// enrol applies w as a human (y) and enrols what is applied, as lox live
// enrol does: a probe that verifies every image, then the record.
func (w ws) enrol(t *testing.T, f *fake) *Enrolment {
	t.Helper()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_, u, err := w.upLive(&fake{keys: f.keys}, func(u *Up) { u.Probe = true })
	if err != nil || !u.Same || u.Reviewed == nil {
		t.Fatalf("probe: same %v reviewed %v err %v", u.Same, u.Reviewed, err)
	}
	e := NewEnrolment(u.Reviewed, "david", time.Unix(1_800_000_000, 0))
	if err := WriteEnrolment(filepath.Join(w.dir, "state"), e); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnrolment(filepath.Join(w.dir, "state"))
	if err != nil || got == nil {
		t.Fatalf("read back: %v %v", got, err)
	}
	return got
}

// The enrolment records the fingerprint the review uses, every pinned
// image cosign verified, and the production profiles; 0600, the user's.
func TestEnrolmentRecord(t *testing.T) {
	w := newWS(t, yamlConf(""))
	os.WriteFile(filepath.Join(w.dir, "projects", ".locksql", "config.toml"), []byte("[profiles.prod]\nengine = \"postgres\"\nhost = \"db.internal\"\nproduction = true\ncredentials = \"vault\"\nvault_path = \"secret/data/crm\"\n"), 0o644)
	f := newFake()
	e := w.enrol(t, f)
	st := filepath.Join(w.dir, "state")
	ab, _ := os.ReadFile(filepath.Join(st, "applied.json"))
	if e.Fingerprint == "" || !strings.Contains(string(ab), e.Fingerprint) {
		t.Errorf("fingerprint %q is not the applied one", e.Fingerprint)
	}
	for _, img := range []string{hubImg, sqlImg, mqImg} {
		if _, ok := e.Images[img]; !ok {
			t.Errorf("image %s not recorded as verified: %v", img, e.Images)
		}
	}
	if !strings.HasPrefix(e.Inputs, "sha256:") {
		t.Errorf("no digest of the files: %+v", e)
	}
	if len(e.Images) != 3 || e.Production["crm-prod"] != "prod" || len(e.Production) != 1 || e.By != "david" {
		t.Errorf("enrolment %+v", e)
	}
	fi, err := os.Stat(filepath.Join(st, EnrolmentFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("enrolment file: %v %v", fi, err)
	}
	// One that group or others can read or write is refused, not trusted.
	os.Chmod(filepath.Join(st, EnrolmentFile), 0o664)
	if _, err := ReadEnrolment(st); err == nil {
		t.Error("an enrolment others can write was read")
	}
	// None: nil, no error.
	os.Remove(filepath.Join(st, EnrolmentFile))
	if e, err := ReadEnrolment(st); e != nil || err != nil {
		t.Errorf("no enrolment: %v %v", e, err)
	}
}

// lox live's start: with the enrolled configuration, the stack comes up
// with no question, no cosign call and no upgrade, and the runtime
// directory is made again.
func TestUpEnrolledStartsWithoutAHuman(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	e := w.enrol(t, f)
	// A reboot: the runtime directory (a tmpfs) is gone.
	os.RemoveAll(filepath.Join(w.dir, "run", "lockhub"))
	f2 := &fake{keys: f.keys}
	out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !f2.ran("up -d --remove-orphans") || !f2.ran("--force-recreate lockhub") {
		t.Errorf("the stack was not started on the new runtime directory: %v", f2.calls)
	}
	if f2.ran("cosign") {
		t.Errorf("cosign ran for images verified at enrolment: %v", f2.calls)
	}
	if strings.Contains(out, "Apply?") || !strings.Contains(out, "enrolled") {
		t.Errorf("output:\n%s", out)
	}
	if fi, err := os.Stat(filepath.Join(w.dir, "run", "lockhub")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("runtime directory: %v %v", fi, err)
	}
	// The configuration it validated and started is its answer: lox live
	// serves that, never the workspace's file read again.
	_, u2, err := w.upLive(&fake{keys: f.keys}, func(u *Up) { u.Enrolled = e })
	if err != nil || u2.Config == nil || len(u2.Config.Locks) != 2 || u2.Config.Locks["crm-prod"].Type != "locksql" {
		t.Errorf("config returned: %+v %v", u2.Config, err)
	}
	// A profile rules command that fails this time (the engine was busy)
	// changes nothing that was enrolled: the applied rules hold.
	f4 := &fake{keys: f.keys, failing: "--no-deps rules-"}
	if out, _, err := w.upLive(f4, func(u *Up) { u.Enrolled = e }); err != nil || !f4.ran("up -d --remove-orphans") {
		t.Errorf("a transient profile rules failure: %v\n%s", err, out)
	}
	// It takes no flag of a maintenance run.
	for name, mod := range map[string]func(*Up){
		"pin":     func(u *Up) { u.Pin = "sha256:" + strings.Repeat("9", 64) },
		"rotate":  func(u *Up) { u.Rotate = []string{"hub"} },
		"upgrade": func(u *Up) { u.Upgrade = &Upgrade{} },
	} {
		f3 := &fake{keys: f.keys}
		if _, _, err := w.upLive(f3, func(u *Up) { u.Enrolled = e; mod(u) }); err == nil || len(f3.calls) != 0 {
			t.Errorf("%s with an enrolment: err %v, calls %v", name, err, f3.calls)
		}
	}
}

// Anything that differs from the enrolment is not applied: nothing is
// started, stopped or asked, and the error says an enrolment is needed.
func TestUpEnrolledRefusesAChange(t *testing.T) {
	// snapshot lists everything under the runtime and state directories.
	snapshot := func(w ws) string {
		var b strings.Builder
		for _, d := range []string{"run", "state"} {
			filepath.Walk(filepath.Join(w.dir, d), func(p string, fi os.FileInfo, err error) error {
				if err == nil && filepath.Base(p) != "serve.lock" {
					fmt.Fprintf(&b, "%s %v %d\n", p, fi.Mode(), fi.Size())
				}
				return nil
			})
		}
		return b.String()
	}
	// early: the files differ from the enrolled ones, so not one command
	// ran and nothing was made.
	early := func(t *testing.T, w ws, before string, f *fake) {
		t.Helper()
		if len(f.calls) != 0 {
			t.Errorf("commands ran for a configuration that is not the enrolled one: %v", f.calls)
		}
		if after := snapshot(w); after != before {
			t.Errorf("something was made or changed:\nbefore:\n%s\nafter:\n%s", before, after)
		}
	}
	needs := func(t *testing.T, err error, f *fake, out string) *NeedsEnrolmentError {
		t.Helper()
		var ne *NeedsEnrolmentError
		if !errors.As(err, &ne) {
			t.Fatalf("err = %v, want a needs-enrolment error\n%s", err, out)
		}
		for _, bad := range []string{"up -d", "docker stop", "docker rm", "network rm", "keygen", " hubkey "} {
			if f.ran(bad) {
				t.Errorf("%q ran although nothing may be applied: %v", bad, f.calls)
			}
		}
		if strings.Contains(out, "Apply?") {
			t.Errorf("a review was asked:\n%s", out)
		}
		return ne
	}
	t.Run("the configuration changed", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		os.WriteFile(w.file, []byte(yamlConf("  routing:\n    crm-prod: [tty]\n")), 0o644)
		os.RemoveAll(filepath.Join(w.dir, "run")) // a reboot
		before := snapshot(w)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		if ne := needs(t, err, f2, out); !strings.Contains(ne.Why, "lockfamily.yaml") {
			t.Errorf("why: %s", ne.Why)
		}
		early(t, w, before, f2)
		ab, _ := os.ReadFile(filepath.Join(w.dir, "state", "applied.json"))
		if !strings.Contains(string(ab), e.Fingerprint) {
			t.Error("applied.json was rewritten")
		}
	})
	t.Run("a profile changed", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		os.WriteFile(filepath.Join(w.dir, "projects", ".locksql", "config.toml"), []byte("[profiles.prod]\nhost = \"other.internal\"\n"), 0o644)
		before := snapshot(w)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		needs(t, err, f2, out)
		early(t, w, before, f2)
	})
	t.Run("a device paired since", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		e2 := *e
		e2.Inputs = "sha256:" + strings.Repeat("0", 64) // as if the devices file had changed
		before := snapshot(w)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = &e2 })
		needs(t, err, f2, out)
		early(t, w, before, f2)
	})
	t.Run("an enrolment without the files' digest", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		e2 := *e
		e2.Inputs = ""
		before := snapshot(w)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = &e2 })
		needs(t, err, f2, out)
		early(t, w, before, f2)
	})
	// What only the engine tells (a lock's key in its volume) is compared
	// after it was read: nothing is applied, started or stopped then either.
	t.Run("a lock key that changed in its volume", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		f2 := &fake{keys: map[string]string{"hub": f.keys["hub"], "crm-prod": pubKey(), "events": f.keys["events"]}}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		if ne := needs(t, err, f2, out); !strings.Contains(ne.Why, "lock crm-prod key") {
			t.Errorf("why: %s", ne.Why)
		}
	})
	t.Run("an image not verified at enrolment", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		other := "ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("9", 64)
		os.WriteFile(w.file, []byte(strings.Replace(yamlConf(""), sqlImg, other, 1)), 0o644)
		// Even enrolled files: an image the enrolment did not verify.
		_, pu, _ := w.upLive(&fake{keys: f.keys}, func(u *Up) { u.Probe = true })
		e2 := *e
		if pu.Inputs == "" {
			t.Fatal("a probe did not digest the files")
		}
		e2.Inputs = pu.Inputs
		before := snapshot(w)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = &e2 })
		if ne := needs(t, err, f2, out); !strings.Contains(ne.Why, other) {
			t.Errorf("why: %s", ne.Why)
		}
		early(t, w, before, f2)
	})
	t.Run("applied again by a human, not enrolled again", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		os.WriteFile(w.file, []byte(yamlConf("  routing:\n    crm-prod: [tty]\n")), 0o644)
		if out, err := w.up("y\n", &fake{keys: f.keys}); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		before := snapshot(w)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		needs(t, err, f2, out)
		early(t, w, before, f2)
	})
	t.Run("nothing applied yet", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		before := snapshot(w)
		out, _, err := w.upLive(f, func(u *Up) { u.Enrolled = &Enrolment{Version: 1, Fingerprint: "sha256:x", Inputs: "sha256:y"} })
		needs(t, err, f, out)
		early(t, w, before, f)
	})
}

// Everything that applies takes the workspace's lock: nothing is applied
// under a serving lox live, which holds it alone.
func TestUpRefusedUnderLoxLive(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	release, err := servelock.Acquire(filepath.Join(w.dir, "state"), servelock.Live)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(w.file, []byte(yamlConf("  routing:\n    crm-prod: [tty]\n")), 0o644)
	f2 := &fake{keys: f.keys}
	out, err := w.up("y\n", f2)
	var he *servelock.HeldError
	if !errors.As(err, &he) || len(f2.calls) != 0 || strings.Contains(out, "Apply?") {
		t.Fatalf("an apply under lox live: %v, calls %v\n%s", err, f2.calls, out)
	}
	// A probe and a dry run apply nothing: allowed (lox live enrol, lox doctor).
	if _, u, err := w.upLive(&fake{keys: f.keys}, func(u *Up) { u.Probe = true }); err != nil || u.Same {
		t.Errorf("a probe under lox live: same %v err %v", u.Same, err)
	}
	release()
	if out, err := w.up("y\n", &fake{keys: f.keys}); err != nil {
		t.Fatalf("once lox live stopped: %v\n%s", err, out)
	}
}
