package family

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		if ne := needs(t, err, f2, out); !strings.Contains(ne.Why, "lock crm-prod routed only to tty") {
			t.Errorf("why: %s", ne.Why)
		}
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
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		needs(t, err, f2, out)
	})
	t.Run("an image not verified at enrolment", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		other := "ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("9", 64)
		os.WriteFile(w.file, []byte(strings.Replace(yamlConf(""), sqlImg, other, 1)), 0o644)
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		if ne := needs(t, err, f2, out); !strings.Contains(ne.Why, other) {
			t.Errorf("why: %s", ne.Why)
		}
		if f2.ran("cosign") {
			t.Error("cosign ran: an unattended start verifies nothing online")
		}
	})
	t.Run("applied again by a human, not enrolled again", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		e := w.enrol(t, f)
		os.WriteFile(w.file, []byte(yamlConf("  routing:\n    crm-prod: [tty]\n")), 0o644)
		if out, err := w.up("y\n", &fake{keys: f.keys}); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		f2 := &fake{keys: f.keys}
		out, _, err := w.upLive(f2, func(u *Up) { u.Enrolled = e })
		if ne := needs(t, err, f2, out); !strings.Contains(ne.Why, "enrol") {
			t.Errorf("why: %s", ne.Why)
		}
	})
	t.Run("nothing applied yet", func(t *testing.T) {
		w := newWS(t, yamlConf(""))
		f := newFake()
		out, _, err := w.upLive(f, func(u *Up) { u.Enrolled = &Enrolment{Version: 1, Fingerprint: "sha256:x"} })
		needs(t, err, f, out)
		if len(f.calls) != 0 {
			t.Errorf("commands ran in a workspace never applied: %v", f.calls)
		}
	})
}
