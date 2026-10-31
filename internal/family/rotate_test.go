package family

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hubImg2 = "ghcr.io/davidgodefroid/lockhub@sha256:5555555555555555555555555555555555555555555555555555555555555555"

// upWith runs lox up with --pin and --rotate.
func upWith(w ws, input string, f *fake, pin string, rotate ...string) (string, error) {
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: f,
		In: bufio.NewReader(strings.NewReader(input)), Out: &out, Pin: pin, Rotate: rotate}
	err := u.Do(context.Background())
	return out.String(), err
}

func (f *fake) index(s string) int {
	for i, c := range f.calls {
		if strings.Contains(c, s) {
			return i
		}
	}
	return -1
}

func TestPinRestoresHubImage(t *testing.T) {
	w := newWS(t, "# my workspace\n"+yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(w.dir, "state")
	// Declined: nothing changes, the file neither.
	f2 := &fake{keys: f.keys}
	out, err := upWith(w, "n\n", f2, strings.TrimPrefix(hubImg2, "ghcr.io/davidgodefroid/lockhub@"))
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "- hub image "+hubImg) || !strings.Contains(out, "+ hub image "+hubImg2) {
		t.Fatalf("pin review: %v\n%s", err, out)
	}
	if !strings.Contains(out, "never ran in this workspace") {
		t.Errorf("no note on a digest never run here:\n%s", out)
	}
	if !f2.ran("cosign verify") || !f2.ran(hubImg2) {
		t.Errorf("pinned image not verified: %v", f2.calls)
	}
	if b, _ := os.ReadFile(w.file); strings.Contains(string(b), hubImg2) {
		t.Error("declined pin written")
	}
	// Applied: the hub runs it, lockfamily.yaml says so (its comment kept),
	// the history has both.
	f3 := &fake{keys: f.keys}
	if out, err := upWith(w, "y\n", f3, hubImg2); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(f3.upCompose, `image: "`+hubImg2+`"`) {
		t.Errorf("hub not on the pinned image:\n%s", f3.upCompose)
	}
	b, _ := os.ReadFile(w.file)
	if !strings.Contains(string(b), "image: "+hubImg2) || strings.Contains(string(b), hubImg) || !strings.Contains(string(b), "# my workspace") {
		t.Errorf("lockfamily.yaml after pin:\n%s", b)
	}
	if h := hubImages(state); len(h) != 2 || h[0] != hubImg || h[1] != hubImg2 {
		t.Errorf("history %v", h)
	}
	// Back to the first: known, so no note; then unchanged.
	f4 := &fake{keys: f.keys}
	out, err = upWith(w, "y\n", f4, hubImg)
	if err != nil || strings.Contains(out, "never ran") {
		t.Errorf("pin back: %v\n%s", err, out)
	}
	out, err = upWith(w, "", &fake{keys: f.keys}, hubImg)
	if err != nil || !strings.Contains(out, "is the hub image already") || !strings.Contains(out, "unchanged") {
		t.Errorf("same pin: %v\n%s", err, out)
	}
	for _, bad := range []string{"sha256:abc", "ghcr.io/davidgodefroid/locksql@sha256:" + strings.Repeat("1", 64), "latest"} {
		if _, err := upWith(w, "y\n", &fake{keys: f.keys}, bad); err == nil || !strings.Contains(err.Error(), "--pin") {
			t.Errorf("pin %q: %v", bad, err)
		}
	}
}

func TestRotateHubAndLock(t *testing.T) {
	conf := yamlConf("") + "  web:\n    type: lockhttp\n    image: " + httpImg + "\n"
	w := newWS(t, conf)
	f := newFake()
	f.keys["web"] = pubKey()
	state := filepath.Join(w.dir, "state")
	if _, err := upWith(w, "y\n", f, "", "hub"); err == nil || !strings.Contains(err.Error(), "first lox up") {
		t.Fatalf("rotation before the first lox up: %v", err)
	}
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	old := map[string]string{}
	for k, v := range f.keys {
		old[k] = v
	}
	f.keys["hub/new"], f.keys["crm-prod/new"], f.keys["web/new"] = pubKey(), pubKey(), pubKey()
	if _, err := upWith(w, "y\n", f, "", "nope"); err == nil || !strings.Contains(err.Error(), "not hub, all, or a lock") {
		t.Errorf("unknown name: %v", err)
	}

	// Declined: every new key is dropped, nothing stops.
	f2 := &fake{keys: f.keys}
	out, err := upWith(w, "n\n", f2, "", "hub,crm-prod", "web")
	if !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"- hub key " + old["hub"], "+ hub key " + f.keys["hub/new"], "- lock crm-prod key " + old["crm-prod"],
		"+ lock crm-prod key " + f.keys["crm-prod/new"], "+ lock web key " + f.keys["web/new"], "--rotate: new keys for the hub, crm-prod, web"} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	if !f2.ran("HOME=/home/locksql/"+rotateDir+" lock-crm-prod hub-key --instance crm-prod") || !f2.ran("gatekey-web hub-key --instance web --home /g/"+rotateDir) {
		t.Errorf("new lock keys not made in the locks' volumes: %v", f2.calls)
	}
	if f2.ran("rotate-key") || f2.ran("swap") || f2.ran("stop lockhub") || f2.ran("up -d") {
		t.Errorf("declined rotation applied: %v", f2.calls)
	}
	if !f2.ran("rotkey-crm-prod clear") || !f2.ran("rotkey-web clear") {
		t.Errorf("new lock keys not dropped: %v", f2.calls)
	}
	if _, err := os.Stat(filepath.Join(state, "hub", "rotate")); !os.IsNotExist(err) {
		t.Errorf("staged hub key kept: %v", err)
	}
	// The rotkey services, for the rotated locks only, as the key's owner.
	stdin := string(f2.stdins[f2.calls[f2.index("rotkey-crm-prod clear")]])
	for _, want := range []string{`"rotkey-crm-prod":`, `user: "10001:10000"`, `"crm-prod-home:/home/locksql"`, `"rotkey-web":`, `"web-gate:/g"`, `user: "10003:10020"`} {
		if !strings.Contains(stdin, want) {
			t.Errorf("compose lacks %q", want)
		}
	}
	if strings.Contains(stdin, `"rotkey-events":`) {
		t.Error("rotkey for a lock not rotated")
	}

	// Applied: the hub stops, takes its key, the locks swap theirs, and
	// every console restarts.
	f3 := &fake{keys: f.keys}
	out, err = upWith(w, "y\n", f3, "", "hub", "crm-prod")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	stop, rk, swap, hk, up, re := f3.index("stop lockhub"), f3.index("lockhub rotate-key --data /var/lib/lockhub --new /var/lib/lockhub/rotate/hub.key"),
		f3.index("rotkey-crm-prod swap"), f3.index("--no-deps hubkey "+f.keys["hub/new"]), f3.index("up -d --remove-orphans"), f3.index("--force-recreate")
	if stop < 0 || rk < stop || swap < rk || hk < swap || up < hk || re < up {
		t.Errorf("apply order: stop %d rotate %d swap %d hubkey %d up %d recreate %d\n%v", stop, rk, swap, hk, up, re, f3.calls)
	}
	if c := f3.calls[re]; !strings.Contains(c, "lock-crm-prod") || !strings.Contains(c, "lock-events") || strings.Contains(c, "lock-web") {
		t.Errorf("recreated: %s", c)
	}
	if f3.ran("rotkey-web") {
		t.Errorf("unexpected: %v", f3.calls)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "hub.pub")); strings.TrimSpace(string(b)) != f.keys["hub/new"] {
		t.Errorf("hub.pub %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(state, HubKeysFile)); string(b) != old["hub"]+"\n"+f.keys["hub/new"]+"\n" {
		t.Errorf("hub-keys.pub %q", b)
	}
	lj, _ := os.ReadFile(filepath.Join(state, "hub", "locks.json"))
	if !strings.Contains(string(lj), f.keys["crm-prod/new"]) || strings.Contains(string(lj), old["crm-prod"]) {
		t.Errorf("locks.json %s", lj)
	}
	st, _ := os.ReadFile(filepath.Join(w.dir, "projects", Dir, UpFile))
	if !strings.Contains(string(st), f.keys["hub/new"]) {
		t.Errorf("up.json keeps the old hub key: %s", st)
	}
	for _, want := range []string{"hub key rotated: lox audit verify takes --hub-key-file", "lea's gate for web"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(state, "hub", "rotate")); !os.IsNotExist(err) {
		t.Errorf("stage left: %v", err)
	}
}

func TestRotateHubFailureFinishesLater(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(w.dir, "state")
	stage := filepath.Join(state, "hub", "rotate")
	oldHub := f.keys["hub"]
	f.keys["hub/new"] = pubKey()
	f2 := &fake{keys: f.keys, failing: "rotate-key"}
	out, err := upWith(w, "y\n", f2, "", "hub")
	if err == nil || !strings.Contains(err.Error(), "run lox up --rotate hub again") || f2.ran("up -d") {
		t.Fatalf("failed rotation: %v %v\n%s", err, f2.calls, out)
	}
	os.WriteFile(filepath.Join(stage, "hub.key"), []byte("staged"), 0o600) // keygen's file, which the fake does not make
	// Until finished, lox up refuses to start the hub on a half-rotated
	// key.
	if _, err := w.up("y\n", &fake{keys: f.keys}); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("plain lox up after a failed rotation: %v", err)
	}
	// Again: the same staged key, no new one.
	f.keys["hub/other"] = pubKey()
	f3 := &fake{keys: f.keys}
	out, err = upWith(w, "y\n", f3, "", "hub")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f3.ran("keygen --data /var/lib/lockhub/rotate") || !f3.ran("rotate-key") || !strings.Contains(out, "+ hub key "+f.keys["hub/new"]) {
		t.Errorf("retry: %v\n%s", f3.calls, out)
	}
	if b, _ := os.ReadFile(filepath.Join(state, HubKeysFile)); string(b) != oldHub+"\n"+f.keys["hub/new"]+"\n" {
		t.Errorf("hub-keys.pub %q", b)
	}
	if _, err := w.up("", &fake{keys: map[string]string{"hub": f.keys["hub/new"], "crm-prod": f.keys["crm-prod"], "events": f.keys["events"]}}); err != nil {
		t.Errorf("after the rotation: %v", err)
	}
}

func TestRotateLockGivingSameKeyRefused(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	f.keys["events/new"] = f.keys["events"]
	if _, err := upWith(w, "y\n", &fake{keys: f.keys}, "", "events"); err == nil || !strings.Contains(err.Error(), "its current key") {
		t.Errorf("same key: %v", err)
	}
}

func TestParseRotate(t *testing.T) {
	c := &Config{Locks: map[string]Lock{"a": {}, "b": {}}}
	r, err := parseRotate(c, []string{"all"})
	if err != nil || !r.hub || strings.Join(r.locks, ",") != "a,b" {
		t.Errorf("all: %+v %v", r, err)
	}
	r, err = parseRotate(c, []string{"b, a", "b"})
	if err != nil || r.hub || strings.Join(r.locks, ",") != "a,b" {
		t.Errorf("list: %+v %v", r, err)
	}
	c.Locks["hub"] = Lock{}
	if _, err := parseRotate(c, []string{"hub"}); err == nil {
		t.Error("ambiguous hub accepted")
	}
}

// A rotation whose hub took the key before lox up stopped: finished
// once the hub says it holds the staged key, refused otherwise.
func TestRotateHubResumeAsksTheHub(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(w.dir, "state")
	f.keys["hub/new"] = pubKey()
	if _, err := upWith(w, "y\n", &fake{keys: f.keys, failing: "rotate-key"}, "", "hub"); err == nil {
		t.Fatal("rotation did not fail")
	}
	// The hub's rename happened (no staged key left), lox up did not see it.
	f.keys["hub/held"] = pubKey()
	f2 := &fake{keys: f.keys}
	if _, err := upWith(w, "y\n", f2, "", "hub"); err == nil || !strings.Contains(err.Error(), "not the staged key") || f2.ran("up -d") {
		t.Errorf("hub holding another key: %v", err)
	}
	f.keys["hub/held"] = f.keys["hub/new"]
	f3 := &fake{keys: f.keys}
	out, err := upWith(w, "y\n", f3, "", "hub")
	if err != nil || f3.ran("rotate-key") || f3.ran("stop lockhub") {
		t.Fatalf("resume: %v %v\n%s", err, f3.calls, out)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "hub.pub")); strings.TrimSpace(string(b)) != f.keys["hub/new"] {
		t.Errorf("hub.pub %s", b)
	}
}

// A hub image without rotate-key is found out before anything stops; a
// pin to such an image is refused once the hub key was rotated.
func TestRotateNeedsRotateKeyImage(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	f.keys["hub/new"] = pubKey()
	f.keys["nohelp"] = "1"
	f2 := &fake{keys: f.keys}
	if _, err := upWith(w, "y\n", f2, "", "hub"); err == nil || !strings.Contains(err.Error(), "no lockhub rotate-key") || f2.ran("keygen") || f2.ran("stop") {
		t.Errorf("old image: %v %v", err, f2.calls)
	}
	// Pinning is fine before any rotation.
	if _, err := upWith(w, "y\n", &fake{keys: f.keys}, hubImg2); err != nil {
		t.Errorf("pin before a rotation: %v", err)
	}
	delete(f.keys, "nohelp")
	if _, err := upWith(w, "y\n", &fake{keys: f.keys}, "", "hub"); err != nil {
		t.Fatal(err)
	}
	f.keys["hub"] = f.keys["hub/new"]
	f.keys["nohelp"] = "1"
	if _, err := upWith(w, "y\n", &fake{keys: f.keys}, hubImg); err == nil || !strings.Contains(err.Error(), "predates hub key rotation") {
		t.Errorf("pin to an old image after a rotation: %v", err)
	}
}
