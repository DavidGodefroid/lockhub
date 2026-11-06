package family

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	hubImgNew = "ghcr.io/davidgodefroid/lockhub@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sqlImgNew = "ghcr.io/davidgodefroid/locksql@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sqlVault  = "ghcr.io/davidgodefroid/locksql@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// cosignOut is cosign verify's stdout for an image signed by repo's
// release workflow for tag.
func cosignOut(repo, tag string) []byte {
	b, _ := json.Marshal([]map[string]any{{
		"critical": map[string]any{"type": "cosign container image signature"},
		"optional": map[string]any{
			"Issuer":            "https://token.actions.githubusercontent.com",
			"Subject":           "https://github.com/DavidGodefroid/" + repo + "/.github/workflows/release.yml@refs/tags/" + tag,
			"githubWorkflowRef": "refs/tags/" + tag,
		},
	}})
	return b
}

// signed is the docker and cosign fake whose cosign verify answers like
// the real one: the image's signature by its release (signedFor), unless
// the image is unsigned (bad).
type signed struct {
	*fake
	signedFor map[string][2]string // ref → repo, tag
	bad       map[string]bool
}

func (s *signed) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	out, err := s.fake.Run(ctx, stdin, name, args...)
	if name != "cosign" || err != nil {
		return out, err
	}
	ref := args[len(args)-1]
	if s.bad[ref] {
		return nil, errors.New("no matching signatures")
	}
	sf, ok := s.signedFor[ref]
	if !ok {
		return []byte("[]"), nil
	}
	// The identity cosign is asked to check must accept the signer.
	id := args[len(args)-2]
	subject := "https://github.com/DavidGodefroid/" + sf[0] + "/.github/workflows/release.yml@refs/tags/" + sf[1]
	if ok, _ := regexp.MatchString(id, subject); !ok {
		return nil, errors.New("none of the expected identities matched: " + id)
	}
	return cosignOut(sf[0], sf[1]), nil
}

func newSigned(f *fake) *signed {
	return &signed{fake: f, signedFor: map[string][2]string{
		hubImg:    {"lockhub", "v0.7.0"},
		hubImgNew: {"lockhub", "v0.8.0"},
		sqlImg:    {"locksql", "v0.16.0"},
		sqlImgNew: {"locksql", "v0.16.2"},
		sqlVault:  {"locksql", "v0.16.2"},
		mqImg:     {"lockmq", "v0.7.0"},
	}, bad: map[string]bool{}}
}

// registry serves the registry token and the manifests' digests
// (ImageVariant's HEAD), by path under /v2/.
func registry(t *testing.T, manifests map[string]string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Write([]byte(`{"token":"t"}`))
			return
		}
		if d, ok := manifests[strings.TrimPrefix(r.URL.Path, "/v2/")]; ok && r.Method == http.MethodHead {
			w.Header().Set("Docker-Content-Digest", d)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func digestOf(ref string) string { return ref[strings.Index(ref, "@")+1:] }

// upgradeWS is a workspace applied once on the old images (hub v0.7.0,
// locksql v0.16.0, lockmq v0.7.0), and an Up for lox run with the
// upgrade through the real Releases, on a fake registry that serves the
// shipped releases (hub v0.8.0, locksql v0.16.2).
func upgradeWS(t *testing.T) (ws, *fake, func(input string, r Runner, review bool, pin string) (string, error)) {
	w := newWS(t, "# my workspace\n"+yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	srv := registry(t, map[string]string{
		"davidgodefroid/lockhub/manifests/0.8.0":        digestOf(hubImgNew),
		"davidgodefroid/locksql/manifests/0.16.2":       digestOf(sqlImgNew),
		"davidgodefroid/locksql/manifests/0.16.2-vault": digestOf(sqlVault),
	})
	run := func(input string, r Runner, review bool, pin string) (string, error) {
		rel := &Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: r}
		var out strings.Builder
		u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: r,
			In: bufio.NewReader(strings.NewReader(input)), Out: &out, Review: review, Pin: pin,
			Upgrade: &Upgrade{Pins: map[string]string{"lockhub": "v0.8.0", "locksql": "v0.16.2", "lockmq": "v0.7.0"}, Image: rel.ImageVariant}}
		err := u.Do(context.Background())
		return out.String(), err
	}
	return w, f, run
}

func TestUpgradeAtStart(t *testing.T) {
	w, f, run := upgradeWS(t)
	s := newSigned(&fake{keys: f.keys})
	// No answer typed: only the images changed, so nothing is asked.
	out, err := run("", s, false, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"hub image upgraded: lockhub v0.7.0 → v0.8.0 (signature verified)\n",
		"lock crm-prod: image upgraded: locksql v0.16.0 → v0.16.2 (signature verified)\n",
		"only the upgraded images changed since the last lox run: applied without a question\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Apply?") || strings.Contains(out, "lock events: image upgraded") {
		t.Errorf("asked, or upgraded a lock already on the shipped release:\n%s", out)
	}
	// Each new digest was verified by its own release's workflow run for
	// that very tag, before compose ran anything on it.
	up := s.index(" up -d")
	for _, c := range []struct{ ref, tag string }{{hubImgNew, `v0\.8\.0`}, {sqlImgNew, `v0\.16\.2`}} {
		i := s.index("refs/tags/" + c.tag + "$ " + c.ref)
		if i < 0 || i > up || s.index(c.ref) < i {
			t.Errorf("%s not verified for its tag before use: %v", c.ref, s.calls)
		}
	}
	// The containers are recreated on the new images.
	for _, want := range []string{`image: "` + hubImgNew + `"`, `image: "` + sqlImgNew + `"`, `image: "` + mqImg + `"`} {
		if !strings.Contains(s.upCompose, want) {
			t.Errorf("compose up without %s", want)
		}
	}
	if strings.Contains(s.upCompose, hubImg) || strings.Contains(s.upCompose, sqlImg) {
		t.Error("compose up still names an old image")
	}
	// lockfamily.yaml says what runs, its comment kept.
	b, _ := os.ReadFile(w.file)
	if got := string(b); !strings.Contains(got, "image: "+hubImgNew) || !strings.Contains(got, "image: "+sqlImgNew) || !strings.Contains(got, "image: "+mqImg) ||
		strings.Contains(got, hubImg) || strings.Contains(got, sqlImg) || !strings.Contains(got, "# my workspace") {
		t.Errorf("lockfamily.yaml after the upgrade:\n%s", got)
	}
	if h := hubImages(filepath.Join(w.dir, "state")); len(h) != 2 || h[1] != hubImgNew {
		t.Errorf("hub history %v", h)
	}
	// The next lox run finds nothing to upgrade.
	s2 := newSigned(&fake{keys: f.keys})
	out, err = run("", s2, false, "")
	if err != nil || strings.Contains(out, "upgraded") || !strings.Contains(out, "configuration unchanged since the last lox run") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}

func TestUpgradeFailsClosed(t *testing.T) {
	w, f, run := upgradeWS(t)
	before, _ := os.ReadFile(w.file)
	// The new locksql image's signature does not verify: it is never
	// used; the hub's does, and is upgraded alone.
	s := newSigned(&fake{keys: f.keys})
	s.bad[sqlImgNew] = true
	out, err := run("", s, false, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "lock crm-prod: image: not upgraded to locksql v0.16.2, keeping v0.16.0: image "+sqlImgNew+" (locksql v0.16.2) is not signed by its release") {
		t.Errorf("no reason given:\n%s", out)
	}
	if !strings.Contains(out, "hub image upgraded: lockhub v0.7.0 → v0.8.0") {
		t.Errorf("hub not upgraded:\n%s", out)
	}
	if strings.Contains(s.upCompose, sqlImgNew) || !strings.Contains(s.upCompose, `image: "`+sqlImg+`"`) {
		t.Errorf("the unverified image reached compose:\n%s", s.upCompose)
	}
	b, _ := os.ReadFile(w.file)
	if strings.Contains(string(b), sqlImgNew) || !strings.Contains(string(b), sqlImg) || !strings.Contains(string(b), hubImgNew) {
		t.Errorf("lockfamily.yaml:\n%s", b)
	}
	// Nothing verifies (the registry is unreachable, say): the old images
	// run, the file is as it was.
	w2, f2, run2 := upgradeWS(t)
	before, _ = os.ReadFile(w2.file)
	s2 := newSigned(&fake{keys: f2.keys})
	s2.bad[sqlImgNew], s2.bad[hubImgNew] = true, true
	out, err = run2("", s2, false, "")
	if err != nil || !strings.Contains(out, "configuration unchanged since the last lox run") || strings.Contains(out, " upgraded:") {
		t.Errorf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "hub image: not upgraded to lockhub v0.8.0, keeping v0.7.0") {
		t.Errorf("no reason for the hub:\n%s", out)
	}
	if after, _ := os.ReadFile(w2.file); string(after) != string(before) {
		t.Errorf("file changed:\n%s", after)
	}
}

func TestUpgradeWithOtherChangesIsReviewed(t *testing.T) {
	w, f, run := upgradeWS(t)
	// A change of lockfamily.yaml besides the upgrade: reviewed as always,
	// the image lines with it; declined, nothing is written back.
	b, _ := os.ReadFile(w.file)
	os.WriteFile(w.file, []byte(strings.Replace(string(b), "    type: lockmq\n", "    type: lockmq\n    profile: other\n", 1)), 0o644)
	before, _ := os.ReadFile(w.file)
	s := newSigned(&fake{keys: f.keys})
	out, err := run("n\n", s, false, "")
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "Apply? [y/N]") || !strings.Contains(out, "+ hub image "+hubImgNew) {
		t.Fatalf("%v\n%s", err, out)
	}
	if s.ran(" up -d") {
		t.Error("applied without the yes")
	}
	if after, _ := os.ReadFile(w.file); string(after) != string(before) {
		t.Errorf("declined upgrade written:\n%s", after)
	}
	// --review asks even for an upgrade alone.
	w2, f2, run2 := upgradeWS(t)
	_ = w2
	out, err = run2("n\n", newSigned(&fake{keys: f2.keys}), true, "")
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "- lock crm-prod image "+sqlImg) || !strings.Contains(out, "+ lock crm-prod image "+sqlImgNew) {
		t.Errorf("--review: %v\n%s", err, out)
	}
}

func TestUpgradeLeavesPinnedHub(t *testing.T) {
	w, f, run := upgradeWS(t)
	_ = w
	s := newSigned(&fake{keys: f.keys})
	s.signedFor[hubImg2] = [2]string{"lockhub", "v0.6.0"}
	out, err := run("y\n", s, false, hubImg2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "hub image upgraded") || !strings.Contains(s.upCompose, `image: "`+hubImg2+`"`) {
		t.Errorf("--pin upgraded:\n%s", out)
	}
	if !strings.Contains(out, "lock crm-prod: image upgraded") {
		t.Errorf("locks not upgraded with --pin:\n%s", out)
	}
}

func TestUpgradeChoices(t *testing.T) {
	conf := vaultConf("vault:\n  address: https://vault.example.com:8200\n", "    vault: true\n  plain:\n    type: locksql\n    image: "+sqlImg+"\n  newer:\n    type: lockmq\n    image: "+mqImg+"\n")
	path := filepath.Join(t.TempDir(), FileName)
	c, err := decode([]byte(conf), path)
	if err != nil {
		t.Fatal(err)
	}
	type call struct{ repo, tag, variant string }
	var calls []call
	u := &Upgrade{Pins: map[string]string{"locksql": "v0.16.2", "lockmq": "v0.6.0"}, Image: func(_ context.Context, repo, tag, variant string) (string, error) {
		calls = append(calls, call{repo, tag, variant})
		if variant == "vault" {
			return sqlVault, nil
		}
		return sqlImgNew, nil
	}}
	var out strings.Builder
	// The hub's signature names no release; lockmq runs a newer one.
	raw, ups, err := u.upgrade(context.Background(), &out, []byte(conf), c, map[string]string{sqlImg: "v0.16.0", mqImg: "v0.7.0"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != (call{"locksql", "v0.16.2", ""}) || calls[1] != (call{"locksql", "v0.16.2", "vault"}) {
		t.Errorf("resolutions %v", calls)
	}
	if len(ups) != 2 {
		t.Fatalf("upgrades %+v", ups)
	}
	c2, err := decode(raw, path)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Locks["shop"].Image != sqlVault || c2.Locks["plain"].Image != sqlImgNew || c2.Locks["newer"].Image != mqImg || c2.Hub.Image != hubImg {
		t.Errorf("images %+v", c2.Locks)
	}
	if !strings.Contains(out.String(), "lock shop: image upgraded: locksql v0.16.0 → v0.16.2 (vault image, signature verified)") {
		t.Errorf("vault line:\n%s", out.String())
	}
	if strings.Contains(out.String(), "hub image upgraded") || strings.Contains(out.String(), "lock newer") {
		t.Errorf("upgraded what it must not:\n%s", out.String())
	}
	// No pin for lockhub here: the hub is not compared at all.
	if strings.Contains(out.String(), "hub image") {
		t.Errorf("hub compared without a pin:\n%s", out.String())
	}
	out.Reset()
	u.Pins["lockhub"] = "v0.8.0"
	if _, ups, _ := u.upgrade(context.Background(), &out, []byte(conf), c, map[string]string{}, false); len(ups) != 0 ||
		!strings.Contains(out.String(), "hub image: not upgraded: its signature names no lockhub release, so it cannot be compared with v0.8.0") {
		t.Errorf("unknown release: %v\n%s", ups, out.String())
	}
	// A registry answer that is not a digest is not used.
	u.Image = func(context.Context, string, string, string) (string, error) {
		return "ghcr.io/davidgodefroid/locksql:0.16.2", nil
	}
	out.Reset()
	if _, ups, _ := u.upgrade(context.Background(), &out, []byte(conf), c, map[string]string{sqlImg: "v0.16.0"}, true); len(ups) != 0 || !strings.Contains(out.String(), "not an image by digest") {
		t.Errorf("tag accepted: %v\n%s", ups, out.String())
	}
}

func TestSignedTag(t *testing.T) {
	two := `[{"optional":{"Subject":"https://github.com/DavidGodefroid/locksql/.github/workflows/release.yml@refs/tags/v0.16.0"}},` +
		`{"optional":{"Subject":"https://github.com/DavidGodefroid/locksql/.github/workflows/release.yml@refs/tags/v0.16.1"}}]`
	for _, c := range []struct {
		out, repo, want string
	}{
		{string(cosignOut("locksql", "v0.16.0")), "locksql", "v0.16.0"},
		{string(cosignOut("locksql", "v1.0.0-rc.1")), "locksql", "v1.0.0-rc.1"},
		{string(cosignOut("lockmq", "v0.16.0")), "locksql", ""}, // another repository's signer
		{string(cosignOut("locksql", "main")), "locksql", ""},   // not a release tag
		{strings.Replace(string(cosignOut("locksql", "v0.16.0")), "release.yml", "other.yml", 1), "locksql", ""},
		{two, "locksql", ""}, // two releases: unknown
		{"", "locksql", ""},
		{"Verification for ghcr.io/x -- ok", "locksql", ""},
	} {
		if got := signedTag([]byte(c.out), c.repo); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.out, c.repo, got, c.want)
		}
	}
}

func TestSetLockImage(t *testing.T) {
	conf := "# top\n" + yamlConf("")
	out, err := setLockImage([]byte(conf), "events", "ghcr.io/davidgodefroid/lockmq@sha256:"+strings.Repeat("9", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# top") || !strings.Contains(string(out), "lockmq@sha256:"+strings.Repeat("9", 64)) || strings.Contains(string(out), mqImg) ||
		!strings.Contains(string(out), sqlImg) {
		t.Errorf("%s", out)
	}
	if _, err := setLockImage([]byte(conf), "nope", mqImg); err == nil {
		t.Error("an unknown lock was set")
	}
	// The result is validated: a lock's image of another repository is refused.
	if _, err := setLockImage([]byte(conf), "events", sqlImg); err == nil {
		t.Error("a locksql image was pinned for a lockmq lock")
	}
}

func TestShippedPins(t *testing.T) {
	p := ShippedPins("0.9.0")
	if p["lockhub"] != "v0.9.0" || p["locksql"] != ShippedLocks["locksql"] {
		t.Errorf("%v", p)
	}
	if _, ok := ShippedPins("dev")["lockhub"]; ok {
		t.Error("a dev build pins a hub")
	}
	for repo, tag := range ShippedLocks {
		if _, ok := Kinds[repo]; !ok || !semverTag.MatchString(tag) || semverLess(tag, MinRelease[repo]) {
			t.Errorf("shipped %s %s", repo, tag)
		}
	}
	for _, typ := range Types {
		if _, ok := ShippedLocks[typ]; !ok {
			t.Errorf("no shipped release for %s", typ)
		}
	}
}

// An upgraded lockfile lock (#118) still runs under lockfile's shipped
// seccomp profile (#45): the upgrade's recreate keeps the security_opt and
// the lockfamily.seccomp label, and the unchanged profile line asks nothing.
func TestUpgradeKeepsLockfileSeccomp(t *testing.T) {
	const fileImgNew = "ghcr.io/davidgodefroid/lockfile@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	w := newWS(t, "version: 1\nhub:\n  image: "+hubImg+"\nlocks:\n  docs:\n    type: lockfile\n    image: "+fileImg+"\n")
	f := seccompFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	srv := registry(t, map[string]string{"davidgodefroid/lockfile/manifests/0.7.0": digestOf(fileImgNew)})
	s := newSigned(&fake{keys: f.keys})
	s.signedFor[fileImg] = [2]string{"lockfile", "v0.6.0"}
	s.signedFor[fileImgNew] = [2]string{"lockfile", "v0.7.0"}
	rel := &Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: s}
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: s,
		In: bufio.NewReader(strings.NewReader("")), Out: &out,
		Upgrade: &Upgrade{Pins: map[string]string{"lockfile": "v0.7.0"}, Image: rel.ImageVariant}}
	if err := u.Do(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{
		"lock docs: image upgraded: lockfile v0.6.0 → v0.7.0 (signature verified)\n",
		"only the upgraded images changed since the last lox run: applied without a question\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in:\n%s", want, out.String())
		}
	}
	svc := service(s.upCompose, "lock-docs")
	copyPath := filepath.Join(w.dir, "state", lockfileSeccompFile)
	for _, want := range []string{`image: "` + fileImgNew + `"`, `"seccomp=` + copyPath + `"`, "lockfamily.seccomp: " + q(LockfileSeccompSum)} {
		if !strings.Contains(svc, want) {
			t.Errorf("upgraded lock-docs without %s:\n%s", want, svc)
		}
	}
}
