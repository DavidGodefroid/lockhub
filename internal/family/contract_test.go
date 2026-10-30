package family

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const httpImg = "ghcr.io/davidgodefroid/lockhttp@sha256:4444444444444444444444444444444444444444444444444444444444444444"

// lock up tells lea, in .lockfamily/up.json, which volumes carry each
// lock's socket; the volumes are labelled so that lea can check them.
func TestUpWritesLeaContract(t *testing.T) {
	conf := yamlConf("") + "  web:\n    type: lockhttp\n    image: " + httpImg + "\n"
	w := newWS(t, conf)
	f := newFake()
	f.keys["web"] = pubKey()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Dir(filepath.Dir(w.file))
	b, err := os.ReadFile(filepath.Join(ws, Dir, UpFile))
	if err != nil {
		t.Fatal(err)
	}
	var s UpState
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	p := Project(ws)
	if s.Version != 1 || s.Project != p || s.Workspace != ws || s.HubNetwork != p+"_lockhub" || s.HubKey != f.keys["hub"] {
		t.Errorf("up.json: %+v", s)
	}
	if l := s.Locks["crm-prod"]; l.Type != "locksql" || l.Socket != p+"_crm-prod-run" || l.GID != "10000" || l.GateHome != "" {
		t.Errorf("crm-prod: %+v", l)
	}
	if l := s.Locks["web"]; l.Socket != p+"_web-run" || l.GateHome != p+"_web-gate" {
		t.Errorf("web: %+v", l)
	}
	for _, want := range []string{
		"  \"crm-prod-run\":\n    labels:\n      dev.lockfamily.role: \"socket\"\n      dev.lockfamily.instance: \"crm-prod\"\n      dev.lockfamily.type: \"locksql\"",
		"  \"crm-prod-home\": {}", // a lock's home has no role: lea never mounts it
		"  \"web-gate\":\n    labels:\n      dev.lockfamily.role: \"gate-home\"",
		"  lockhub:\n    internal: true\n    labels:\n      dev.lockfamily.role: \"hub\"",
	} {
		if !strings.Contains(f.upCompose, want) {
			t.Errorf("compose lacks %q", want)
		}
	}
	// lockhttp: the console serves the policy only; the gate's key is
	// made in the gate's own volume, as the gate's account.
	web := block(f.upCompose, "lock-web")
	if strings.Contains(web, "--hub") || strings.Contains(web, "lockhub,") || !strings.Contains(web, `user: "10021:10020"`) {
		t.Errorf("lockhttp console service:\n%s", web)
	}
	if !f.ran("--no-deps gatehome-web") || !f.ran("--no-deps gatekey-web") || f.ran("lock-web hub-key") {
		t.Errorf("gate key: %v", f.calls)
	}
	// The hub key reaches the locks' volume before they start.
	hk, up := -1, -1
	for i, c := range f.calls {
		if strings.Contains(c, "--no-deps hubkey "+f.keys["hub"]) {
			hk = i
		}
		if strings.Contains(c, " up -d") {
			up = i
		}
	}
	if hk < 0 || hk > up {
		t.Errorf("hubkey run %d, up %d: %v", hk, up, f.calls)
	}
}

func TestComposeNeverStartsSetupServices(t *testing.T) {
	c := &Config{Version: 1, Hub: Hub{Image: hubImg}, Locks: map[string]Lock{"web": {Type: "lockhttp", Image: httpImg}, "docs": {Type: "lockfile", Image: strings.Replace(httpImg, "lockhttp", "lockfile", 1)}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"})
	if strings.Contains(out, "type: bind\n        source: \"/w") {
		t.Error("a workspace directory is bind-mounted")
	}
	for _, svc := range []string{"hubkey", "gatehome-web", "gatekey-web", "profile-lockfile", "profile-lockhttp"} {
		blk := block(out, svc)
		if !strings.Contains(blk, "    image: ") {
			t.Fatalf("no service %s", svc)
		}
		if !strings.Contains(blk, "profiles: [setup]") || !strings.Contains(blk, "network_mode: none") {
			t.Errorf("%s:\n%s", svc, blk)
		}
	}
	// lockfile reads ~/.config/lockfile only: the workspace's .lockfile is
	// mounted there, and its console gets a profile.
	if !strings.Contains(out, `      - "profile-lockfile":/home/lockfile/.config/lockfile:ro`) || !strings.Contains(out, `"console", "--profile", "default", "--hub"`) {
		t.Errorf("lockfile service:\n%s", out)
	}
}

func TestLocateAndLegacy(t *testing.T) {
	ws := t.TempDir()
	if got := Locate(ws); got != filepath.Join(ws, Dir, FileName) || Legacy(got) || Workspace(got) != ws {
		t.Errorf("fresh: %s", got)
	}
	old := filepath.Join(ws, FileName)
	os.WriteFile(old, []byte("version: 1\n"), 0o644)
	if got := Locate(ws); got != old || !Legacy(got) || Workspace(got) != ws || !strings.Contains(LegacyWarning(got), "mv ") {
		t.Errorf("legacy: %s", got)
	}
	os.Mkdir(filepath.Join(ws, Dir), 0o755)
	os.WriteFile(filepath.Join(ws, Dir, FileName), []byte("version: 1\n"), 0o644)
	if got := Locate(ws); got != filepath.Join(ws, Dir, FileName) {
		t.Errorf("both: %s", got)
	}
	// The same workspace keeps its project (and state) when the file moves.
	if Project(Workspace(old)) != Project(Workspace(filepath.Join(ws, Dir, FileName))) {
		t.Error("moving lockfamily.yaml changes the project")
	}
	for _, sub := range []string{"a", "b"} {
		os.MkdirAll(filepath.Join(ws, sub, Dir), 0o755)
	}
	os.WriteFile(filepath.Join(ws, "a", Dir, FileName), nil, 0o644)
	os.WriteFile(filepath.Join(ws, "b", FileName), nil, 0o644)
	got := SubProjects(ws)
	if len(got) != 2 || got[0] != filepath.Join(ws, "a", Dir, FileName) || got[1] != filepath.Join(ws, "b", FileName) {
		t.Errorf("sub-projects: %v", got)
	}
}

func TestEnsureDirRefusesLink(t *testing.T) {
	ws := t.TempDir()
	os.Symlink(t.TempDir(), filepath.Join(ws, Dir))
	if err := Add(filepath.Join(ws, Dir, FileName), AddOptions{Type: "locksql", Name: "crm", Image: sqlImg, HubImage: hubImg}); err == nil {
		t.Error("lock add wrote through a .lockfamily link")
	}
}

type cosignFake struct{ calls []string }

func (c *cosignFake) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	c.calls = append(c.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

func TestReleasesLatestSignedDigest(t *testing.T) {
	const dg = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/DavidGodefroid/locksql/releases":
			auth = r.Header.Get("Authorization")
			w.Write([]byte(`[{"tag_name":"v0.9.0"},{"tag_name":"v0.10.0"},{"tag_name":"v0.11.0-rc.1","prerelease":true},{"tag_name":"v0.12.0","draft":true}]`))
		case r.URL.Path == "/repos/DavidGodefroid/lockhttp/releases":
			w.Write([]byte(`[{"tag_name":"v0.2.0","prerelease":true},{"tag_name":"v0.2.1","prerelease":true}]`))
		case r.URL.Path == "/repos/DavidGodefroid/lockmq/releases":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/token":
			w.Write([]byte(`{"token":"t"}`))
		case r.URL.Path == "/v2/davidgodefroid/locksql/manifests/0.10.0" && r.Method == http.MethodHead && r.Header.Get("Authorization") == "Bearer t":
			w.Header().Set("Docker-Content-Digest", dg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cf := &cosignFake{}
	r := &Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: cf, Token: "gh"}
	ctx := context.Background()
	tag, pre, err := r.Latest(ctx, "locksql")
	if err != nil || tag != "v0.10.0" || pre || auth != "Bearer gh" {
		t.Fatalf("latest: %s %v %v %q", tag, pre, err, auth)
	}
	if tag, pre, _ := r.Latest(ctx, "lockhttp"); tag != "v0.2.1" || !pre {
		t.Errorf("pre-releases only: %s %v", tag, pre)
	}
	if _, _, err := r.Latest(ctx, "lockmq"); err == nil {
		t.Error("no release: no error")
	}
	ref, err := r.Image(ctx, "locksql", "v0.10.0")
	if err != nil || ref != "ghcr.io/davidgodefroid/locksql@"+dg {
		t.Fatalf("image: %s %v", ref, err)
	}
	if len(cf.calls) != 1 || !strings.Contains(cf.calls[0], `^https://github\.com/DavidGodefroid/locksql/\.github/workflows/release\.yml@refs/tags/v0\.10\.0$ `+ref) {
		t.Errorf("cosign: %v", cf.calls)
	}
	if _, err := r.Image(ctx, "locksql", "v0.9.0"); err == nil {
		t.Error("an image the registry does not serve was pinned")
	}
	if _, err := r.Image(ctx, "locksql", "latest"); err == nil {
		t.Error("a non-release tag was accepted")
	}
	r.Run = &fake{failing: "cosign"}
	if _, err := r.Image(ctx, "locksql", "v0.10.0"); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Errorf("unsigned digest pinned: %v", err)
	}
}

// block is the service (or top-level entry) name of a compose file.
func block(out, name string) string {
	var b strings.Builder
	in := false
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") {
			in = l == "  "+name+":" || l == "  \""+name+"\":"
		} else if !strings.HasPrefix(l, " ") {
			in = false
		}
		if in {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// The profile is a reviewed copy: its fingerprint is in the review, and
// lock up copies exactly what it read into the profile volume.
func TestProfileReviewedAndCopied(t *testing.T) {
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.crm]\n"), 0o644)
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := ReadProfile(filepath.Join(ws, ".locksql"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "profile locksql "+filepath.Join(ws, ".locksql")+" "+pr.Fingerprint) {
		t.Errorf("review lacks the profile:\n%s", out)
	}
	if !f.ran("--no-deps profile-locksql "+pr.B64()) || !strings.Contains(f.upCompose, "lockfamily.profile: \""+pr.Fingerprint) {
		t.Errorf("copy: %v", f.calls)
	}
	// A changed profile is a change to review.
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.crm]\nproduction = false\n"), 0o644)
	if out, err := w.up("n\n", newFake()); err == nil || !strings.Contains(out, "- profile locksql") {
		t.Errorf("changed profile applied without review: %v\n%s", err, out)
	}
}

func TestProfileRefusals(t *testing.T) {
	for name, mk := range map[string]func(d string){
		"link dir": func(d string) {
			os.Remove(d)
			os.Symlink(t.TempDir(), d)
		},
		"link file":          func(d string) { os.Symlink("/etc/passwd", filepath.Join(d, "config.toml")) },
		"group-writable dir": func(d string) { os.Chmod(d, 0o775) },
		"world-writable file": func(d string) {
			p := filepath.Join(d, "config.toml")
			os.WriteFile(p, nil, 0o644)
			os.Chmod(p, 0o666)
		},
		"fifo":     func(d string) { syscall.Mkfifo(filepath.Join(d, "x"), 0o644) },
		"too big":  func(d string) { os.WriteFile(filepath.Join(d, "big"), make([]byte, maxProfile+1), 0o644) },
		"sub link": func(d string) { os.Mkdir(filepath.Join(d, "s"), 0o755); os.Symlink("/", filepath.Join(d, "s", "r")) },
	} {
		t.Run(name, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), ".locksql")
			os.Mkdir(d, 0o755)
			mk(d)
			if _, err := ReadProfile(d); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// .lockfamily must be the user's own directory that no one else writes.
func TestLockfamilyDirRefusals(t *testing.T) {
	ws := t.TempDir()
	os.Mkdir(filepath.Join(ws, Dir), 0o777)
	os.Chmod(filepath.Join(ws, Dir), 0o777)
	if err := Add(filepath.Join(ws, Dir, FileName), AddOptions{Type: "locksql", Name: "crm", Image: sqlImg, HubImage: hubImg}); err == nil {
		t.Error("lock add wrote in a world-writable .lockfamily")
	}
	if err := writeUpState(ws, UpState{Version: 1}); err == nil {
		t.Error("up.json written in a world-writable .lockfamily")
	}
}

// A link planted as .lockfamily/up.json is replaced, never written
// through; lock up keeps its own copy in its state directory.
func TestUpStateLinkReplaced(t *testing.T) {
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o644)
	os.Symlink(victim, filepath.Join(ws, Dir, UpFile))
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("up.json written through a link")
	}
	fi, err := os.Lstat(filepath.Join(ws, Dir, UpFile))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Errorf("up.json: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(w.dir, "state", UpFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("state copy: %v", err)
	}
}
