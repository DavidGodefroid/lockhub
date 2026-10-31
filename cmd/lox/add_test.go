package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

type okRunner struct{ calls []string }

func (o *okRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	o.calls = append(o.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

// lox add without --image pins the lock's (and, for a new workspace,
// the hub's) latest release by digest, once cosign verified it, in
// .lockfamily/lockfamily.yaml.
func TestAddResolvesLatestSignedRelease(t *testing.T) {
	d := map[string]string{"locksql": strings.Repeat("a", 64), "lockhub": strings.Repeat("b", 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases"):
			w.Write([]byte(`[{"tag_name":"v1.2.3"}]`))
		case r.URL.Path == "/token":
			w.Write([]byte(`{"token":"t"}`))
		case strings.HasSuffix(r.URL.Path, "/manifests/1.2.3"):
			repo := strings.Split(r.URL.Path, "/")[3]
			w.Header().Set("Docker-Content-Digest", "sha256:"+d[repo])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cos := &okRunner{}
	old := newReleases
	newReleases = func() *family.Releases {
		return &family.Releases{API: srv.URL, Registry: srv.URL, HTTP: srv.Client(), Run: cos}
	}
	t.Cleanup(func() { newReleases = old })
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	wd, _ := os.Getwd()
	os.Chdir(ws)
	t.Cleanup(func() { os.Chdir(wd) })
	var out, errb bytes.Buffer
	if code := run([]string{"add", "locksql", "crm"}, devNull(t), &out, &errb); code != 0 {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	b, err := os.ReadFile(filepath.Join(ws, ".lockfamily", "lockfamily.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ghcr.io/davidgodefroid/locksql@sha256:" + d["locksql"], "ghcr.io/davidgodefroid/lockhub@sha256:" + d["lockhub"]} {
		if !strings.Contains(string(b), want) {
			t.Errorf("lockfamily.yaml lacks %s:\n%s", want, b)
		}
	}
	if len(cos.calls) != 2 || !strings.Contains(out.String(), "signature verified") {
		t.Errorf("cosign: %v\n%s", cos.calls, out.String())
	}
	if code := run([]string{"add", "locksql", "x", "--version", "v1", "--image", "y"}, devNull(t), &out, &errb); code != 2 {
		t.Error("--version and --image together accepted")
	}
	if code := run([]string{"add", "lockdb", "x"}, devNull(t), &out, &errb); code != 2 {
		t.Error("unknown type accepted")
	}
}

func TestLegacyFileWarns(t *testing.T) {
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(ws, "lockfamily.yaml"), []byte("version: 1\n"), 0o644)
	wd, _ := os.Getwd()
	os.Chdir(ws)
	t.Cleanup(func() { os.Chdir(wd) })
	var errb bytes.Buffer
	f, err := lockFile("", &errb)
	if err != nil || f != filepath.Join(ws, "lockfamily.yaml") || !strings.Contains(errb.String(), "lea's agents can write") {
		t.Errorf("%s %v %q", f, err, errb.String())
	}
}
