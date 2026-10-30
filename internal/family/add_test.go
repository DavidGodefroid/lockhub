package family

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fileImg = "ghcr.io/davidgodefroid/lockfile@sha256:4444444444444444444444444444444444444444444444444444444444444444"

func TestAddKeepsCommentsAndValidates(t *testing.T) {
	w := newWS(t, "# my workspace\n"+yamlConf(""))
	if err := Add(w.file, AddOptions{Type: "lockfile", Name: "docs", Image: fileImg}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.file)
	if !strings.Contains(string(b), "# my workspace") {
		t.Errorf("comment lost:\n%s", b)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	l := c.Locks["docs"]
	if l.Type != "lockfile" || l.Image != fileImg {
		t.Errorf("added %+v", l)
	}
	if len(c.Locks) != 3 {
		t.Errorf("locks %v", c.Instances())
	}
}

func TestAddRefusals(t *testing.T) {
	for name, o := range map[string]AddOptions{
		"duplicate":      {Type: "locksql", Name: "crm-prod", Image: sqlImg},
		"tag not digest": {Type: "lockfile", Name: "docs", Image: "ghcr.io/davidgodefroid/lockfile:latest"},
		"wrong repo":     {Type: "lockfile", Name: "docs", Image: sqlImg},
		"bad name":       {Type: "lockfile", Name: "Docs", Image: fileImg},
		"unknown type":   {Type: "lockftp", Name: "docs", Image: fileImg},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWS(t, yamlConf(""))
			before, _ := os.ReadFile(w.file)
			if err := Add(w.file, o); err == nil {
				t.Fatal("accepted")
			}
			if after, _ := os.ReadFile(w.file); string(after) != string(before) {
				t.Error("file changed on refusal")
			}
		})
	}
}

func TestAddCreatesFreshWorkspace(t *testing.T) {
	ws := t.TempDir()
	file := Locate(ws)
	if file != filepath.Join(ws, Dir, FileName) {
		t.Fatalf("a new lockfamily.yaml goes in .lockfamily: %s", file)
	}
	if err := Add(file, AddOptions{Type: "locksql", Name: "crm", Image: sqlImg}); err == nil || !strings.Contains(err.Error(), "--hub-image") {
		t.Fatalf("no hub image: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("file written without a hub image")
	}
	if err := Add(file, AddOptions{Type: "locksql", Name: "crm", Image: sqlImg, HubImage: hubImg}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hub.Image != hubImg || c.Locks["crm"].Image != sqlImg {
		t.Errorf("%+v", c)
	}
	if fi, err := os.Stat(filepath.Dir(file)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf(".lockfamily: %v", err)
	}
	// Then lock up starts it, once the lock's profile exists.
	f0 := &fake{keys: map[string]string{"hub": pubKey(), "crm": pubKey()}}
	if _, err := upFor(t, file)("y\n", f0); err == nil || !strings.Contains(err.Error(), "profile of the locksql locks") {
		t.Fatalf("lock up without the lock's profile: %v", err)
	}
	// No PII rule set yet: the console writes its first one in its own
	// volume (LOCKSQL_PII_DIR), the profile copy being read-only.
	os.Mkdir(filepath.Join(ws, ".locksql"), 0o755)
	f := &fake{keys: map[string]string{"hub": pubKey(), "crm": pubKey()}}
	u := upFor(t, file)
	if out, err := u("y\n", f); err != nil || !f.ran("up -d") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// upFor runs lock up on file, with its state and runtime next to it.
func upFor(t *testing.T, file string) func(string, *fake) (string, error) {
	dir := t.TempDir()
	return func(input string, f *fake) (string, error) {
		var out strings.Builder
		u := &Up{File: file, State: filepath.Join(dir, "state"), Runtime: filepath.Join(dir, "run"), User: "1000:1000", Run: f, In: bufio.NewReader(strings.NewReader(input)), Out: &out}
		return out.String(), u.Do(context.Background())
	}
}

func TestAddRefusedIntoFreshWorkspaceLeavesNoDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), Dir, FileName)
	if err := Add(path, AddOptions{Name: "Bad Name", Type: "locksql", Image: sqlImg, HubImage: hubImg}); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := os.Lstat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("%s left behind by a refused lock add: %v", filepath.Dir(path), err)
	}
}
