package family

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fileImg = "ghcr.io/davidgodefroid/lockfile@sha256:4444444444444444444444444444444444444444444444444444444444444444"

func TestAddKeepsCommentsAndValidates(t *testing.T) {
	w := newWS(t, "# my workspace\n"+yamlConf(""))
	if err := Add(w.file, AddOptions{Type: "lockfile", Name: "docs", Image: fileImg, Production: true, Credentials: "ask"}); err != nil {
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
	if l.Type != "lockfile" || l.Image != fileImg || !l.Production || l.Credentials != "ask" {
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
		"secret":         {Type: "lockfile", Name: "docs", Image: fileImg, Credentials: "hunter2"},
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
	file := filepath.Join(t.TempDir(), "lockfamily.yaml")
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
	// Then lock up starts it.
	f := &fake{keys: map[string]string{"hub": pubKey(), "crm": pubKey()}}
	u := upFor(t, file)
	if out, err := u("y\n", f); err != nil || !f.ran("up -d") {
		t.Fatalf("%v\n%s", err, out)
	}
}
