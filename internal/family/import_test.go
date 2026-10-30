package family

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, s string) string {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const otherSQL = "ghcr.io/davidgodefroid/locksql@sha256:5555555555555555555555555555555555555555555555555555555555555555"

func TestImportTwoSubProjectsKeepsStrictest(t *testing.T) {
	root := t.TempDir()
	// The workspace declares only its hub: its locks come from the sub-projects.
	base := write(t, filepath.Join(root, "lockfamily.yaml"), "# workspace\nversion: 1\nhub:\n  image: "+hubImg+"\n  facades: [tty, deck, slack]\n")
	a := write(t, filepath.Join(root, "crm", "lockfamily.yaml"), `version: 1
hub:
  image: `+hubImg+`
locks:
  crm:
    type: locksql
    image: `+sqlImg+`
  events:
    type: lockmq
    image: `+mqImg+`
`)
	b := write(t, filepath.Join(root, "billing", "lockfamily.yaml"), `version: 1
hub:
  image: `+hubImg+`
  facades: [tty, deck, slack]
  routing:
    crm: [tty, slack]
locks:
  crm:
    type: locksql
    image: `+otherSQL+`
  events:
    type: lockfile
    image: `+fileImg+`
`)
	notes, err := Import(base, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(base)
	if err != nil {
		t.Fatal(err)
	}
	crm := c.Locks["crm"]
	if crm.Image != sqlImg {
		t.Errorf("first declaration not kept: %+v", crm)
	}
	// crm: facades tty,deck in a (defaults), tty,slack in b: only tty is in both.
	if got := strings.Join(c.Hub.Routing["crm"], ","); got != "tty" {
		t.Errorf("routing crm = %q, want tty", got)
	}
	if c.Locks["events"].Type != "lockmq" {
		t.Errorf("type conflict resolved wrongly: %+v", c.Locks["events"])
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{"adds lock crm", "adds lock events", "another image", "routing narrowed", "rename one"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
	if raw, _ := os.ReadFile(base); !strings.Contains(string(raw), "# workspace") {
		t.Errorf("comment lost:\n%s", raw)
	}
}

func TestImportNarrowsNewLockToItsFacades(t *testing.T) {
	root := t.TempDir()
	base := write(t, filepath.Join(root, "lockfamily.yaml"), yamlConf(""))
	a := write(t, filepath.Join(root, "a", "lockfamily.yaml"), "version: 1\nhub:\n  image: "+hubImg+"\n  facades: [tty]\nlocks:\n  docs:\n    type: lockfile\n    image: "+fileImg+"\n")
	if _, err := Import(base, []string{a}); err != nil {
		t.Fatal(err)
	}
	c, _ := Load(base)
	if got := strings.Join(c.Hub.Routing["docs"], ","); got != "tty" {
		t.Errorf("docs routed to %q: a sub-project answering only at the terminal must stay so", got)
	}
}

func TestImportRefusesUnanswerableRouting(t *testing.T) {
	root := t.TempDir()
	base := write(t, filepath.Join(root, "lockfamily.yaml"), yamlConf("  routing:\n    crm-prod: [deck]\n"))
	before, _ := os.ReadFile(base)
	a := write(t, filepath.Join(root, "a", "lockfamily.yaml"), "version: 1\nhub:\n  image: "+hubImg+"\n  routing:\n    crm-prod: [tty]\nlocks:\n  crm-prod:\n    type: locksql\n    image: "+sqlImg+"\n")
	if _, err := Import(base, []string{a}); err == nil || !strings.Contains(err.Error(), "no facade") {
		t.Fatalf("err %v", err)
	}
	if after, _ := os.ReadFile(base); string(after) != string(before) {
		t.Error("file changed on refusal")
	}
}

func TestImportIntoFreshWorkspace(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "lockfamily.yaml")
	a := write(t, filepath.Join(root, "a", "lockfamily.yaml"), yamlConf(""))
	notes, err := Import(base, []string{a})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(base)
	if err != nil || len(c.Locks) != 2 || c.Hub.Image != hubImg {
		t.Fatalf("%v %+v", err, c)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "hub section from") {
		t.Errorf("notes %v", notes)
	}
}
