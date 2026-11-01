package family

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// probe runs lox up as a probe over w's workspace and state.
func (w ws) probe(t *testing.T, f *fake) (same bool, prompt string) {
	t.Helper()
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
		Run: f, In: bufio.NewReader(strings.NewReader("")), Out: &out, Probe: true}
	if err := u.Do(context.Background()); err != nil {
		t.Fatalf("probe: %v\n%s", err, out.String())
	}
	return u.Same, out.String()
}

// snapshot is every file under dir with its bytes (and every directory).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			m[p] = "<dir>"
			return nil
		}
		b, _ := os.ReadFile(p)
		m[p] = string(b)
		return nil
	})
	return m
}

func TestProbeNothingApplied(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	before := snapshot(t, w.dir)
	same, _ := w.probe(t, f)
	if same || len(f.calls) != 0 {
		t.Errorf("same %v, calls %v: want false, none", same, f.calls)
	}
	if after := snapshot(t, w.dir); len(after) != len(before) {
		t.Errorf("a probe created files: %d -> %d", len(before), len(after))
	}
}

func TestProbeUnchangedAndEdited(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	f.calls = nil // the locks keep their keys between runs
	before := snapshot(t, w.dir)
	same, prompt := w.probe(t, f)
	if !same {
		t.Errorf("an applied, unchanged configuration is not Same\n%s", prompt)
	}
	if f.ran(" up -d") || strings.Contains(prompt, "Apply?") {
		t.Errorf("a probe applied or asked: %v\n%s", f.calls, prompt)
	}
	after := snapshot(t, w.dir)
	if len(after) != len(before) {
		t.Errorf("a probe created files: %d -> %d", len(before), len(after))
	}
	for p, b := range before {
		if after[p] != b {
			t.Errorf("%s changed by a probe", p)
		}
	}
	// The yaml edited by hand: not Same.
	if err := os.WriteFile(w.file, []byte(strings.Replace(yamlConf(""), "type: lockmq", "type: lockmq\n    profile: other", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if same, _ := w.probe(t, f); same {
		t.Error("an edited lockfamily.yaml is Same")
	}
}

func TestProbeNewLockMakesNoKey(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	f.calls = nil
	conf := yamlConf("") + "  extra:\n    type: lockmq\n    image: " + mqImg + "\n"
	if err := os.WriteFile(w.file, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	f.keys["extra"] = pubKey()
	same, _ := w.probe(t, f)
	if same {
		t.Error("a newly declared lock is Same")
	}
	for _, c := range f.calls {
		if strings.Contains(c, "lock-extra") || strings.Contains(c, "up -d") {
			t.Errorf("a probe ran %q", c)
		}
	}
}
