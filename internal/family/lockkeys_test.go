package family

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/keys"
)

func loadUnion(t *testing.T, dir string) map[string]string {
	t.Helper()
	lk, err := keys.LoadLocks(filepath.Join(dir, LockKeysFile))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for n, k := range lk {
		out[n] = keys.Public(k)
	}
	return out
}

// Each workspace's lock up keeps the others' lock keys: locks.json is the
// union of locks.d; an instance with two keys, or a key on two instances,
// is left out and named; a workspace with no lock leaves the union.
func TestPinLockKeysUnion(t *testing.T) {
	dir := t.TempDir()
	a, b, c := pubKey(), pubKey(), pubKey()
	if bad, err := pinLockKeys(dir, "lockfamily-aaaa", map[string]string{"crm": a}); err != nil || len(bad) != 0 {
		t.Fatal(bad, err)
	}
	if bad, err := pinLockKeys(dir, "lockfamily-bbbb", map[string]string{"events": b}); err != nil || len(bad) != 0 {
		t.Fatal(bad, err)
	}
	if got := loadUnion(t, dir); !reflect.DeepEqual(got, map[string]string{"crm": a, "events": b}) {
		t.Fatalf("union %v", got)
	}
	// Workspace b also names an instance crm, with its own key: neither
	// workspace's crm can be checked.
	bad, err := pinLockKeys(dir, "lockfamily-bbbb", map[string]string{"events": b, "crm": c})
	if err != nil || !reflect.DeepEqual(bad, []string{"crm"}) {
		t.Fatalf("conflicts %v %v", bad, err)
	}
	if got := loadUnion(t, dir); !reflect.DeepEqual(got, map[string]string{"events": b}) {
		t.Fatalf("union with a conflict %v", got)
	}
	// One key on two instances (a copied lock home): both left out.
	bad, err = pinLockKeys(dir, "lockfamily-bbbb", map[string]string{"events": a})
	if err != nil || !reflect.DeepEqual(bad, []string{"crm", "events"}) {
		t.Fatalf("shared key conflicts %v %v", bad, err)
	}
	// Workspace b re-applied without locks: its file goes, a's keys stay.
	if bad, err := pinLockKeys(dir, "lockfamily-bbbb", nil); err != nil || len(bad) != 0 {
		t.Fatal(bad, err)
	}
	if got := loadUnion(t, dir); !reflect.DeepEqual(got, map[string]string{"crm": a}) {
		t.Fatalf("union after b left %v", got)
	}
	for _, p := range []string{filepath.Join(dir, LockKeysFile), filepath.Join(dir, LockKeysDir, "lockfamily-aaaa.json")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, LockKeysDir)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("locks.d: %v %v", fi, err)
	}
}

// Two workspaces under one user's facade keys: the second lock up keeps
// the first one's lock keys in locks.json (lock approve and lea's deck
// check both workspaces' reveals).
func TestLockUpTwoWorkspacesKeepEachOthersLockKeys(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	facades := filepath.Join(root, "facades")
	up := func(name, conf string, f *fake) string {
		t.Helper()
		ws := filepath.Join(root, name)
		file := filepath.Join(ws, Dir, FileName)
		os.MkdirAll(filepath.Dir(file), 0o755)
		for _, ty := range Types {
			os.Mkdir(filepath.Join(ws, "."+ty), 0o755)
		}
		piiSet(ws)
		os.WriteFile(file, []byte(conf), 0o644)
		var out strings.Builder
		u := &Up{File: file, State: filepath.Join(root, "state-"+name), Runtime: filepath.Join(root, "run"), Facades: facades,
			User: "1000:1000", Run: f, In: bufio.NewReader(strings.NewReader("y\n")), Out: &out}
		if err := u.Do(context.Background()); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out.String())
		}
		return out.String()
	}
	fa := newFake()
	up("one", yamlConf(""), fa)
	fb := &fake{keys: map[string]string{"hub": pubKey(), "web": pubKey()}}
	out := up("two", `version: 1
hub:
  image: `+hubImg+`
locks:
  web:
    type: lockfile
    image: `+fileImg+`
`, fb)
	got := loadUnion(t, facades)
	want := map[string]string{"crm-prod": fa.keys["crm-prod"], "events": fa.keys["events"], "web": fb.keys["web"]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("locks.json %v, want %v\n%s", got, want, out)
	}
	if strings.Contains(out, "warning: lock instance") {
		t.Errorf("a conflict reported:\n%s", out)
	}
}
