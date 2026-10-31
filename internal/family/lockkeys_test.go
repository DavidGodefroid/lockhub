package family

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

// Each workspace's lox up keeps the others' lock keys: locks.json is the
// union of locks.d; an instance with two keys, or a key on two instances,
// is left out with a warning naming both workspaces; a workspace with no
// lock leaves the union.
func TestPinLockKeysUnion(t *testing.T) {
	dir := t.TempDir()
	a, b, c := pubKey(), pubKey(), pubKey()
	if w, err := pinLockKeys(dir, "lockfamily-aaaa", "/ws/a", map[string]string{"crm": a}); err != nil || len(w) != 0 {
		t.Fatal(w, err)
	}
	if w, err := pinLockKeys(dir, "lockfamily-bbbb", "/ws/b", map[string]string{"events": b}); err != nil || len(w) != 0 {
		t.Fatal(w, err)
	}
	if got := loadUnion(t, dir); !reflect.DeepEqual(got, map[string]string{"crm": a, "events": b}) {
		t.Fatalf("union %v", got)
	}
	// Workspace b also names an instance crm, with its own key: neither
	// workspace's crm can be checked; the warning names both.
	w, err := pinLockKeys(dir, "lockfamily-bbbb", "/ws/b", map[string]string{"events": b, "crm": c})
	if err != nil || len(w) != 1 || !strings.Contains(w[0], "lock instance crm has another key") ||
		!strings.Contains(w[0], "/ws/a (locks.d/lockfamily-aaaa.json)") || !strings.Contains(w[0], "/ws/b (locks.d/lockfamily-bbbb.json)") {
		t.Fatalf("warnings %q %v", w, err)
	}
	if got := loadUnion(t, dir); !reflect.DeepEqual(got, map[string]string{"events": b}) {
		t.Fatalf("union with a conflict %v", got)
	}
	// One key on two instances (a copied lock home): both left out.
	w, err = pinLockKeys(dir, "lockfamily-bbbb", "/ws/b", map[string]string{"events": a})
	if err != nil || len(w) != 1 || !strings.Contains(w[0], "share a key") {
		t.Fatalf("shared key warnings %q %v", w, err)
	}
	if lk, err := keys.LoadLocks(filepath.Join(dir, LockKeysFile)); err == nil {
		t.Fatalf("a shared key reached the union: %v", lk)
	}
	// Three instances on one key: all three left out.
	if _, err := pinLockKeys(dir, "lockfamily-cccc", "/ws/c", map[string]string{"web": a}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, LockKeysFile)); strings.Contains(string(b), a) {
		t.Fatalf("a key three instances share reached the union: %s", b)
	}
	if _, err := pinLockKeys(dir, "lockfamily-cccc", "/ws/c", nil); err != nil {
		t.Fatal(err)
	}
	// Workspace b re-applied without locks: its file goes, a's keys stay.
	if w, err := pinLockKeys(dir, "lockfamily-bbbb", "/ws/b", nil); err != nil || len(w) != 0 {
		t.Fatal(w, err)
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

// Another workspace's file that does not parse, or a key that is not one,
// is left out with a warning; the lox up goes on and the rest of the
// union stands. Two spellings of one key are one key.
func TestPinLockKeysBadFiles(t *testing.T) {
	dir := t.TempDir()
	a := pubKey()
	if _, err := pinLockKeys(dir, "lockfamily-aaaa", "/ws/a", map[string]string{"crm": a}); err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(dir, LockKeysDir)
	os.WriteFile(filepath.Join(d, "lockfamily-cccc.json"), []byte("{not json"), 0o600)
	os.WriteFile(filepath.Join(d, "lockfamily-dddd.json"), []byte(`{"workspace":"/ws/d","locks":{"web":{"public_key":"bm90IGEga2V5"},"Bad Name":{"public_key":"`+pubKey()+`"}}}`), 0o600)
	// a, spelled with non-zero trailing bits: the same 32 bytes.
	raw := []byte(a)
	alt := string(raw[:len(raw)-2]) + string(raw[len(raw)-2]+1) + "="
	if alt == a {
		t.Skip("no alternative spelling")
	}
	if k, err := base64.StdEncoding.DecodeString(alt); err == nil && keys.Public(k) == a {
		os.WriteFile(filepath.Join(d, "lockfamily-eeee.json"), []byte(`{"workspace":"/ws/e","locks":{"crm-copy":{"public_key":"`+alt+`"}}}`), 0o600)
	}
	w, err := pinLockKeys(dir, "lockfamily-bbbb", "/ws/b", map[string]string{"events": pubKey()})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(w, "\n")
	if strings.Contains(joined, "Bad Name") {
		t.Errorf("a name that is not an instance name is shown:\n%s", joined)
	}
	for _, want := range []string{"locks.d/lockfamily-cccc.json: unreadable", `instance "web" has no valid key`, "an instance without a valid name"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q:\n%s", want, joined)
		}
	}
	got := loadUnion(t, dir)
	if _, ok := got["events"]; !ok || got["web"] != "" {
		t.Errorf("union %v", got)
	}
	if _, err := os.Stat(filepath.Join(d, "lockfamily-eeee.json")); err == nil {
		if !strings.Contains(joined, "share a key") || got["crm"] != "" {
			t.Errorf("two spellings of one key not seen as shared: %v\n%s", got, joined)
		}
	}
}

// Concurrent lock ups of different workspaces lose none of each other's
// keys (the lock on the facades directory).
func TestPinLockKeysConcurrent(t *testing.T) {
	dir := t.TempDir()
	want := map[string]string{}
	for i := range 8 {
		want[fmt.Sprintf("lock-%d", i)] = pubKey()
	}
	var wg sync.WaitGroup
	for n, k := range want {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pinLockKeys(dir, "lockfamily-"+n, "/ws/"+n, map[string]string{n: k}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := loadUnion(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatalf("union %v, want %v", got, want)
	}
}

// Two workspaces under one user's facade keys: the second lox up keeps
// the first one's lock keys in locks.json (lox approve and lea's deck
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
	if strings.Contains(out, "warning: lock keys") {
		t.Errorf("a conflict reported:\n%s", out)
	}
}
