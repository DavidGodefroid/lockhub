package family

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// lox init's manual mode: a declared lock unchecked leaves lockfamily.yaml
// (and hub.routing), the rest of the file as it was.
func TestRemoveLock(t *testing.T) {
	w := newWS(t, "# my workspace\n"+yamlConf("  routing:\n    events: [tty]\n"))
	if err := RemoveLock(w.file, "events"); err != nil {
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
	if !slices.Equal(c.Instances(), []string{"crm-prod"}) || len(c.Hub.Routing) != 0 {
		t.Errorf("locks %v, routing %v", c.Instances(), c.Hub.Routing)
	}
	if err := RemoveLock(w.file, "nope"); err == nil {
		t.Error("removed a lock that is not there")
	}
}

// The only lock may go: a hub alone is a valid lockfamily.yaml.
func TestRemoveLastLock(t *testing.T) {
	w := newWS(t, "version: 1\nhub:\n  image: "+hubImg+"\nlocks:\n  crm-prod:\n    type: locksql\n    image: "+sqlImg+"\n")
	if err := RemoveLock(w.file, "crm-prod"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Locks) != 0 {
		t.Errorf("locks %v", c.Instances())
	}
}

// lox init gives lea's uid to the locks lea's agents reach.
func TestAddAllowedUIDs(t *testing.T) {
	w := newWS(t, yamlConf(""))
	if err := Add(w.file, AddOptions{Type: "lockfile", Name: "docs", Image: fileImg, Profile: "docs", AllowedUIDs: []int{1000}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.file)
	if !strings.Contains(string(b), "    allowed_uids: [1000]\n") {
		t.Errorf("allowed_uids not written in flow style:\n%s", b)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Locks["docs"]; !slices.Equal(l.AllowedUIDs, UIDList{1000}) || l.Profile != "docs" {
		t.Errorf("added %+v", l)
	}
	// Refused as lox up would: the console's own uid.
	if err := Add(w.file, AddOptions{Type: "locksql", Name: "other", Image: sqlImg, AllowedUIDs: []int{10001}}); err == nil {
		t.Error("allowed_uids with the console's own uid accepted")
	}
}

const profilesTOML = `# shop profiles
[profiles.orders]
host = "db.example.com"
vhosts = [
  "a",
]

[profiles.orders.extra]
x = 1

# inventory below
[profiles.inventory]
host = "inv.example.com"
`

func TestRemoveProfileKeepsOthers(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte(profilesTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProfile(dir, "orders"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	want := "# shop profiles\n\n# inventory below\n[profiles.inventory]\nhost = \"inv.example.com\"\n"
	if string(b) != want {
		t.Errorf("config.toml:\n%s\nwant:\n%s", b, want)
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if err := RemoveProfile(dir, "orders"); err == nil || !strings.Contains(err.Error(), "orders") {
		t.Errorf("a profile that is not there: %v", err)
	}
}

func TestRemoveProfileRefusesMultiline(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	src := "[profiles.orders]\nnote = \"\"\"\n[profiles.fake]\n\"\"\"\n"
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RemoveProfile(dir, "orders")
	if err == nil || err.Error() != "config.toml holds a multi-line string: remove [profiles.orders] by hand" {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != src {
		t.Errorf("file changed:\n%s", b)
	}
}

// The other profiles are kept byte for byte when the removed one holds an
// escaped quote before a bracket, or when a header has quotes and a
// trailing comment.
func TestRemoveProfileTrickyTOML(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"escaped quote": {
			"[profiles.orders]\npw = \"a\\\"[b\"\n\n[profiles.inventory]\nhost = \"inv\"\n",
			"[profiles.inventory]\nhost = \"inv\"\n"},
		"quoted header with comment": {
			"[profiles.orders]\nhost = \"x\"\n\n[profiles.\"inventory\"] # main\nhost = \"inv\"\n",
			"[profiles.\"inventory\"] # main\nhost = \"inv\"\n"},
		"literal string": {
			"[profiles.orders]\npw = 'a\\'\n\n[profiles.inventory]\nhost = \"inv\"\n",
			"[profiles.inventory]\nhost = \"inv\"\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(cfg, []byte(c.in), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := RemoveProfile(dir, "orders"); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(cfg); string(b) != c.want {
				t.Errorf("config.toml:\n%s\nwant:\n%s", b, c.want)
			}
		})
	}
}

// Safety net: a file whose brackets do not balance (a line this editor
// misreads) is refused untouched, never emptied.
func TestRemoveProfileRefusesWhatItMisreads(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	src := "[profiles.orders]\nx = [\n  1,\n\n[profiles.inventory]\nhost = \"inv\"\n"
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProfile(dir, "orders"); err == nil {
		t.Error("removed from a file it cannot read")
	}
	if b, _ := os.ReadFile(cfg); string(b) != src {
		t.Errorf("file changed:\n%s", b)
	}
}

// Valid TOML whose other profile has a quoted key (commas, brackets,
// dots, spaces): it is kept byte for byte.
func TestRemoveProfileQuotedKeys(t *testing.T) {
	for _, key := range []string{`"a,b"`, `"a=b"`, `"a]b"`, `"a[b"`, `'orders.x'`, `"orders "`, `"or ders"`, `"orders.v2"`} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "config.toml")
			other := "[profiles." + key + "]\nhost = \"inv\"\n"
			if err := os.WriteFile(cfg, []byte("[profiles.orders]\nx = 1\n\n"+other), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := RemoveProfile(dir, "orders"); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(cfg); string(b) != other {
				t.Errorf("config.toml:\n%s\nwant:\n%s", b, other)
			}
		})
	}
}

// Removing a profile whose name holds a dot removes that profile only.
func TestRemoveProfileDottedName(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	src := "[profiles.orders]\nx = 1\n\n[profiles.\"orders.v2\"]\nhost = \"v2\"\n[profiles.\"orders.v2\".extra]\ny = 2\n"
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProfile(dir, "orders.v2"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "[profiles.orders]\nx = 1\n\n" {
		t.Errorf("config.toml:\n%s", b)
	}
}

// A line starting with [ that is no table header is refused, file untouched.
func TestRemoveProfileRefusesUnparseableHeader(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	src := "[profiles.orders]\nx = 1\n[profiles.inv entory]\nhost = \"inv\"\n"
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProfile(dir, "orders"); err == nil {
		t.Error("edited a file with a line it cannot read")
	}
	if b, _ := os.ReadFile(cfg); string(b) != src {
		t.Errorf("file changed:\n%s", b)
	}
}

// The oracle (a real TOML parser) refuses a result that is not the
// original with only the profile deleted.
func TestCheckProfileEditOracle(t *testing.T) {
	orig := "[profiles.orders]\nx = 1\n[profiles.inventory]\nhost = \"inv\"\n"
	if err := checkProfileEdit([]byte(orig), []byte("[profiles.inventory]\nhost = \"inv\"\n"), "orders"); err != nil {
		t.Errorf("right edit refused: %v", err)
	}
	for name, out := range map[string]string{
		"empty":         "",
		"other changed": "[profiles.inventory]\nhost = \"x\"\n",
		"not removed":   orig,
		"not toml":      "[profiles.inventory\n",
	} {
		if err := checkProfileEdit([]byte(orig), []byte(out), "orders"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkProfileEdit([]byte("[x"), []byte(""), "orders"); err == nil {
		t.Error("an original that does not decode was accepted")
	}
}

// A nan outside the profile is the same nan after the edit (NaN is not
// equal to itself, but the file did not change there).
func TestCheckProfileEditNaN(t *testing.T) {
	rest := "[limits]\nratio = nan\nlist = [1.0, -nan]\n[[rules]]\nw = +nan\n[profiles.inventory]\nhost = \"inv\"\n"
	orig := "[profiles.orders]\nx = 1\n" + rest
	if err := checkProfileEdit([]byte(orig), []byte(rest), "orders"); err != nil {
		t.Errorf("nan outside the profile refused: %v", err)
	}
	if err := checkProfileEdit([]byte(orig), []byte(strings.Replace(rest, "ratio = nan", "ratio = 1.0", 1)), "orders"); err == nil {
		t.Error("a nan changed to a number was accepted")
	}
}
