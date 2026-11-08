package family

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExpandHome(t *testing.T) {
	for in, want := range map[string]string{
		"~/db-ca.pem":       "/home/locksql/db-ca.pem",
		"~/.ssh/id_ed25519": "/home/locksql/.ssh/id_ed25519",
		"~":                 "/home/locksql",
		"~/":                "/home/locksql",
		"/etc/ssl/ca.pem":   "/etc/ssl/ca.pem",
		"certs/ca.pem":      "certs/ca.pem",
		"~other/ca.pem":     "~other/ca.pem",
	} {
		if got := ExpandHome(in, ConsoleHome("locksql")); got != want {
			t.Errorf("ExpandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileFileKeys(t *testing.T) {
	p := tomlProfile(
		`[profiles.other]`,
		`tls_ca = "/other.pem"`,
		`[profiles.orders]`,
		`engine = "postgres"`,
		`tls_ca = "~/db-ca.pem"   # the CA`,
		`tls_cert = '/etc/locksql/client.pem'`,
		`tls_key = "~/client.key"`,
		`[profiles.orders.ssh]`,
		`host = "bastion"`,
		`auth = "key"`,
		`key = "~/.ssh/id_ed25519"`,
	)
	got, odd := ProfileFileKeys(p, "orders")
	want := []FileKey{{"tls_ca", "~/db-ca.pem"}, {"tls_cert", "/etc/locksql/client.pem"}, {"tls_key", "~/client.key"}, {"ssh.key", "~/.ssh/id_ed25519"}}
	if !reflect.DeepEqual(got, want) || odd != nil {
		t.Errorf("got %v %v, want %v", got, odd, want)
	}
	// ssh.key counts with auth = "key" only; dotted keys are the table's.
	p = tomlProfile(`[profiles.p]`, `ssh.auth = "agent"`, `ssh.key = "~/k"`, `tls_ca = "a\"b"`)
	if got, odd := ProfileFileKeys(p, ""); got != nil || !reflect.DeepEqual(odd, []string{"tls_ca"}) {
		t.Errorf("agent auth: %v %v", got, odd)
	}
	p = tomlProfile(`[profiles.p]`, `ssh.auth = "key"`, `ssh.key = "~/k"`)
	if got, _ := ProfileFileKeys(p, ""); !reflect.DeepEqual(got, []FileKey{{"ssh.key", "~/k"}}) {
		t.Errorf("dotted keys: %v", got)
	}
}

// The script homefiles-<instance> runs, on a fake home volume.
func TestHomeFilesScript(t *testing.T) {
	if out, err := exec.Command("stat", "-L", "-c", "%a", "/").Output(); err != nil || len(out) == 0 {
		t.Skip("no stat -c here")
	}
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "ca.pem"), []byte("pem"), 0o644)
	os.WriteFile(filepath.Join(home, "client.key"), []byte("key"), 0o600)
	os.WriteFile(filepath.Join(home, "open.key"), []byte("key"), 0o640)
	os.Mkdir(filepath.Join(home, "dir"), 0o700)
	in := strings.Join([]string{"ca.pem", "client.key", "open.key", "dir", "absent.pem", "-n"}, "\n") + "\n"
	for _, n := range []string{"ca.pem", "client.key", "open.key", "dir", "absent.pem"} {
		in = strings.Replace(in, n+"\n", filepath.Join(home, n)+"\n", 1)
	}
	cmd := exec.Command("/bin/sh", "-c", homeFilesScript, "homefiles")
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := "ok 644\nok 600\nok 640\nnotfile\nmissing\nmissing\n"
	if string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
	// homecopy-<instance>: its stdin to $1, private, its directory made.
	dst := filepath.Join(home, "new", "db-ca.pem")
	cmd = exec.Command("/bin/sh", "-c", homeCopyScript, "homecopy", dst)
	cmd.Stdin = strings.NewReader("pem\n")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "pem\n" {
		t.Errorf("copied %q", b)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
}

func TestHomeFileWarnings(t *testing.T) {
	l := Lock{Type: "locksql", Image: sqlImg}
	f := func(k, p, state string, mode uint32) HomeFile {
		return HomeFile{FileKey: FileKey{k, p}, Resolved: ExpandHome(p, "/home/locksql"), State: state, Mode: mode}
	}
	got := HomeFileWarnings("lockfamily-1234abcd", "orders", l, []HomeFile{
		f("tls_ca", "~/db-ca.pem", "missing", 0),
		f("tls_cert", "~/client.pem", "ok", 0o644),
		f("tls_key", "~/client.key", "ok", 0o600),
		f("ssh.key", "~/.ssh/id", "ok", 0o644),
		f("tls_ca", "/etc/ca.pem", "missing", 0),
	}, nil, nil)
	want := []string{
		"tls_ca: /home/locksql/db-ca.pem (~/db-ca.pem) is not in the lock's home volume; copy it there: docker run --rm -i --network none --user 10001:10000 -v lockfamily-1234abcd_orders-home:/home/locksql --entrypoint /bin/sh " + sqlImg + " -c 'umask 077 && mkdir -p /home/locksql && cat > /home/locksql/db-ca.pem' < db-ca.pem",
		"ssh.key: /home/locksql/.ssh/id (~/.ssh/id) is readable by others (mode 0644): docker run --rm --network none --user 10001:10000 -v lockfamily-1234abcd_orders-home:/home/locksql --entrypoint chmod " + sqlImg + " 600 /home/locksql/.ssh/id",
		"tls_ca: /etc/ca.pem not found in the lock's image; write it ~/ca.pem (/home/locksql) and copy it into the lock's home",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

const homeConf = `version: 1
hub:
  image: ` + hubImg + `
locks:
  orders:
    type: locksql
    image: ` + sqlImg + `
    profile: orders
`

func homeWS(t *testing.T, profile string) (ws, *fake) {
	w := newWS(t, homeConf)
	os.WriteFile(filepath.Join(w.dir, "projects", ".locksql", "config.toml"), []byte(profile), 0o644)
	f := newFake()
	f.keys["orders"] = f.keys["crm-prod"]
	return w, f
}

func TestReviewFlagsMissingHomeFile(t *testing.T) {
	w, f := homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\ntls_ca = \"~/db-ca.pem\"\ntls_key = \"~/client.key\"\n")
	f.keys["homefiles/orders"] = "missing\nok 644\n"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"  file         WARNING: tls_ca: /home/locksql/db-ca.pem (~/db-ca.pem) is not in the lock's home volume; copy it there: docker run --rm -i --network none --user 10001:10000 -v lockfamily-",
		"_orders-home:/home/locksql --entrypoint /bin/sh " + sqlImg + " -c 'umask 077 && mkdir -p /home/locksql && cat > /home/locksql/db-ca.pem' < db-ca.pem\n",
		"  file         WARNING: tls_key: /home/locksql/client.key (~/client.key) is readable by others (mode 0644): docker run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	var call string
	for _, c := range f.calls {
		if strings.Contains(c, " --no-deps homefiles-orders") {
			call = c
		}
	}
	if call == "" || string(f.stdins[call]) != "/home/locksql/db-ca.pem\n/home/locksql/client.key\n" {
		t.Errorf("homefiles: %q %q", call, f.stdins[call])
	}
	if !strings.Contains(f.upCompose, `"homefiles-orders":`) || !strings.Contains(f.upCompose, `"orders-home:/home/locksql"`) || !strings.Contains(f.upCompose, `[ ! -e \"$$p\" ]`) {
		t.Errorf("no homefiles service:\n%s", f.upCompose)
	}
	// Unchanged since: no block, the warning still said.
	f2 := &fake{keys: f.keys}
	if out, err = w.up("", f2); err != nil || !strings.Contains(out, "configuration unchanged") || !strings.Contains(out, "warning: lock orders: tls_ca: /home/locksql/db-ca.pem") {
		t.Errorf("unchanged: %v\n%s", err, out)
	}
}

func TestReviewPresentHomeFilesSayNothing(t *testing.T) {
	w, f := homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\ntls_ca = \"~/db-ca.pem\"\n[profiles.orders.ssh]\nhost = \"b\"\nauth = \"key\"\nkey = \"~/.ssh/id\"\n")
	f.keys["homefiles/orders"] = "ok 644\nok 600\n"
	out, err := w.up("y\n", f)
	if err != nil || strings.Contains(out, "WARNING") || strings.Contains(out, "warning:") {
		t.Errorf("%v\n%s", err, out)
	}
	// No file key: nothing run.
	w, f = homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\n")
	if out, err := w.up("y\n", f); err != nil || f.ran("homefiles-") {
		t.Errorf("%v %v\n%s", err, f.calls, out)
	}
}

func TestReviewHomeFilesUncheckable(t *testing.T) {
	w, f := homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\ntls_ca = \"~/db-ca.pem\"\n")
	f.failing = "homefiles-orders"
	out, err := w.up("y\n", f)
	if err != nil || !strings.Contains(out, "file         WARNING: the profile's files could not be checked (") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestReviewFlagWarnsHomeFiles(t *testing.T) {
	w, f := homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\ntls_ca = \"~/db-ca.pem\"\n")
	f.keys["homefiles/orders"] = "missing\n"
	out, err := upReview(w, context.Background(), strings.NewReader("y\n"), true, f)
	if err != nil || !strings.Contains(out, "warning: lock orders: tls_ca: /home/locksql/db-ca.pem (~/db-ca.pem) is not in the lock's home volume") {
		t.Errorf("%v\n%s", err, out)
	}
}

// lox add: a missing file is offered a host file, copied after the yes.
func TestOfferCopyCopiesAfterYes(t *testing.T) {
	w, f := homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\ntls_ca = \"~/certs/db-ca.pem\"\n")
	f.keys["homefiles/orders"] = "missing\n"
	src := filepath.Join(w.dir, "db-ca.pem")
	os.WriteFile(src, []byte("PEM\n"), 0o644)
	up := func(in string, f *fake) (string, error) {
		var out strings.Builder
		u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
			Run: f, In: bufio.NewReader(strings.NewReader(in)), Out: &out, Focus: "orders", OfferCopy: true}
		err := u.Do(context.Background())
		return out.String(), err
	}
	// A refused answer: no copy; nothing copied on n.
	out, err := up(filepath.Join(w.dir, "absent")+"\n"+src+"\nn\n", f)
	if err == nil || f.ran("homecopy-") || !strings.Contains(out, "tls_ca: "+filepath.Join(w.dir, "absent")+": no such file or directory") {
		t.Errorf("declined: %v %v\n%s", err, f.calls, out)
	}
	f2 := &fake{keys: f.keys}
	out, err = up(src+"\ny\n", f2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Copy tls_ca into the lock's home as /home/locksql/certs/db-ca.pem, from the host file (optional: empty = not now, with the command above): ") ||
		!strings.Contains(out, "lock orders: tls_ca copied to /home/locksql/certs/db-ca.pem") {
		t.Errorf("no copy said:\n%s", out)
	}
	var copyAt, upAt int = -1, -1
	for i, c := range f2.calls {
		if strings.HasSuffix(c, " --no-deps homecopy-orders /home/locksql/certs/db-ca.pem") {
			copyAt = i
			if string(f2.stdins[c]) != "PEM\n" {
				t.Errorf("copied %q", f2.stdins[c])
			}
		}
		if strings.Contains(c, " up -d --remove-orphans") {
			upAt = i
		}
	}
	if copyAt < 0 || upAt < copyAt {
		t.Errorf("copy %d, up %d: %v", copyAt, upAt, f2.calls)
	}
	// Empty answer: not now.
	w, f = homeWS(t, "[profiles.orders]\nengine = \"postgres\"\nhost = \"db.example.com\"\ntls_ca = \"~/db-ca.pem\"\n")
	f.keys["homefiles/orders"] = "missing\n"
	if out, err := up("\ny\n", f); err != nil || f.ran("homecopy-") {
		t.Errorf("empty answer: %v\n%s", err, out)
	}
}
