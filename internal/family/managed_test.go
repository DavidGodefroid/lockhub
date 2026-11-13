//go:build lockfamily_managed_test

package family

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

// withManaged places body as the machine's managed file (lockkit's test
// path, no ownership check) and returns its directory.
func withManaged(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	writeManaged(t, dir, body)
	managed.SetTestPath(filepath.Join(dir, managed.FileName))
	t.Cleanup(func() { managed.SetTestPath("") })
	return dir
}

func writeManaged(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, managed.FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// noManaged makes the machine have no managed file.
func noManaged(t *testing.T) {
	managed.SetTestPath(filepath.Join(t.TempDir(), managed.FileName))
	t.Cleanup(func() { managed.SetTestPath("") })
}

// signManaged signs the managed file of dir as lox would have verified
// it: a bundle, signer.toml and the stamp lockkit takes for the check.
func signManaged(t *testing.T, dir string) string {
	t.Helper()
	data, _ := os.ReadFile(filepath.Join(dir, managed.FileName))
	bundle := []byte(`{"bundle":"test"}`)
	signer := []byte("certificate_identity_regexp = \"^https://github.com/acme/policy/\"\noidc_issuer = \"https://token.actions.githubusercontent.com\"\n")
	h := sha256.New()
	for _, b := range [][]byte{data, bundle, signer} {
		fmt.Fprintf(h, "%d:", len(b))
		h.Write(b)
	}
	stamp := "sha256:" + hex.EncodeToString(h.Sum(nil))
	os.WriteFile(filepath.Join(dir, managed.BundleName), bundle, 0o644)
	os.WriteFile(filepath.Join(dir, managed.SignerName), signer, 0o644)
	os.WriteFile(filepath.Join(dir, managed.VerifiedName), []byte(stamp+"\n"), 0o644)
	return stamp
}

const managedBody = `version = 1
organisation = "Acme"

[locksql.bounds]
tier = "write"
`

// tarFiles lists an archive's files with their content.
func tarFiles(t *testing.T, b []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Mode != 0o644 {
			t.Errorf("%s: owner %d:%d mode %o", h.Name, h.Uid, h.Gid, h.Mode)
		}
		c, _ := io.ReadAll(tr)
		out[h.Name] = string(c)
	}
}

func managedStdin(f *fake) []byte {
	for l, b := range f.stdins {
		if strings.HasSuffix(l, " --no-deps managed") {
			return b
		}
	}
	return nil
}

// No managed file: lox run as before, nothing of it in the compose file
// or applied.json.
func TestManagedNone(t *testing.T) {
	noManaged(t)
	if m, err := LoadManaged(context.Background()); m != nil || err != nil {
		t.Fatalf("no file: %v %v", m, err)
	}
	w := newWS(t, yamlConf(""))
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(f.upCompose, "managed") || f.ran("managedcheck-") || strings.Contains(out, "managed:") {
		t.Errorf("managed without a file:\n%s\n%s", out, f.upCompose)
	}
	b, _ := os.ReadFile(filepath.Join(w.dir, "state", "applied.json"))
	if strings.Contains(string(b), "managed") {
		t.Errorf("applied.json: %s", b)
	}
}

// A managed file lox cannot apply refuses the whole run: nothing runs.
func TestManagedRefusedStopsEverything(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":        "version = 1\n[nope\n",
		"unknown lox":    "version = 1\n[lox]\negress_allow = [\"a:1\"]\n",
		"bad action":     "version = 1\n[lox]\nauto_max = { delete = \"auto\" }\n",
		"bad value":      "version = 1\n[lox]\nauto_max = { write = \"maybe\" }\n",
		"bad image_min":  "version = 1\n[lox]\nimage_min = { locksql = \"0.17\" }\n",
		"unknown lock":   "version = 1\n[lox]\nimage_min = { lockdb = \"v1.0.0\" }\n",
		"bad egress":     "version = 1\n[lox]\negress = [\"db.internal\"]\n",
		"empty egress":   "version = 1\n[lox]\negress = []\n",
		"no version":     "[lox]\n",
		"bad vault addr": "version = 1\n[family]\nvault = { address = \"ftp://vault\" }\n",
	} {
		t.Run(name, func(t *testing.T) {
			withManaged(t, body)
			w := newWS(t, yamlConf(""))
			f := newFake()
			out, err := w.up("y\n", f)
			var me *ManagedError
			if !errors.As(err, &me) {
				t.Fatalf("not refused as managed: %v\n%s", err, out)
			}
			if len(f.calls) != 0 {
				t.Errorf("ran %v", f.calls)
			}
		})
	}
	// A signed file whose stamp is not for these bytes is refused too.
	dir := withManaged(t, managedBody)
	signManaged(t, dir)
	writeManaged(t, dir, managedBody+"# changed\n")
	managed.SetTestPath(filepath.Join(dir, managed.FileName))
	if _, err := LoadManaged(context.Background()); err == nil {
		t.Error("a stale stamp accepted")
	}
}

// A valid file is copied into the volume managed, mounted read-only at
// /etc/lockfamily in every lock with its fingerprint as a label; a lock
// whose managed check refuses its profile is not started, the others are.
func TestManagedMountedAndChecked(t *testing.T) {
	withManaged(t, managedBody)
	w := newWS(t, yamlConf(""))
	f := newFake()
	f.keys["check/crm-prod"] = "blocked by company policy: locksql.bounds.tier = write (profile p: tier = ddl)\n"
	f.keys["checkexit/crm-prod"] = "3"
	f.keys["check/events"] = "ok: 1 profile within the company policy (e)\n"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	why := "blocked by company policy: locksql.bounds.tier = write (profile p: tier = ddl)"
	for _, s := range []string{"lock crm-prod: not started: " + why + " (the other locks are)", "lock events: started", "managed: Acme sha256:"} {
		if !strings.Contains(out, s) {
			t.Errorf("no %q:\n%s", s, out)
		}
	}
	m, err := LoadManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if files := tarFiles(t, managedStdin(f)); len(files) != 1 || files[managed.FileName] != managedBody {
		t.Errorf("managed copy: %v", files)
	}
	svc := block(f.upCompose, "lock-events")
	for _, s := range []string{"      - managed:/etc/lockfamily:ro\n", "      lockfamily.managed: \"" + m.Fingerprint() + "\"\n"} {
		if !strings.Contains(svc, s) {
			t.Errorf("lock-events lacks %q:\n%s", s, svc)
		}
	}
	if !strings.Contains(f.upCompose, "\n  managed: {}\n") || block(f.upCompose, "lock-crm-prod") != "" {
		t.Errorf("compose:\n%s", f.upCompose)
	}
	chk := block(f.upCompose, "\"managedcheck-events\"")
	for _, s := range []string{"network_mode: none", "managed check", "      - managed:/etc/lockfamily:ro\n", `user: "10011:10010"`} {
		if !strings.Contains(chk, s) {
			t.Errorf("managedcheck-events lacks %q:\n%s", s, chk)
		}
	}
	setup := block(f.upCompose, "managed")
	for _, s := range []string{`user: "0:0"`, "network_mode: none", "      - managed:/m\n", "chown -R 0:0 /m && chmod 0755 /m"} {
		if !strings.Contains(setup, s) {
			t.Errorf("managed lacks %q:\n%s", s, setup)
		}
	}
	state := filepath.Join(w.dir, "state")
	if ns, _ := ReadNotStarted(state); ns["crm-prod"] != why {
		t.Errorf("not started: %v", ns)
	}
	var a Applied
	b, _ := os.ReadFile(filepath.Join(state, "applied.json"))
	if json.Unmarshal(b, &a); a.ManagedFingerprint != m.Fingerprint() {
		t.Errorf("applied.json: %s", b)
	}
}

// An image that predates `managed check` passes only when the file has no
// section for its lock.
func TestManagedCheckUnknownCommand(t *testing.T) {
	for _, tc := range []struct {
		body    string
		started bool
	}{{managedBody, true}, {managedBody + "[lockmq.bounds]\nhosts = [\"*.internal\"]\n", false}} {
		withManaged(t, tc.body)
		w := newWS(t, yamlConf(""))
		f := newFake()
		f.keys["tag/"+mqImg] = "v0.8.0"
		f.keys["check/events"] = ""
		f.keys["checkerr/events"] = "lockmq: unknown command; the commands are:\n"
		f.keys["checkexit/events"] = "3"
		out, err := w.up("y\n", f)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if got := strings.Contains(out, "lock events: started"); got != tc.started {
			t.Errorf("started %v, want %v:\n%s", got, tc.started, out)
		}
		if !tc.started && !strings.Contains(out, "lock events: not started: lockmq v0.8.0 predates managed support: upgrade it or set [lox] image_min") {
			t.Errorf("no reason:\n%s", out)
		}
	}
}

// A change of the managed file alone is applied without a question, and
// recreates the locks (their label); a profile change still asks.
func TestManagedChangeNoQuestion(t *testing.T) {
	dir := withManaged(t, managedBody)
	w := newWS(t, yamlConf(""))
	f := newFake()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m1, _ := LoadManaged(context.Background())
	writeManaged(t, dir, strings.Replace(managedBody, "Acme", "Acme Corp", 1))
	m2, _ := LoadManaged(context.Background())
	f2 := &fake{keys: f.keys}
	out, err := w.up("", f2)
	if err != nil {
		t.Fatalf("managed-only change asked: %v\n%s", err, out)
	}
	if strings.Contains(out, "Apply?") || !strings.Contains(out, "managed: changed "+shortFP(m1.Fingerprint())+" → "+shortFP(m2.Fingerprint())) {
		t.Errorf("review:\n%s", out)
	}
	if !strings.Contains(block(f2.upCompose, "lock-crm-prod"), m2.Fingerprint()) {
		t.Errorf("label not changed:\n%s", f2.upCompose)
	}
	// A profile change still asks.
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"sqlite\"\npath = \"/tmp/x.db\"\n"), 0o644)
	if out, err := w.up("n\n", &fake{keys: f.keys}); !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "Apply?") {
		t.Errorf("profile change: %v\n%s", err, out)
	}
	// The file removed: no volume, no mount, no question.
	os.Remove(filepath.Join(dir, managed.FileName))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), nil, 0o644)
	os.Remove(filepath.Join(ws, ".locksql", "config.toml"))
	f3 := &fake{keys: f.keys}
	out, err = w.up("", f3)
	if err != nil || strings.Contains(f3.upCompose, "managed") || !strings.Contains(out, "managed: changed "+shortFP(m2.Fingerprint())+" → none") {
		t.Errorf("file removed: %v\n%s\n%s", err, out, f3.upCompose)
	}
}

// [lox] image_min: an older image is not started, the others are; lox add
// of that lock stops on it.
func TestManagedImageMin(t *testing.T) {
	withManaged(t, "version = 1\n[lox]\nimage_min = { locksql = \"v0.18.0\", lockmq = \"v0.9.0\" }\n")
	w := newWS(t, yamlConf(""))
	f := newFake()
	f.keys["tag/"+sqlImg] = "v0.17.1"
	f.keys["tag/"+mqImg] = "v0.9.0"
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, s := range []string{"lock crm-prod: not started: blocked by company policy: lox.image_min.locksql = v0.18.0 (the image is locksql v0.17.1)", "lock events: started"} {
		if !strings.Contains(out, s) {
			t.Errorf("no %q:\n%s", s, out)
		}
	}
	if f.ran("managedcheck-crm-prod") {
		t.Error("a lock below image_min was checked")
	}
	// Its release unknown: not started either (fail closed).
	delete(f.keys, "tag/"+sqlImg)
	out, err = w.up("y\n", &fake{keys: f.keys})
	if err != nil || !strings.Contains(out, "lock crm-prod: not started: blocked by company policy: lox.image_min.locksql = v0.18.0 (the image's release is unknown") {
		t.Errorf("unknown release: %v\n%s", err, out)
	}
	var b strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000", Run: &fake{keys: f.keys}, Out: &b, Focus: "crm-prod"}
	if err := u.Do(context.Background()); err == nil || !strings.Contains(err.Error(), "lox.image_min.locksql") {
		t.Errorf("lox add of the lock: %v\n%s", err, b.String())
	}
}

// [lox] egress: an endpoint outside it keeps its lock from starting.
func TestManagedEgress(t *testing.T) {
	withManaged(t, "version = 1\n[lox]\negress = [\"*.allowed.internal:5432\", \"mq.allowed.internal:*\"]\n")
	w := newWS(t, yamlConf(""))
	ws := filepath.Dir(filepath.Dir(w.file))
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db.other.internal\"\n"), 0o644)
	os.WriteFile(filepath.Join(ws, ".lockmq", "config.toml"), []byte("[profiles.e]\nurl = \"https://mq.allowed.internal:15671\"\n"), 0o644)
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, s := range []string{"lock crm-prod: not started: blocked by company policy: lox.egress does not allow db.other.internal:5432 (lock crm-prod)", "lock events: started"} {
		if !strings.Contains(out, s) {
			t.Errorf("no %q:\n%s", s, out)
		}
	}
	// Inside it: started.
	os.WriteFile(filepath.Join(ws, ".locksql", "config.toml"), []byte("[profiles.p]\nengine = \"postgres\"\nhost = \"db.allowed.internal\"\n"), 0o644)
	out, err = w.up("y\n", &fake{keys: f.keys})
	if err != nil || !strings.Contains(out, "lock crm-prod: started") {
		t.Errorf("inside the allowlist: %v\n%s", err, out)
	}
}

func TestEgressPatterns(t *testing.T) {
	pats := []string{"*.allowed.internal:5432", "vault.example.com:*", "exact.internal:443"}
	for _, tc := range []struct {
		host string
		port int
		ok   bool
	}{
		{"db.allowed.internal", 5432, true},
		{"a.b.allowed.internal", 5432, true},
		{"allowed.internal", 5432, false},
		{"db.allowed.internal", 5433, false},
		{"evilallowed.internal", 5432, false},
		{"vault.example.com", 8200, true},
		{"Exact.Internal.", 443, true},
		{"exact.internal", 444, false},
	} {
		if got := egressAllowed(pats, tc.host, tc.port); got != tc.ok {
			t.Errorf("%s:%d: %v, want %v", tc.host, tc.port, got, tc.ok)
		}
	}
	if !egressAllowed([]string{"*:*"}, "any.where", 1) {
		t.Error("*:* refuses")
	}
}

// A signed file goes to the locks with its bundle, signer.toml and the
// stamp that stands for the signature check in their containers.
func TestManagedSignedTar(t *testing.T) {
	dir := withManaged(t, managedBody)
	stamp := signManaged(t, dir)
	m, err := LoadManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !m.File.Signed || !strings.HasSuffix(m.Line(), " signed") || m.Fingerprint() != stamp {
		t.Errorf("signed: %v %q %s", m.File.Signed, m.Line(), m.Fingerprint())
	}
	files := tarFiles(t, m.Tar())
	if len(files) != 4 || files[managed.VerifiedName] != stamp+"\n" || files[managed.BundleName] == "" || files[managed.SignerName] == "" {
		t.Errorf("tar: %v", files)
	}
	// What the locks read back from that copy, lockkit's own check: the
	// stamp matches, so the signature counts as verified.
	cp := t.TempDir()
	for n, c := range files {
		os.WriteFile(filepath.Join(cp, n), []byte(c), 0o644)
	}
	managed.SetTestPath(filepath.Join(cp, managed.FileName))
	if f, err := managed.Load(context.Background()); err != nil || !f.Signed {
		t.Errorf("the copy as a lock reads it: %v %v", f, err)
	}
}

// --no-upgrade under allow_no_upgrade = false.
func TestManagedNoUpgrade(t *testing.T) {
	withManaged(t, "version = 1\n[lox]\nallow_no_upgrade = false\n")
	m, err := LoadManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var me *ManagedError
	if err := m.CheckNoUpgrade(); !errors.As(err, &me) || !strings.Contains(err.Error(), "blocked by company policy: lox.allow_no_upgrade = false") {
		t.Errorf("--no-upgrade: %v", err)
	}
	var none *Managed
	if none.CheckNoUpgrade() != nil {
		t.Error("no file refuses --no-upgrade")
	}
}

// [family] vault takes the place of the workspace's vault: block.
func TestManagedVault(t *testing.T) {
	withManaged(t, "version = 1\n[family]\nvault = { address = \"https://vault.acme.internal:8200\", namespace = \"ops\", required = true }\n")
	conf := strings.Replace(yamlConf(""), "    type: locksql\n", "    type: locksql\n    vault: true\n", 1) + "vault:\n  address: https://vault.mine.internal:8200\n"
	w := newWS(t, conf)
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	svc := block(f.upCompose, "lock-crm-prod")
	if !strings.Contains(svc, `VAULT_ADDR: "https://vault.acme.internal:8200"`) || !strings.Contains(svc, `VAULT_NAMESPACE: "ops"`) {
		t.Errorf("lock-crm-prod:\n%s", svc)
	}
	b, _ := os.ReadFile(filepath.Join(w.dir, "state", "applied.json"))
	if !strings.Contains(string(b), "vault from the managed configuration ([family] vault): https://vault.acme.internal:8200 namespace ops, required") {
		t.Errorf("not reviewed:\n%s", b)
	}
}

func TestManagedShow(t *testing.T) {
	var none *Managed
	if s := none.Show(); len(s) != 1 || s[0] != "no managed configuration" {
		t.Errorf("none: %v", s)
	}
	withManaged(t, managedBody+"[lox]\nauto_max = { write = \"ask\" }\nallow_no_upgrade = false\negress = [\"*.internal:5432\"]\n")
	m, err := LoadManaged(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(m.Show(), "\n")
	for _, s := range []string{"Managed by Acme (sha256:", "organisation: Acme", "signed: no", "  auto_max.write = ask", "  allow_no_upgrade = false", "  egress = *.internal:5432", "sections: locksql"} {
		if !strings.Contains(got, s) {
			t.Errorf("no %q:\n%s", s, got)
		}
	}
}

func TestDoctorManagedLine(t *testing.T) {
	d, _ := healthy(t)
	withManaged(t, managedBody)
	if out, _ := doc(t, d); !strings.Contains(out, "ok   managed: Managed by Acme (sha256:") {
		t.Errorf("doctor:\n%s", out)
	}
	withManaged(t, "version = 2\n")
	if out, n := doc(t, d); n == 0 || !strings.Contains(out, "FAIL managed: ") {
		t.Errorf("refused file: %d\n%s", n, out)
	}
}
