package family

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The copy of lockfile's seccomp.json (lockfile v0.3.0 to v0.7.0). A new
// digest is a deliberate change: copy lockfile's file and update it here.
const lockfileSeccompPinned = "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"

func TestLockfileSeccompIsLockfiles(t *testing.T) {
	if LockfileSeccompSum != lockfileSeccompPinned {
		t.Fatalf("lockfile-seccomp.json sha256 %s, pinned %s: copy lockfile's seccomp.json byte for byte and update the pin", LockfileSeccompSum, lockfileSeccompPinned)
	}
	var p struct {
		DefaultAction string            `json:"defaultAction"`
		Syscalls      []json.RawMessage `json:"syscalls"`
	}
	if err := json.Unmarshal(LockfileSeccomp, &p); err != nil {
		t.Fatal(err)
	}
	// A deny-by-default list, never an unconfined one; it allows the
	// plugin sandbox's own calls (Landlock).
	if p.DefaultAction != "SCMP_ACT_ERRNO" || len(p.Syscalls) == 0 {
		t.Fatalf("not a deny-by-default profile: %q, %d rules", p.DefaultAction, len(p.Syscalls))
	}
	for _, sc := range []string{"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "seccomp"} {
		if !strings.Contains(string(LockfileSeccomp), `"`+sc+`"`) {
			t.Errorf("profile does not allow %s", sc)
		}
	}
}

func seccompComposeConf(t *testing.T) *Config {
	t.Helper()
	conf := `version: 1
hub:
  image: ` + hubImg + `
locks:
  docs:
    type: lockfile
    image: ` + fileImg + `
  orders:
    type: locksql
    image: ` + sqlImg + `
`
	c, err := decode([]byte(conf), filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestComposeLockfileSeccomp(t *testing.T) {
	c := seccompComposeConf(t)
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0", Seccomp: "/s/lockfile-seccomp.json", SeccompSum: "abcd"})
	docs := service(out, "lock-docs")
	for _, want := range []string{
		`    security_opt: ["no-new-privileges:true", "seccomp=/s/lockfile-seccomp.json"]`,
		`      lockfamily.seccomp: "abcd"`,
	} {
		if !strings.Contains(docs, want) {
			t.Errorf("lock-docs lacks %q:\n%s", want, docs)
		}
	}
	if strings.Count(out, "seccomp=") != 1 || strings.Count(out, "lockfamily.seccomp") != 1 {
		t.Errorf("seccomp on a service other than lock-docs:\n%s", out)
	}
	for _, other := range []string{"lockhub", "lock-orders", "hubkey"} {
		if s := service(out, other); s == "" || strings.Contains(s, "seccomp") || !strings.Contains(s, `security_opt: ["no-new-privileges:true"]`) {
			t.Errorf("%s: empty, or its security_opt changed:\n%s", other, s)
		}
	}
	// Never unconfined.
	if strings.Contains(out, "unconfined") {
		t.Errorf("unconfined in the compose:\n%s", out)
	}
	// No copy yet (the key stage before the review): Docker's default.
	out = Compose(c, Paths{Workspace: "/w", User: "0:0"})
	if strings.Contains(out, "seccomp") {
		t.Errorf("seccomp without its copy:\n%s", out)
	}
}

func seccompFake() *fake {
	f := newFake()
	f.keys["docs"], f.keys["orders"] = pubKey(), pubKey()
	return f
}

func TestUpRunsLockfileUnderItsSeccomp(t *testing.T) {
	w := newWS(t, "version: 1\nhub:\n  image: "+hubImg+"\nlocks:\n  docs:\n    type: lockfile\n    image: "+fileImg+"\n")
	copyPath := filepath.Join(w.dir, "state", lockfileSeccompFile)
	line := "lock docs seccomp lockfile's shipped profile sha256:" + lockfileSeccompPinned

	// Declined: nothing written.
	out, err := w.up("n\n", seccompFake())
	if err == nil || !strings.Contains(out, line) {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatalf("copy written before the yes: %v", err)
	}

	f := seccompFake()
	out, err = w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, line) {
		t.Errorf("the review does not show the seccomp profile:\n%s", out)
	}
	b, err := os.ReadFile(copyPath)
	if err != nil || string(b) != string(LockfileSeccomp) {
		t.Fatalf("copy: %v", err)
	}
	if fi, _ := os.Stat(copyPath); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	if !strings.Contains(service(f.upCompose, "lock-docs"), `"seccomp=`+copyPath+`"`) {
		t.Errorf("up compose does not run lock-docs under the copy:\n%s", f.upCompose)
	}

	// The lockfile lock removed: the copy goes.
	os.WriteFile(w.file, []byte("version: 1\nhub:\n  image: "+hubImg+"\nlocks:\n  orders:\n    type: locksql\n    image: "+sqlImg+"\n"), 0o644)
	if out, err := w.up("y\n", seccompFake()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Errorf("copy kept without a lockfile lock: %v", err)
	}
}
