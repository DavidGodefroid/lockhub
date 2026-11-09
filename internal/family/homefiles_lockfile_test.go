package family

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// lockhub#174: a lockfile sftp profile names its known_hosts (and, with
// auth = "key", its key); no other source reads a file.
func TestProfileFileKeysLockfile(t *testing.T) {
	p := tomlProfile(`[profiles.drop]`, `source = "sftp"`, `host = "h"`, `user = "u"`, `auth = "key"`,
		`key = "~/.ssh/id"`, `known_hosts = "~/.config/lockfile/known_hosts"`)
	want := []FileKey{{"known_hosts", "~/.config/lockfile/known_hosts"}, {"key", "~/.ssh/id"}}
	if got, odd := ProfileFileKeys(p, "lockfile", "drop"); !reflect.DeepEqual(got, want) || odd != nil {
		t.Errorf("key auth: %v %v", got, odd)
	}
	p = tomlProfile(`[profiles.drop]`, `source = "sftp"`, `auth = "password"`, `key = "~/.ssh/id"`, `known_hosts = "/kh"`)
	if got, _ := ProfileFileKeys(p, "lockfile", ""); !reflect.DeepEqual(got, []FileKey{{"known_hosts", "/kh"}}) {
		t.Errorf("password auth: %v", got)
	}
	p = tomlProfile(`[profiles.docs]`, `source = "s3"`, `bucket = "b"`, `known_hosts = "/kh"`)
	if got, odd := ProfileFileKeys(p, "lockfile", ""); got != nil || odd != nil {
		t.Errorf("s3: %v %v", got, odd)
	}
}

const fileConf = `version: 1
hub:
  image: ` + hubImg + `
locks:
  drop:
    type: lockfile
    image: ` + fileImg + `
    profile: drop
`

func fileWS(t *testing.T, profile string) (ws, *fake, string) {
	w := newWS(t, fileConf)
	dir := filepath.Join(w.dir, "projects", ".lockfile")
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[profiles.drop]\nsource = \"sftp\"\nhost = \"h\"\nuser = \"u\"\nauth = \"password\"\ncredentials = \"ask\"\n"+profile), 0o644)
	f := newFake()
	f.keys["drop"] = pubKey()
	return w, f, dir
}

// The path lox add writes, ~/.config/lockfile/known_hosts, is the
// console's copy of the profile: checked in the reviewed copy, nothing
// run in the container.
func TestReviewLockfileKnownHostsInProfile(t *testing.T) {
	w, f, dir := fileWS(t, "known_hosts = \"~/.config/lockfile/known_hosts\"\n")
	os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("h ssh-ed25519 AAAA\n"), 0o600)
	f.keys["homefiles/drop"] = "missing\n"
	out, err := w.up("y\n", f)
	if err != nil || strings.Contains(out, "WARNING") || strings.Contains(out, "warning:") || f.ran("homefiles-") {
		t.Fatalf("%v %v\n%s", err, f.calls, out)
	}
	// The homefiles service sees the profile where the console does, and
	// has no working directory in the workspace (the console has none).
	for _, want := range []string{`"homefiles-drop":`, `"profile-lockfile:/home/lockfile/.config/lockfile:ro"`} {
		if !strings.Contains(f.upCompose, want) {
			t.Errorf("compose lacks %s:\n%s", want, f.upCompose)
		}
	}
	if svc := block(f.upCompose, "homefiles-drop"); strings.Contains(svc, "working_dir:") {
		t.Errorf("homefiles-drop has a working directory:\n%s", svc)
	}
	// Not in the copy: said before the start.
	os.Remove(filepath.Join(dir, "known_hosts"))
	f2 := &fake{keys: f.keys}
	out, err = w.up("y\n", f2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "WARNING: known_hosts: /home/lockfile/.config/lockfile/known_hosts (~/.config/lockfile/known_hosts) is not in the profile's directory: write it " + filepath.Join(dir, "known_hosts") + " (the review copies it)"
	if !strings.Contains(out, want) {
		t.Errorf("review lacks %q:\n%s", want, out)
	}
}

// The paths the issue found: the workspace's .lockfile (which the console
// never sees) and any other host path. Both are said, with the path to
// write; a path into the workspace's copy is not asked of the container.
func TestReviewLockfileHostPaths(t *testing.T) {
	w, f, dir := fileWS(t, "")
	cfg := filepath.Join(dir, "config.toml")
	b, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, append(b, []byte("known_hosts = \""+filepath.Join(dir, "known_hosts")+"\"\n")...), 0o644)
	os.WriteFile(filepath.Join(dir, "known_hosts"), []byte("h ssh-ed25519 AAAA\n"), 0o600)
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "known_hosts: " + filepath.Join(dir, "known_hosts") + " is the workspace's path, which the console does not see: write it ~/.config/lockfile/known_hosts (its copy of the profile)"
	if !strings.Contains(out, want) || f.ran("homefiles-") {
		t.Errorf("review lacks %q (or ran homefiles: %v):\n%s", want, f.calls, out)
	}

	w, f, _ = fileWS(t, "known_hosts = \"/home/david/lf-e2e/known_hosts_sftp\"\n")
	f.keys["homefiles/drop"] = "missing\n"
	out, err = w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want = "known_hosts: /home/david/lf-e2e/known_hosts_sftp not found in the lock's container; copy it to .lockfile/known_hosts_sftp and write it ~/.config/lockfile/known_hosts_sftp (the console's copy of the profile)"
	if !strings.Contains(out, want) {
		t.Errorf("review lacks %q:\n%s", want, out)
	}
	// Not offered a copy into the home volume.
	if !strings.Contains(out, "known_hosts_sftp") || strings.Contains(out, "copy it there: docker run") {
		t.Errorf("a home copy offered:\n%s", out)
	}
}
