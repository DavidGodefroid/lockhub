package loxadd

import (
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// lox add lockssh asks one SSH host and login: the key and known_hosts
// are files of the lock's account, the allow rules are split on ";" into
// one --allow each, exec is a flag.
func TestLocksshQuestions(t *testing.T) {
	fs := fieldsOf(t, "lockssh", Defaults{})
	keysOf := func(a Answers) string {
		var keys []string
		for _, f := range fs {
			if f.When == nil || f.When(a) {
				keys = append(keys, f.Key)
			}
		}
		return strings.Join(keys, " ")
	}
	if got := keysOf(Answers{"auth": "key", "credentials": "none"}); got != "host port user auth key known-hosts allow exec production credentials name" {
		t.Errorf("key auth asks %q", got)
	}
	if got := keysOf(Answers{"auth": "password", "credentials": "vault"}); got != "host port user auth known-hosts allow exec production credentials vault-path vault-address vault-namespace vault-ca name" {
		t.Errorf("password auth asks %q", got)
	}
	for key, want := range map[string]string{
		"host":        "SSH host, a name (host.docker.internal for this machine) (required): ",
		"port":        "Port (required) [22]: ",
		"user":        "Login (required): ",
		"key":         "Private key file in the lock's home (~/ is its home; lox run offers to copy yours there) (required) [~/.ssh/id_ed25519]: ",
		"known-hosts": "Known hosts file in the lock's home (optional: empty = the console's own: a new host key is confirmed at the console): ",
		"allow":       "Allowed commands, separated by ;, such as uptime; df -h; systemctl status * (optional: empty = none yet (edit .lockssh/config.toml)): ",
		"exec":        "May the agent ask for other commands (each one approved on a ticket)? [y/N] ",
		"credentials": "Credentials: none (an unencrypted key), ask (typed at the console's start) or vault (required) [none]: ",
	} {
		if got := Prompt(find(t, fs, key, Answers{"auth": "key"})); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}
	if got := Prompt(find(t, fs, "credentials", Answers{"auth": "password"})); got != "Credentials: ask (the password typed at the console's start) or vault (required) [ask]: " {
		t.Errorf("password credentials %q", got)
	}
	if got := Prompt(find(t, fs, "vault-path", Answers{"credentials": "vault"})); got != "Vault path (required) [secret/data/lockssh/ssh]: " {
		t.Errorf("vault path %q", got)
	}
	k := find(t, fs, "key", Answers{"auth": "key"})
	for _, v := range []string{"~/.ssh/id_ed25519", "/home/lockssh/k"} {
		if r := k.Check(v, nil); r != "" {
			t.Errorf("key %q refused: %s", v, r)
		}
	}
	for _, v := range []string{"id_ed25519", "~/.ssh/", "~/a b", "~/k\n"} {
		if r := k.Check(v, nil); !strings.HasPrefix(r, "key:") {
			t.Errorf("key %q: %q", v, r)
		}
	}
	h := find(t, fs, "host", nil)
	for _, v := range []string{"10.0.0.5", "user@web1", "web1:22", "ssh://web1"} {
		if h.Check(v, nil) == "" {
			t.Errorf("host %q accepted", v)
		}
	}
	al := find(t, fs, "allow", nil)
	if al.Check(" ; ", nil) == "" || al.Check("uptime; df -h", nil) != "" {
		t.Error("allow rules")
	}
}

func TestLocksshProfileArgs(t *testing.T) {
	l, err := Build("lockssh", Answers{"name": "web", "host": "web1.example.com", "port": "22", "user": "deploy", "auth": "key",
		"key": "~/.ssh/id_ed25519", "allow": "uptime; df -h ;; systemctl status *", "exec": "y", "production": "n", "credentials": "none"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"profile", "add", "--non-interactive", "--json", "--project", "/p", "--profile", "web", "--credentials", "none",
		"--host", "web1.example.com", "--port", "22", "--user", "deploy", "--auth", "key", "--key", "~/.ssh/id_ed25519",
		"--allow", "uptime", "--allow", "df -h", "--allow", "systemctl status *", "--exec"}
	if got := l.ProfileArgs("/p"); !slices.Equal(got, want) {
		t.Errorf("argv\n got %q\nwant %q", got, want)
	}
	l, err = Build("lockssh", Answers{"name": "db", "host": "db1", "user": "ops", "auth": "password", "exec": "n", "credentials": "vault",
		"vault-path": "secret/data/lockssh/db", "production": "y"})
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"profile", "add", "--non-interactive", "--json", "--project", "/p", "--profile", "db", "--credentials", "vault",
		"--vault-path", "secret/data/lockssh/db", "--production", "--host", "db1", "--user", "ops", "--auth", "password"}
	if got := l.ProfileArgs("/p"); !slices.Equal(got, want) {
		t.Errorf("password argv\n got %q\nwant %q", got, want)
	}
	for name, a := range map[string]Answers{
		"no host": {"name": "web", "user": "deploy", "key": "~/k"},
		"no user": {"name": "web", "host": "web1", "key": "~/k"},
		"no key":  {"name": "web", "host": "web1", "user": "deploy", "auth": "key"},
	} {
		if _, err := Build("lockssh", a); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

// A host of ~/.ssh/config gives the defaults.
func TestLocksshDefaultsFromSSHConfig(t *testing.T) {
	s := loxinit.Source{Kind: loxinit.KindSSH, Name: "Web1", Host: "web1.example.com", User: "deploy", Port: 2222}
	fs := fieldsOf(t, "lockssh", Defaults{Source: &s})
	for key, want := range map[string]string{"host": "web1.example.com", "user": "deploy", "port": "2222", "name": "web1"} {
		if got := find(t, fs, key, nil).Default; got != want {
			t.Errorf("%s default %q, want %q", key, got, want)
		}
	}
	if UIDsFor("lockssh", true, 1000) == nil || UIDsFor("lockssh", true, 10041) != nil {
		t.Error("lockssh allowed_uids for lea")
	}
}
