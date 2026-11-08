package loxinit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// SSHHosts proposes the plain Host blocks of ~/.ssh/config: their name,
// HostName, User and Port; never a pattern, a host behind a bastion, an
// IP address, or a value of another key.
func TestSSHHosts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(`# mine
Host *
  ServerAliveInterval 30
Host web1
  HostName web1.example.com
  User deploy
  IdentityFile ~/.ssh/id_web
Host db
  HostName=db.internal
  Port 2222
Host behind
  HostName app.internal
  ProxyJump bastion
Host ip
  HostName 10.0.0.5
Host a b
  HostName two.example.com
Match host x
  User nobody
Host "quoted"
  HostName q.example.com
  PasswordAuthentication yes
`), 0o600)
	got := SSHHosts(p)
	want := []Source{
		{Kind: KindSSH, Name: "web1", Host: "web1.example.com", User: "deploy", Port: 22, From: []string{"~/.ssh/config (Host web1)"},
			Notes: []string{"the key file goes in the lock's home: lox run offers to copy yours there (IdentityFile ~/.ssh/id_web)"}},
		{Kind: KindSSH, Name: "db", Host: "db.internal", Port: 2222, From: []string{"~/.ssh/config (Host db)"},
			Notes: []string{"the key file goes in the lock's home: lox run offers to copy yours there"}},
		{Kind: KindSSH, Name: "quoted", Host: "q.example.com", Port: 22, From: []string{"~/.ssh/config (Host quoted)"},
			Notes: []string{"the key file goes in the lock's home: lox run offers to copy yours there"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
	if got[0].Lock() != "lockssh" || got[0].Target() != "deploy@web1.example.com:22" || got[0].Label() != "SSH" {
		t.Errorf("source %s %s %s", got[0].Lock(), got[0].Target(), got[0].Label())
	}
	var b strings.Builder
	RenderHints(&b, got[:1])
	if !strings.Contains(b.String(), "found: ssh on deploy@web1.example.com:22 (~/.ssh/config) → `lox add lockssh`") {
		t.Errorf("hint:\n%s", b.String())
	}
	if SSHHosts(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Error("a missing file")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(p, link)
	if SSHHosts(link) != nil {
		t.Error("a link is followed")
	}
}
