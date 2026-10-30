package chatconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, File)
	if s, err := Load(p); err != nil || s.Slack != nil {
		t.Fatalf("missing: %v %+v", err, s)
	}
	os.WriteFile(p, []byte(`{"slack":{"team":"T01","channel":"C02","users":["U03"]}}`), 0o600)
	if s, err := Load(p); err != nil || s.Slack.Users[0] != "U03" {
		t.Fatalf("%v %+v", err, s)
	}
	for _, bad := range []string{
		`{"slack":{"team":"T01","channel":"C02","users":[]}}`,
		`{"slack":{"team":"x","channel":"C02","users":["U03"]}}`,
		`{"slack":{"team":"T01","channel":"#general","users":["U03"]}}`,
		`{"slack":{"team":"T01","channel":"C02","users":["@david"]}}`,
		`{"slack":{"team":"T01","channel":"C02","users":["U03"],"extra":1}}`,
	} {
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, SlackBotToken)
	os.WriteFile(p, []byte("xoxb-1\n"), 0o600)
	if s, err := ReadSecret(p); err != nil || s != "xoxb-1" {
		t.Fatalf("%q %v", s, err)
	}
	os.Chmod(p, 0o640)
	if _, err := ReadSecret(p); err == nil {
		t.Error("group-readable secret accepted")
	}
	os.Chmod(p, 0o600)
	l := filepath.Join(dir, "link")
	os.Symlink(p, l)
	if _, err := ReadSecret(l); err == nil {
		t.Error("link accepted")
	}
	os.WriteFile(p, []byte("a b\n"), 0o600)
	if _, err := ReadSecret(p); err == nil {
		t.Error("two words accepted")
	}
}
