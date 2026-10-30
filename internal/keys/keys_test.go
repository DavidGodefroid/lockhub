package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hub.key")
	pub, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(p); err == nil {
		t.Error("overwrote an existing key")
	}
	priv, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("loaded key does not match")
	}
	os.Chmod(p, 0o640)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("group-readable key: %v", err)
	}
}

func TestLoadLocks(t *testing.T) {
	k1, _, _ := ed25519.GenerateKey(rand.Reader)
	k2, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "locks.json")
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	ok := `{"locks":{"crm-prod":{"public_key":"` + Public(k1) + `"},"files":{"public_key":"` + Public(k2) + `"}}}`
	m, err := LoadLocks(write(ok))
	if err != nil || len(m) != 2 || !m["crm-prod"].Equal(k1) {
		t.Fatalf("LoadLocks = %v, %v", m, err)
	}
	for name, s := range map[string]string{
		"empty":       `{"locks":{}}`,
		"bad name":    `{"locks":{"Bad Name":{"public_key":"` + Public(k1) + `"}}}`,
		"bad key":     `{"locks":{"a":{"public_key":"abcd"}}}`,
		"unknown key": `{"locks":{"a":{"public_key":"` + Public(k1) + `","x":1}}}`,
		"shared key":  `{"locks":{"a":{"public_key":"` + Public(k1) + `"},"b":{"public_key":"` + Public(k1) + `"}}}`,
		"not json":    `{`,
	} {
		if _, err := LoadLocks(write(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadOrCreateP256(t *testing.T) {
	p := filepath.Join(t.TempDir(), VAPIDFile)
	k, err := LoadOrCreateP256(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	again, err := LoadOrCreateP256(p)
	if err != nil || !again.Equal(k) {
		t.Fatalf("second load: a different key (%v)", err)
	}
	os.Chmod(p, 0o640)
	if _, err := LoadOrCreateP256(p); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("group-readable key: %v", err)
	}
	// An Ed25519 key is not a VAPID key.
	ed := filepath.Join(t.TempDir(), "hub.key")
	if _, err := Generate(ed); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateP256(ed); err == nil {
		t.Error("loaded an Ed25519 key as P-256")
	}
}

func TestRetired(t *testing.T) {
	dir := t.TempDir()
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	cur, _, _ := ed25519.GenerateKey(rand.Reader)
	if ks, err := LoadRetired(dir, cur); err != nil || ks != nil {
		t.Errorf("none: %v %v", ks, err)
	}
	w := func(s string) { os.WriteFile(filepath.Join(dir, RetiredFile), []byte(s), 0o644) }
	w(string(FormatPublics([]ed25519.PublicKey{a, b})) + "\n")
	if ks, err := LoadRetired(dir, cur); err != nil || len(ks) != 2 || !ks[0].Equal(a) || !ks[1].Equal(b) {
		t.Errorf("two: %v %v", ks, err)
	}
	// A rotation that retired cur, then stopped before hub.key changed.
	w(string(FormatPublics([]ed25519.PublicKey{a, cur})))
	if ks, err := LoadRetired(dir, cur); err != nil || len(ks) != 1 {
		t.Errorf("cur last: %v %v", ks, err)
	}
	for name, s := range map[string]string{
		"cur first": string(FormatPublics([]ed25519.PublicKey{cur, a})),
		"twice":     string(FormatPublics([]ed25519.PublicKey{a, a})),
		"junk":      "nope\n",
	} {
		w(s)
		if _, err := LoadRetired(dir, cur); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
