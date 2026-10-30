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
