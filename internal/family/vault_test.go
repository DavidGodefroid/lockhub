package family

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const lockHTTPImg = "ghcr.io/davidgodefroid/lockhttp@sha256:5555555555555555555555555555555555555555555555555555555555555555"

func vaultConf(vault, lockExtra string) string {
	return `version: 1
hub:
  image: ` + hubImg + `
` + vault + `locks:
  shop:
    type: locksql
    image: ` + sqlImg + `
` + lockExtra
}

func loadVaultConf(t *testing.T, conf string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return decode([]byte(conf), path)
}

func TestVaultBlockParses(t *testing.T) {
	c, err := loadVaultConf(t, vaultConf("vault:\n  address: https://vault.example.com:8200\n  namespace: shop\n  ca_file: /etc/ssl/shop-ca.pem\n", "    vault: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault == nil || c.Vault.Address != "https://vault.example.com:8200" || c.Vault.Namespace != "shop" || c.Vault.CAFile != "/etc/ssl/shop-ca.pem" {
		t.Errorf("vault %+v", c.Vault)
	}
	if !c.Locks["shop"].Vault {
		t.Error("lock vault flag lost")
	}
}

func TestVaultAddressRefusesLoopback(t *testing.T) {
	loop := "vault.address: 127.0.0.1 and localhost are the console's own container: use host.docker.internal for this machine"
	shape := "vault.address: want http(s)://host[:port], no path or user info"
	for addr, want := range map[string]string{
		"http://127.0.0.1:8200":             loop,
		"https://localhost:8200":            loop,
		"http://LocalHost":                  loop,
		"http://[::1]:8200":                 loop,
		"http://host.docker.internal:8200":  "",
		"https://vault.example.com":         "",
		"vault.example.com":                 shape,
		"ftp://vault.example.com":           shape,
		"https://vault.example.com/v1":      shape,
		"https://user:pw@vault.example.com": shape,
		"https://vault.example.com?x=1":     shape,
		"":                                  shape,
	} {
		v := Vault{Address: addr}
		err := v.validate()
		switch {
		case want == "" && err != nil:
			t.Errorf("%q refused: %v", addr, err)
		case want != "" && (err == nil || err.Error() != want):
			t.Errorf("%q: got %v, want %q", addr, err, want)
		}
	}
	caMsg := "vault.ca_file: an absolute path to a PEM file of yours, at most 64 KiB"
	v := Vault{Address: "https://vault.example.com", CAFile: "ca.pem"}
	if err := v.validate(); err == nil || err.Error() != caMsg {
		t.Errorf("relative ca_file: %v", err)
	}
	big := filepath.Join(t.TempDir(), "big.pem")
	os.WriteFile(big, []byte(strings.Repeat("x", 64*1024+1)), 0o644)
	v = Vault{Address: "https://vault.example.com", CAFile: big}
	if err := v.validate(); err == nil || err.Error() != caMsg {
		t.Errorf("big ca_file: %v", err)
	}
}

func TestVaultLockNeedsBlock(t *testing.T) {
	_, err := loadVaultConf(t, vaultConf("", "    vault: true\n"))
	if err == nil || !strings.Contains(err.Error(), "locks.shop.vault: set, but lockfamily.yaml has no vault: block (lox vault set --address URL)") {
		t.Errorf("got %v", err)
	}
}

func TestVaultRefusedOnLockhttp(t *testing.T) {
	conf := vaultConf("vault:\n  address: https://vault.example.com\n", "  web:\n    type: lockhttp\n    image: "+lockHTTPImg+"\n    vault: true\n")
	_, err := loadVaultConf(t, conf)
	if err == nil || !strings.Contains(err.Error(), "locks.web.vault: a lockhttp lock reads no secret") {
		t.Errorf("got %v", err)
	}
}

func TestSetVaultKeepsComments(t *testing.T) {
	w := newWS(t, "# my workspace\n"+yamlConf(""))
	if err := SetVault(w.file, Vault{Address: "https://vault.example.com", Namespace: "shop"}); err != nil {
		t.Fatal(err)
	}
	if err := SetVault(w.file, Vault{Address: "http://host.docker.internal:8200"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.file)
	if !strings.Contains(string(b), "# my workspace") {
		t.Errorf("comment lost:\n%s", b)
	}
	if strings.Count(string(b), "vault:") != 1 || strings.Contains(string(b), "namespace") {
		t.Errorf("vault block not replaced:\n%s", b)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault == nil || c.Vault.Address != "http://host.docker.internal:8200" {
		t.Errorf("vault %+v", c.Vault)
	}
	before, _ := os.ReadFile(w.file)
	if err := SetVault(w.file, Vault{Address: "http://localhost:8200"}); err == nil {
		t.Fatal("loopback accepted")
	}
	if after, _ := os.ReadFile(w.file); string(after) != string(before) {
		t.Error("file changed on refusal")
	}
}

func TestAddWritesVaultTrue(t *testing.T) {
	w := newWS(t, yamlConf(""))
	if err := SetVault(w.file, Vault{Address: "https://vault.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := Add(w.file, AddOptions{Type: "lockfile", Name: "docs", Image: fileImg, Vault: true}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Locks["docs"].Vault || c.Locks["crm-prod"].Vault {
		t.Errorf("vault flags: docs=%v crm-prod=%v", c.Locks["docs"].Vault, c.Locks["crm-prod"].Vault)
	}
}
