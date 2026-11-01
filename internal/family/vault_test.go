package family

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	v = Vault{Address: "https://vault.example.com", CAFile: t.TempDir()}
	if err := v.validate(); err == nil || err.Error() != caMsg {
		t.Errorf("directory ca_file: %v", err)
	}
	v = Vault{Address: "https://vault.example.com/"}
	if err := v.validate(); err == nil || err.Error() != shape {
		t.Errorf("trailing slash: %v", err)
	}
}

func TestAddVaultRefusedOnLockhttp(t *testing.T) {
	w := newWS(t, yamlConf(""))
	if err := SetVault(w.file, Vault{Address: "https://vault.example.com"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(w.file)
	err := Add(w.file, AddOptions{Type: "lockhttp", Name: "web", Image: lockHTTPImg, Vault: true})
	if err == nil || !strings.Contains(err.Error(), "locks.web.vault: a lockhttp lock reads no secret") {
		t.Errorf("got %v", err)
	}
	if after, _ := os.ReadFile(w.file); string(after) != string(before) {
		t.Error("file changed on refusal")
	}
}

func TestSetVaultKeepsOtherKeysAndComments(t *testing.T) {
	conf := `# top comment
version: 1
hub:
  image: ` + hubImg + `  # hub pin
  facades: [tty, deck]
vault:
  address: https://old.example.com # old vault
  namespace: old
locks:
  # the shop lock
  shop:
    type: locksql
    image: ` + sqlImg + `
    profile: main # its profile
    vault: true
  # the queue
  events:
    type: lockmq
    image: ` + mqImg + `
`
	w := newWS(t, conf)
	if err := SetVault(w.file, Vault{Address: "https://vault.example.com", CAFile: "/etc/ssl/shop-ca.pem"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.file)
	s := string(b)
	for _, want := range []string{"# top comment", "# hub pin", "# the shop lock", "# its profile", "# the queue", "facades: [tty, deck]", "profile: main", "vault: true", "type: lockmq"} {
		if !strings.Contains(s, want) {
			t.Errorf("lost %q:\n%s", want, s)
		}
	}
	if strings.Count(s, "\nvault:") != 1 || strings.Contains(s, "old.example.com") || strings.Contains(s, "namespace") {
		t.Errorf("vault block not replaced once:\n%s", s)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault.Address != "https://vault.example.com" || c.Vault.CAFile != "/etc/ssl/shop-ca.pem" || c.Locks["shop"].Profile != "main" || !c.Locks["shop"].Vault || c.Locks["events"].Vault {
		t.Errorf("config %+v %+v", c.Vault, c.Locks)
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

const caPEM = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"

func vaultComposeConf(t *testing.T, vault string) *Config {
	t.Helper()
	conf := `version: 1
hub:
  image: ` + hubImg + `
` + vault + `locks:
  orders:
    type: locksql
    image: ` + sqlImg + `
    vault: true
  events:
    type: lockmq
    image: ` + mqImg + `
`
	c, err := decode([]byte(conf), filepath.Join(t.TempDir(), FileName))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// service returns the compose text of one service (up to the next one).
func service(out, name string) string {
	_, rest, _ := strings.Cut(out, "\n  "+name+":\n")
	for i, l := range strings.Split(rest, "\n") {
		if l != "" && !strings.HasPrefix(l, "   ") {
			return strings.Join(strings.Split(rest, "\n")[:i], "\n")
		}
	}
	return rest
}

func TestComposeVaultEnv(t *testing.T) {
	c := vaultComposeConf(t, "vault:\n  address: https://vault.example.com:8200\n  namespace: shop\n")
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"})
	if got := strings.Count(out, "VAULT_ADDR"); got != 1 {
		t.Fatalf("VAULT_ADDR appears %d times:\n%s", got, out)
	}
	orders := service(out, "lock-orders")
	for _, want := range []string{`VAULT_ADDR: "https://vault.example.com:8200"`, `VAULT_NAMESPACE: "shop"`} {
		if !strings.Contains(orders, want) {
			t.Errorf("lock-orders lacks %q:\n%s", want, orders)
		}
	}
	for _, other := range []string{"lockhub", "lock-events", "hubkey"} {
		if s := service(out, other); s == "" || strings.Contains(s, "VAULT_") {
			t.Errorf("%s: empty or carries VAULT_*:\n%s", other, s)
		}
	}
	if strings.Contains(out, "VAULT_CACERT") || strings.Contains(out, "lockfamily-vault") || strings.Contains(out, "VAULT_TOKEN") {
		t.Errorf("CA or token without a CA copy:\n%s", out)
	}
	// No namespace: no VAULT_NAMESPACE.
	c = vaultComposeConf(t, "vault:\n  address: https://vault.example.com:8200\n")
	if strings.Contains(Compose(c, Paths{Workspace: "/w", User: "0:0"}), "VAULT_NAMESPACE") {
		t.Error("VAULT_NAMESPACE without a namespace")
	}
}

func TestComposeVaultCA(t *testing.T) {
	c := vaultComposeConf(t, "vault:\n  address: https://vault.example.com:8200\n")
	out := Compose(c, Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0", VaultCA: "/s/vault-ca.pem"})
	orders := service(out, "lock-orders")
	for _, want := range []string{`VAULT_CACERT: "/run/lockfamily-vault/ca.pem"`, "source: \"/s/vault-ca.pem\"\n        target: \"/run/lockfamily-vault/ca.pem\"\n        read_only: true"} {
		if !strings.Contains(orders, want) {
			t.Errorf("lock-orders lacks %q:\n%s", want, orders)
		}
	}
	if strings.Contains(service(out, "lock-events"), "vault") {
		t.Errorf("another lock gets the CA:\n%s", service(out, "lock-events"))
	}
}

func TestVaultCAChangeIsReviewed(t *testing.T) {
	w := newWS(t, "version: 1\nhub:\n  image: "+hubImg+"\nvault:\n  address: https://vault.example.com:8200\n  ca_file: CAFILE\nlocks:\n  crm-prod:\n    type: locksql\n    image: "+sqlImg+"\n    vault: true\n")
	ca := filepath.Join(w.dir, "ca.pem")
	conf, _ := os.ReadFile(w.file)
	os.WriteFile(w.file, []byte(strings.Replace(string(conf), "CAFILE", ca, 1)), 0o644)
	copyPath := filepath.Join(w.dir, "state", "vault-ca.pem")

	// A missing ca_file is refused before anything is applied.
	f := newFake()
	if _, err := w.up("y\n", f); err == nil || !strings.Contains(err.Error(), "vault.ca_file: an absolute path to a PEM file of yours, at most 64 KiB") || strings.Contains(err.Error(), ca) {
		t.Fatalf("missing ca_file: %v", err)
	}
	if f.ran("up -d") {
		t.Fatal("applied with a missing ca_file")
	}

	os.WriteFile(ca, []byte(caPEM), 0o644)
	sum := sha256.Sum256([]byte(caPEM))
	f = newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"lock crm-prod vault VAULT_ADDR=https://vault.example.com:8200", "vault ca_file " + ca + " sha256:" + hex.EncodeToString(sum[:])} {
		if !strings.Contains(out, want) {
			t.Errorf("review lacks %q:\n%s", want, out)
		}
	}
	if b, _ := os.ReadFile(copyPath); string(b) != caPEM {
		t.Fatalf("copy %q", b)
	}
	if fi, _ := os.Stat(copyPath); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	if !strings.Contains(f.upCompose, "source: \""+copyPath+"\"") {
		t.Errorf("up compose does not mount the copy:\n%s", f.upCompose)
	}

	// A changed CA is a reviewed change; declined, the copy stays.
	os.WriteFile(ca, []byte(strings.Replace(caPEM, "example", "other", 1)), 0o644)
	out, err = w.up("n\n", newFake())
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "+ vault ca_file "+ca+" sha256:") || !strings.Contains(out, "- vault ca_file "+ca+" sha256:") {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(copyPath); string(b) != caPEM {
		t.Fatalf("declined change replaced the copy: %q", b)
	}
	if _, err := w.up("y\n", newFake()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(copyPath); !strings.Contains(string(b), "other") {
		t.Fatalf("confirmed change not copied: %q", b)
	}
}

func TestReadCARefusals(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ca.pem")
	os.WriteFile(good, []byte(caPEM), 0o644)
	big := filepath.Join(dir, "big.pem")
	os.WriteFile(big, make([]byte, maxCAFile+1), 0o644)
	link := filepath.Join(dir, "link.pem")
	os.Symlink(good, link)
	fifo := filepath.Join(dir, "fifo.pem")
	syscall.Mkfifo(fifo, 0o600)
	if b, sum, err := readCA(good); err != nil || string(b) != caPEM || len(sum) != 64 {
		t.Fatalf("good: %v %q", err, sum)
	}
	for name, p := range map[string]string{"missing": filepath.Join(dir, "none.pem"), "big": big, "dir": dir, "symlink": link, "fifo": fifo, "relative": "ca.pem"} {
		_, _, err := readCA(p)
		if err == nil || err.Error() != "vault.ca_file: an absolute path to a PEM file of yours, at most 64 KiB" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
