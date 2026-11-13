package family

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultTokenValidation(t *testing.T) {
	block := "vault:\n  address: https://vault.example.com:8200\n"
	for _, c := range []struct{ vault, lock, want string }{
		{block, "    vault: true\n    vault_token: cli\n", ""},
		{block, "    vault: true\n    vault_token: ask\n", ""},
		{block, "    vault: true\n", ""},
		{block, "    vault_token: cli\n", "locks.shop.vault_token: set, but the lock has no vault: true"},
		{block, "    vault_token: ask\n", "locks.shop.vault_token: set, but the lock has no vault: true"},
		{block, "    vault: true\n    vault_token: env\n", "locks.shop.vault_token: want ask or cli"},
		{block, "    vault: true\n    vault_token: CLI\n", "locks.shop.vault_token: want ask or cli"},
	} {
		c2, err := loadVaultConf(t, vaultConf(c.vault, c.lock))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%q refused: %v", c.lock, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%q: got %v, want %q", c.lock, err, c.want)
		case c.want == "" && strings.Contains(c.lock, "vault_token: cli") && c2.Locks["shop"].VaultToken != VaultTokenCLI:
			t.Errorf("%q: vault_token %q", c.lock, c2.Locks["shop"].VaultToken)
		}
	}
}

const vaultCLIConf = "version: 1\nhub:\n  image: " + hubImg + "\nvault:\n  address: http://host.docker.internal:58200\n  namespace: shop\nlocks:\n  crm-prod:\n    type: locksql\n    image: " + sqlImg + "\n    vault: true\n"

// ask -> cli is a loosening the human confirms in the review; only the
// applied review gives lox run the lock, its Vault and its vault_path.
func TestVaultTokenCLIIsReviewed(t *testing.T) {
	w := newWS(t, vaultCLIConf)
	toml := filepath.Join(w.dir, "projects", ".locksql", "config.toml")
	os.WriteFile(toml, []byte("[profiles.crm]\nengine = \"postgres\"\nhost = \"host.docker.internal\"\ncredentials = \"vault\"\nvault_path = \"secret/data/crm\"\n"), 0o644)
	state := filepath.Join(w.dir, "state")
	keys := newFake().keys
	fake := func() *fake { return &fake{keys: keys} }
	if out, err := w.up("y\n", fake()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if v, err := AppliedVaultCLI(state); err != nil || v != nil {
		t.Fatalf("ask: applied vault cli %+v, %v", v, err)
	}

	os.WriteFile(w.file, []byte(vaultCLIConf+"    vault_token: cli\n"), 0o644)
	out, err := w.up("n\n", fake())
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "  vault token  from the host's Vault CLI\n") {
		t.Fatalf("ask -> cli not asked: %v\n%s", err, out)
	}
	if strings.Contains(out, "Other changes") {
		t.Errorf("the vault token row is listed again:\n%s", out)
	}
	if v, _ := AppliedVaultCLI(state); v != nil {
		t.Fatalf("declined, yet applied: %+v", v)
	}
	if out, err := w.up("y\n", fake()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	v, err := AppliedVaultCLI(state)
	if err != nil || v == nil {
		t.Fatalf("cli applied: %+v, %v", v, err)
	}
	if v.Address != "http://host.docker.internal:58200" || v.Namespace != "shop" || v.CAFile != "" || len(v.Locks) != 1 || v.Locks["crm-prod"] != "secret/data/crm" {
		t.Errorf("applied vault cli %+v", v)
	}

	// cli -> ask: the line goes, and lox run (which also needs the file's
	// cli) stops using the CLI's token without waiting for it.
	os.WriteFile(w.file, []byte(vaultCLIConf+"    vault_token: ask\n"), 0o644)
	out, err = w.up("n\n", fake())
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "- lock crm-prod vault token from the host's Vault CLI") || strings.Contains(out, "  vault token  ") {
		t.Fatalf("cli -> ask: %v\n%s", err, out)
	}
}

func TestVaultCLIOfSummary(t *testing.T) {
	base := []string{
		"lock a type locksql", "lock a profile crm",
		"lock a vault VAULT_ADDR=https://vault.example.com", "lock a vault VAULT_NAMESPACE=ns",
		"lock a vault token from the host's Vault CLI",
		"lock b type locksql", "lock b vault VAULT_ADDR=https://vault.example.com", "lock b vault VAULT_NAMESPACE=ns",
		"vault ca_file /etc/ca.pem sha256:abcd",
		"profile locksql /ws/.locksql sha256:ff",
		"profile locksql config.toml:1 [profiles.crm]",
		"profile locksql config.toml:2 credentials = \"vault\"",
		"profile locksql config.toml:3 vault_path = \"secret/data/crm\"",
		"profile locksql config.toml:4 [profiles.other]",
		"profile locksql config.toml:5 vault_path = \"secret/data/other\"",
	}
	v, err := vaultCLIOf(base)
	if err != nil || v == nil {
		t.Fatal(v, err)
	}
	if v.Address != "https://vault.example.com" || v.Namespace != "ns" || v.CAFile != "/etc/ca.pem" || v.CASHA256 != "abcd" || len(v.Locks) != 1 || v.Locks["a"] != "secret/data/crm" {
		t.Errorf("%+v", v)
	}
	// No reviewed vault_path, or an odd one: the lock is served nothing.
	odd := append([]string{}, base[:len(base)-3]...)
	odd = append(odd, "profile locksql config.toml:3 vault_path = 42")
	if v, _ := vaultCLIOf(odd); v == nil || v.Locks["a"] != "" {
		t.Errorf("odd vault_path: %+v", v)
	}
	// A cli lock without its Vault address is an error, not a guess.
	if _, err := vaultCLIOf([]string{"lock a vault token from the host's Vault CLI"}); err == nil {
		t.Error("cli without an address accepted")
	}
	if v, err := vaultCLIOf(base[5:]); v != nil || err != nil {
		t.Errorf("no cli lock: %+v %v", v, err)
	}
}

func TestVaultCLICAChecked(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, []byte(caPEM), 0o644)
	_, sha, err := readCA(ca)
	if err != nil {
		t.Fatal(err)
	}
	v := &VaultCLI{CAFile: ca, CASHA256: sha}
	if b, err := v.CA(); err != nil || string(b) != caPEM {
		t.Fatalf("reviewed CA: %q %v", b, err)
	}
	os.WriteFile(ca, []byte(strings.Replace(caPEM, "example", "other", 1)), 0o644)
	if _, err := v.CA(); err == nil || !strings.Contains(err.Error(), "changed since the last lox run's review") {
		t.Errorf("changed CA: %v", err)
	}
	if b, err := (&VaultCLI{}).CA(); b != nil || err != nil {
		t.Errorf("no CA: %q %v", b, err)
	}
}
