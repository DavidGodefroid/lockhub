package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

func TestVaultUsage(t *testing.T) {
	for _, args := range [][]string{{"vault"}, {"vault", "get"}, {"vault", "set"}, {"vault", "set", "--namespace", "shop"}, {"vault", "set", "--address", "https://vault.example.com:8200", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, devNull(t), &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage: lox vault set") {
			t.Errorf("run(%q) = %d, err %q", args, code, errb.String())
		}
	}
}

func TestVaultRefusesLocalhost(t *testing.T) {
	_, file := removeWorld(t)
	for _, addr := range []string{"https://localhost:8200", "http://127.0.0.1:8200"} {
		var out, errb bytes.Buffer
		if code := vaultCmd([]string{"set", "--file", file, "--address", addr}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "use host.docker.internal for this machine") {
			t.Errorf("%s: code %d, err %q", addr, code, errb.String())
		}
	}
	if b, _ := os.ReadFile(file); string(b) != removeYAML {
		t.Errorf("lockfamily.yaml changed:\n%s", b)
	}
}

func TestVaultSetThenReread(t *testing.T) {
	ws, file := removeWorld(t)
	ca := filepath.Join(ws, "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	args := []string{"set", "--file", file, "--address", "https://vault.example.com:8200", "--namespace", "shop", "--ca-file", ca}
	if code := vaultCmd(args, &out, &errb); code != 0 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	if want := file + ": vault set; run lox up to review and apply it"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout %q", out.String())
	}
	c, err := family.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault == nil || c.Vault.Address != "https://vault.example.com:8200" || c.Vault.Namespace != "shop" || c.Vault.CAFile != ca {
		t.Errorf("vault = %+v", c.Vault)
	}
}

const vaultCommented = "# the shop family\nversion: 1\nhub:\n  image: " + hubImg + "\nvault:\n  address: https://old.example.com:8200\n  namespace: shop\n  ca_file: CA\nlocks: {}  # none yet\n"

func vaultWorld(t *testing.T) (file, ca string) {
	t.Helper()
	ws, file := removeWorld(t)
	ca = filepath.Join(ws, "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(strings.Replace(vaultCommented, "CA", ca, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return file, ca
}

func TestVaultOmittedFlagsKeepTheValues(t *testing.T) {
	file, ca := vaultWorld(t)
	var out, errb bytes.Buffer
	if code := vaultCmd([]string{"set", "--file", file, "--address", "https://vault.example.com:8200"}, &out, &errb); code != 0 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	c, err := family.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault.Address != "https://vault.example.com:8200" || c.Vault.Namespace != "shop" || c.Vault.CAFile != ca {
		t.Errorf("vault = %+v", c.Vault)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), "# the shop family") || !strings.Contains(string(b), "# none yet") {
		t.Errorf("comments lost:\n%s", b)
	}
}

func TestVaultExplicitEmptyClears(t *testing.T) {
	file, _ := vaultWorld(t)
	var out, errb bytes.Buffer
	if code := vaultCmd([]string{"set", "--file", file, "--address", "https://vault.example.com:8200", "--namespace", "", "--ca-file", ""}, &out, &errb); code != 0 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	c, err := family.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault.Namespace != "" || c.Vault.CAFile != "" {
		t.Errorf("vault = %+v", c.Vault)
	}
}

func TestVaultRefusesABadCAFile(t *testing.T) {
	file, _ := vaultWorld(t)
	before, _ := os.ReadFile(file)
	for name, ca := range map[string]string{"directory": filepath.Dir(file), "relative": "ca.pem", "missing": filepath.Join(filepath.Dir(file), "missing.pem")} {
		var out, errb bytes.Buffer
		if code := vaultCmd([]string{"set", "--file", file, "--address", "https://vault.example.com:8200", "--ca-file", ca}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "vault.ca_file:") {
			t.Errorf("%s: code %d, err %q", name, code, errb.String())
		}
	}
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Errorf("lockfamily.yaml changed:\n%s", after)
	}
}

func TestVaultRepairsAFileLoadRefuses(t *testing.T) {
	// The current address is localhost, which Load refuses: set must still
	// repair the file and keep the namespace and ca_file.
	file, ca := vaultWorld(t)
	b, _ := os.ReadFile(file)
	bad := strings.Replace(string(b), "https://old.example.com:8200", "http://localhost:8200", 1)
	if err := os.WriteFile(file, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := vaultCmd([]string{"set", "--file", file, "--address", "https://vault.example.com:8200"}, &out, &errb); code != 0 {
		t.Fatalf("code %d, %s", code, errb.String())
	}
	c, err := family.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault.Address != "https://vault.example.com:8200" || c.Vault.Namespace != "shop" || c.Vault.CAFile != ca {
		t.Errorf("vault = %+v", c.Vault)
	}
}

func TestVaultUnparseableYAMLLeavesFileUntouched(t *testing.T) {
	file, _ := vaultWorld(t)
	broken := "version: 1\nlocks: [unclosed\n"
	if err := os.WriteFile(file, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := vaultCmd([]string{"set", "--file", file, "--address", "https://vault.example.com:8200"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "lox vault set:") {
		t.Fatalf("code %d, err %q", code, errb.String())
	}
	if after, _ := os.ReadFile(file); string(after) != broken {
		t.Errorf("lockfamily.yaml changed:\n%s", after)
	}
}
