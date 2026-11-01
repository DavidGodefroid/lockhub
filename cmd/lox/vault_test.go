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
