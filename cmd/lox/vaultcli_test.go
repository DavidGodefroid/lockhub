package main

import (
	"context"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

// lox run serves vault_token: cli only to the locks both the applied
// review and the file give it: the file alone (an agent can write it)
// never turns it on, and dropping it from the file turns it off.
func TestVaultCLIServedLocks(t *testing.T) {
	applied := &family.VaultCLI{Address: "https://vault.example.com", Locks: map[string]string{"inv": "secret/data/inv", "nopath": "", "gone": "secret/x"}}
	c := &family.Config{Locks: map[string]family.Lock{
		"inv":    {Type: "locksql", Vault: true, VaultToken: family.VaultTokenCLI},
		"nopath": {Type: "locksql", Vault: true, VaultToken: family.VaultTokenCLI},
		"gone":   {Type: "locksql", Vault: true, VaultToken: family.VaultTokenAsk},
		"new":    {Type: "locksql", Vault: true, VaultToken: family.VaultTokenCLI},
	}}
	v := vaultCLI(applied, c)
	if v == nil || v.Address != applied.Address || len(v.Locks) != 2 || !v.Locks["inv"] || !v.Locks["nopath"] {
		t.Fatalf("%+v", v)
	}
	// No reviewed vault_path: never read, never checked anywhere.
	t.Setenv("PATH", t.TempDir())
	if tok, err := v.Token(context.Background(), "nopath"); tok != nil || err == nil || !strings.Contains(err.Error(), "names no vault_path") {
		t.Errorf("nopath: %q %v", tok, err)
	}
	c.Locks["inv"] = family.Lock{Type: "locksql", Vault: true}
	c.Locks["nopath"] = family.Lock{Type: "locksql", Vault: true}
	if v := vaultCLI(applied, c); v != nil {
		t.Errorf("cli dropped from the file, still served: %+v", v)
	}
}
