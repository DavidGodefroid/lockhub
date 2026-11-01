// Package loxadd is `lox add <type>`: one lock, its target asked in a
// short guided form (or given as flags), applied at once. This file holds
// the credential sources and locksql's TLS modes.
package loxadd

// Credential sources a profile add takes (the console asks at its start,
// or reads Vault).
const (
	CredAsk   = "ask"
	CredVault = "vault"
)

// TLS modes locksql takes.
var TLSModes = []string{"disable", "prefer", "require", "verify-ca", "verify-full"}
