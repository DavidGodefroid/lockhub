// Package loxadd is `lox add <type>`: one lock, its target asked in a
// short guided form (or given as flags), applied at once. This file holds
// a lock's target flags and the credential sources.
package loxadd

import (
	"strconv"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// Credential sources a profile add takes (the console asks at its start,
// or reads Vault).
const (
	CredAsk   = "ask"
	CredVault = "vault"
)

// TLS modes locksql takes.
var TLSModes = []string{"disable", "prefer", "require", "verify-ca", "verify-full"}

// SQLTarget are locksql's target flags for s; tls is the TLS mode (always
// given: locksql's default for a remote host is verify-full, and a local
// compose database seldom has TLS).
func SQLTarget(s loxinit.Source, tls string) []string {
	a := []string{"--engine", s.Kind, "--host", s.Host, "--port", strconv.Itoa(s.Port)}
	if s.User != "" {
		a = append(a, "--user", s.User)
	}
	if s.Database != "" {
		a = append(a, "--database", s.Database)
	}
	if tls != "" {
		a = append(a, "--tls", tls)
	}
	return a
}

// MQTarget are lockmq's target flags for s.
func MQTarget(s loxinit.Source) []string {
	a := []string{"--url", s.MgmtURL()}
	if s.User != "" {
		a = append(a, "--user", s.User)
	}
	if s.VHost != "" {
		a = append(a, "--vhost", s.VHost)
	}
	if u := s.AMQPURL(); u != "" {
		a = append(a, "--amqp-url", u)
	}
	return a
}

// DefaultTLS is the TLS mode proposed when the files say none: disable
// for a database on this machine (its traffic stays on the host), else
// verify-full; verify-full for production whatever the host.
func DefaultTLS(s loxinit.Source, production bool) string {
	if s.Local && !production {
		return "disable"
	}
	return "verify-full"
}
