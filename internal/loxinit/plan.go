package loxinit

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Credential sources a profile add takes (the console asks at its start,
// or reads Vault).
const (
	CredAsk   = "ask"
	CredVault = "vault"
)

// TLS modes locksql takes.
var TLSModes = []string{"disable", "prefer", "require", "verify-ca", "verify-full"}

// Declared is a lock lockfamily.yaml declares already.
type Declared struct {
	Instance, Lock, Profile string
}

// Planned is one lock lox init sets up.
type Planned struct {
	Lock     string
	Instance string
	Profile  string
	// Target are the lock's own target flags (profile add).
	Target []string
	// Source is the detected source it serves (nil in manual mode when
	// typed in).
	Source     *Source
	Production bool
	// Credentials: CredAsk or CredVault; "" for a target with no secret
	// (lockhttp, a local lockfile directory).
	Credentials string
	VaultPath   string
	// AllowedUIDs: lea's agents' uid, for a lock lea's agents reach
	// (locksql, lockmq, lockfile; lox up's allowed_uids).
	AllowedUIDs []int
}

// ProfileArgs are the arguments of the lock's profile add, from the
// project root: never a secret (the lock takes none, and refuses one).
func (p Planned) ProfileArgs(root string) []string {
	a := []string{"profile", "add", "--non-interactive", "--json", "--project", root, "--profile", p.Profile}
	if p.Production {
		a = append(a, "--production")
	}
	if p.Credentials != "" {
		a = append(a, "--credentials", p.Credentials)
		if p.Credentials == CredVault {
			a = append(a, "--vault-path", p.VaultPath)
		}
	}
	return append(a, p.Target...)
}

// SQLTarget are locksql's target flags for s; tls is the TLS mode (always
// given: locksql's default for a remote host is verify-full, and a local
// compose database seldom has TLS).
func SQLTarget(s Source, tls string) []string {
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
func MQTarget(s Source) []string {
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
func DefaultTLS(s Source, production bool) string {
	if s.Local && !production {
		return "disable"
	}
	return "verify-full"
}

var nameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// cleanName is s made an instance and profile name: lower case, digits
// and -, at most 40 characters; "" when nothing is left.
func cleanName(s string) string {
	n := nameChars.ReplaceAllString(strings.ToLower(s), "-")
	n = strings.Trim(n, "-")
	if len(n) > 40 {
		n = strings.Trim(n[:40], "-")
	}
	if n == "hub" {
		n = "hub-db"
	}
	return n
}

// SuggestName is the instance (and profile) name proposed for s: its
// compose service, its database or vhost, else the lock's usual one.
func SuggestName(s Source) string {
	for _, c := range []string{s.Service, s.Database, s.VHost} {
		if n := cleanName(c); n != "" {
			return n
		}
	}
	if s.Kind == KindRabbitMQ {
		return "mq"
	}
	return "db"
}

// keptBy is the declared lock that already serves name for lock: the
// same type and the same profile (or, with no profile, the same
// instance).
func keptBy(decl []Declared, lock, name string) *Declared {
	for i, d := range decl {
		if d.Lock == lock && (d.Profile == name || (d.Profile == "" && d.Instance == name)) {
			return &decl[i]
		}
	}
	return nil
}

// uniqueName is name, or name-2, name-3... when an instance (declared
// or planned) already has it.
func uniqueName(name string, taken func(string) bool) string {
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		n := fmt.Sprintf("%s-%d", name, i)
		if !taken(n) {
			return n
		}
	}
}

// uidsFor are lox up's allowed_uids of a lock lea's agents reach: lea's
// uid, when it is one a console takes (not root, not nobody).
func uidsFor(lock string, lea bool, uid int) []int {
	if !lea || uid <= 0 || uid == 65534 || !slices.Contains([]string{"locksql", "lockmq", "lockfile"}, lock) {
		return nil
	}
	return []int{uid}
}
