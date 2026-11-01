package loxadd

import (
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

// Lock is one lock to add: its type, names and the target flags of its
// `profile add`. It holds no secret: the console asks at start or reads
// Vault.
type Lock struct {
	Type, Name, Profile string
	Target              []string
	Production          bool
	Credentials         string
	VaultPath           string
	// Vault is set only when the vault block is created now (vault-address
	// answered).
	Vault *family.Vault
}

// targetKeys are the answers that become target flags, in argv order, per
// lock (each key is the flag name of the lock's `profile add`).
var targetKeys = map[string][]string{
	"locksql":  {"engine", "host", "port", "user", "database", "path", "tls"},
	"lockmq":   {"url", "user", "vhost", "amqp-url"},
	"lockfile": {"source", "bucket", "endpoint", "region", "path", "host", "port", "user", "key", "known-hosts", "base-dir"},
	"lockhttp": nil,
}

// Build is the lock the answers describe. An empty answer gives no flag.
func Build(lock string, a Answers) (Lock, error) {
	keys, ok := targetKeys[lock]
	if !ok {
		return Lock{}, fmt.Errorf("lock: want locksql, lockmq, lockfile or lockhttp")
	}
	name := a["name"]
	if name == "" {
		return Lock{}, fmt.Errorf("name: a value is needed")
	}
	l := Lock{Type: lock, Name: name, Profile: name}
	switch strings.ToLower(a["production"]) {
	case "y", "yes":
		l.Production = true
	}
	if lock != "lockhttp" {
		l.Credentials = a["credentials"]
		if l.Credentials == CredVault {
			if a["vault-path"] == "" {
				return Lock{}, fmt.Errorf("vault-path: a value is needed")
			}
			l.VaultPath = a["vault-path"]
		}
	}
	for _, k := range keys {
		if v := a[k]; v != "" {
			l.Target = append(l.Target, "--"+k, v)
		}
	}
	if addr := a["vault-address"]; addr != "" {
		l.Vault = &family.Vault{Address: addr, Namespace: a["vault-namespace"], CAFile: a["vault-ca"]}
	}
	return l, nil
}

// ProfileArgs is the argument list of `<type> profile add` for the project
// at root.
func (l Lock) ProfileArgs(root string) []string {
	args := []string{"profile", "add", "--non-interactive", "--json", "--project", root, "--profile", l.Profile}
	if l.Credentials != "" {
		args = append(args, "--credentials", l.Credentials)
	}
	if l.VaultPath != "" {
		args = append(args, "--vault-path", l.VaultPath)
	}
	if l.Production {
		args = append(args, "--production")
	}
	return append(args, l.Target...)
}
