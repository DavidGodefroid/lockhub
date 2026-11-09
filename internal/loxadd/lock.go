package loxadd

import (
	"fmt"
	"os"
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
	// LogRoots is a locklog lock's log_roots: its directories outside
	// family.DefaultLogRoots, which LOCKLOG_EXTRA_ROOTS let in.
	LogRoots []string
}

// getenv reads LOCKLOG_EXTRA_ROOTS (tests replace it).
var getenv = os.Getenv

// targetKeys are the answers that become target flags, in argv order, per
// lock (each key is the flag name of the lock's `profile add`).
var targetKeys = map[string][]string{
	"locksql":  {"engine", "host", "port", "user", "database", "path", "tls"},
	"lockmq":   {"url", "user", "vhost", "amqp-url"},
	"lockfile": {"source", "bucket", "endpoint", "region", "path", "host", "port", "user", "auth", "key", "known-hosts", "base-dir"},
	"lockhttp": nil,
	"locklog":  {"only"},
	"lockssh":  {"host", "port", "user", "auth", "key", "known-hosts", "allow", "exec"},
}

// Build is the lock the answers describe. An empty answer gives no flag.
func Build(lock string, a Answers) (Lock, error) {
	keys, ok := targetKeys[lock]
	if !ok {
		return Lock{}, fmt.Errorf("lock: want locksql, lockmq, lockfile, lockhttp, locklog or lockssh")
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
	if err := checkRequired(lock, a); err != nil {
		return Lock{}, err
	}
	if takesCredentials(lock, a) {
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
			switch {
			case lock == "locklog" && k == "only":
				v = normDirs(v) // locklog profile add --only does not trim
				// lox run's root rule, now: never a lock it refuses.
				roots, err := family.AddLogRoots(strings.Split(v, ","), strings.Fields(getenv("LOCKLOG_EXTRA_ROOTS")))
				if err != nil {
					return Lock{}, fmt.Errorf("only: %w", err)
				}
				l.LogRoots = roots
			case lock == "lockssh" && k == "allow":
				// One --allow per rule (lockssh profile add repeats it).
				for _, r := range splitRules(v) {
					l.Target = append(l.Target, "--allow", r)
				}
				continue
			case lock == "lockssh" && k == "exec":
				if yes(v) {
					l.Target = append(l.Target, "--exec")
				}
				continue
			}
			l.Target = append(l.Target, "--"+k, v)
		}
	}
	if addr := a["vault-address"]; addr != "" {
		l.Vault = &family.Vault{Address: addr, Namespace: family.TrimVaultNamespace(a["vault-namespace"]), CAFile: a["vault-ca"]}
	}
	return l, nil
}

// takesCredentials: lockhttp, locklog (its non-interactive profile add
// takes the host's own logs), a sqlite file and a local directory hold no
// secret, and their profile add refuses --credentials and --vault-path.
func takesCredentials(lock string, a Answers) bool {
	switch lock {
	case "lockhttp", "locklog":
		return false
	case "locksql":
		return a["engine"] != "sqlite"
	case "lockfile":
		return a["source"] != "local"
	}
	return true
}

// yes: a y/n answer that says yes.
func yes(v string) bool {
	switch strings.ToLower(v) {
	case "y", "yes":
		return true
	}
	return false
}

// splitRules are the allow rules of a lockssh answer: separated by ";",
// each trimmed, none empty.
func splitRules(v string) []string {
	var out []string
	for _, r := range strings.Split(v, ";") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// checkRequired refuses a missing key the lock's profile add needs.
func checkRequired(lock string, a Answers) error {
	var need []string
	switch lock {
	case "lockmq":
		need = []string{"url"}
	case "lockssh":
		need = []string{"host", "user"}
		if a["auth"] != "password" {
			need = append(need, "key")
		}
	case "lockfile":
		switch a["source"] {
		case "local":
			need = []string{"path"}
		case "s3":
			need = []string{"bucket"}
			if a["region"] == "" && a["endpoint"] == "" {
				need = append(need, "region")
			}
		case "sftp":
			need = []string{"host", "user", "auth", "known-hosts"}
			if a["auth"] == "key" {
				need = append(need, "key")
			}
		default:
			need = []string{"source"}
		}
	}
	for _, k := range need {
		if a[k] == "" {
			return fmt.Errorf("%s: a value is needed", k)
		}
	}
	return nil
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
