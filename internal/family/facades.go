package family

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/DavidGodefroid/lockkit/ticket"

	"github.com/DavidGodefroid/lockhub/internal/keys"
)

// HostFacades are the facades that run on the host and whose keys the
// locks pin: a lock seals a ticket's clear values (Ctrl-O) only to an
// ephemeral key one of them signed.
var HostFacades = []string{ticket.FacadeTTY, ticket.FacadeDeck}

// Files of the host facades.
const (
	// FacadesFile, in a workspace's state directory, is the
	// ticket.FacadeSet mounted read-only in every lock at
	// LockFacadesPath.
	FacadesFile = "facades.json"
	// LockFacadesPath is where a lock reads it (--facade-keys-file),
	// next to the devices file (/run/lockfamily is the hub key's volume).
	LockFacadesPath = "/run/lockfamily-facades/facades.json"
	// LockKeysFile, in the facade keys directory, lists the lock keys
	// lox up pinned ({"locks": {"<instance>": {"public_key": "…"}}}),
	// for host facades to verify a lock's signed answers.
	LockKeysFile = "locks.json"
	// LockKeysDir, in the facade keys directory, holds the lock keys
	// each workspace's lox up pinned (<project>.json, same format):
	// LockKeysFile is their union, so a lox up in one workspace keeps the
	// keys of the others (one hub per user, many workspaces).
	LockKeysDir = "locks.d"
)

// FacadeKeysDir is the host-only directory of the host facades' keys
// under stateHome ($XDG_STATE_HOME): one per user, shared by workspaces.
func FacadeKeysDir(stateHome string) string { return filepath.Join(stateHome, "lockfamily", "facades") }

// FacadeKeyPath is the private key of facade f in dir (PKCS#8 PEM, 0600).
func FacadeKeyPath(dir, f string) string { return filepath.Join(dir, f+".key") }

// EnsureFacadeKeys creates the keys of the host facades in dir if
// needed, and returns their public halves by facade.
func EnsureFacadeKeys(dir string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range HostFacades {
		path := FacadeKeyPath(dir, f)
		priv, err := keys.Load(path)
		if errors.Is(err, os.ErrNotExist) {
			if _, err := keys.Generate(path); err != nil {
				return nil, err
			}
			priv, err = keys.Load(path)
		}
		if err != nil {
			return nil, err
		}
		out[f] = keys.Public(priv.Public().(ed25519.PublicKey))
	}
	return out, nil
}

// facadeSet is the FacadeSet of pubs, in HostFacades order.
func facadeSet(pubs map[string]string) ticket.FacadeSet {
	fs := ticket.FacadeSet{V: ticket.Version, Facades: []ticket.FacadeKey{}}
	for _, f := range HostFacades {
		if k, ok := pubs[f]; ok {
			fs.Facades = append(fs.Facades, ticket.FacadeKey{Facade: f, Key: k})
		}
	}
	return fs
}

// writeFacadeSet writes the facade keys locks pin. It holds public keys
// only and is mounted in the locks, so it is world-readable, like the
// hub's public key.
func writeFacadeSet(path string, pubs map[string]string) error {
	fs := facadeSet(pubs)
	b, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return err
	}
	if _, err := ticket.ParseFacades(b); err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o644)
}

// writeAtomic replaces path with b: a reader sees the old file or the
// new one, never a part.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
