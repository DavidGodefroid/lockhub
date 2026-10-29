// Package keys reads and writes the hub's signing key and the list of
// lock instances allowed to reach it.
//
// Files in the hub's data directory:
//
//	hub.key     the hub's Ed25519 private key, PKCS#8 PEM, 0600
//	locks.json  {"locks": {"<instance>": {"public_key": "<base64 raw 32 bytes>"}}}
//
// lock up writes both; lockhub keygen writes hub.key alone.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
)

const pemType = "PRIVATE KEY"

// Generate writes a new hub key at path (refusing to overwrite one) and
// returns its public half.
func Generate(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: pemType, Bytes: der}); err != nil {
		f.Close()
		return nil, err
	}
	return pub, f.Close()
}

// Load reads the hub key at path. A key readable by group or others is
// refused.
func Load(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %v, want 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemType {
		return nil, fmt.Errorf("%s: not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return priv, nil
}

// Public encodes a public key as locks.json and `lockhub keygen` print it.
func Public(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

var instanceName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidInstance reports whether name may name a lock instance.
func ValidInstance(name string) bool { return instanceName.MatchString(name) }

// LoadLocks reads locks.json.
func LoadLocks(path string) (map[string]ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Locks map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"locks"`
	}
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string]ed25519.PublicKey{}
	seen := map[string]string{}
	for name, l := range f.Locks {
		if !ValidInstance(name) {
			return nil, fmt.Errorf("%s: bad instance name %q", path, name)
		}
		k, err := base64.StdEncoding.DecodeString(l.PublicKey)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s: instance %q: public_key is not a base64 Ed25519 key", path, name)
		}
		if other, dup := seen[string(k)]; dup {
			return nil, fmt.Errorf("%s: instances %q and %q share a key", path, other, name)
		}
		seen[string(k)] = name
		out[name] = ed25519.PublicKey(k)
	}
	if len(out) == 0 {
		return nil, errors.New(path + ": no lock instance")
	}
	return out, nil
}
