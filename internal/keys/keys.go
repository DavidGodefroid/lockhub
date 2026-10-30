// Package keys reads and writes the hub's signing key and the list of
// lock instances allowed to reach it.
//
// Files in the hub's data directory:
//
//	hub.key     the hub's Ed25519 private key, PKCS#8 PEM, 0600
//	locks.json  {"locks": {"<instance>": {"public_key": "<base64 raw 32 bytes>"}}}
//	retired-keys.pub  the hub keys used before hub.key, oldest first, one
//	            base64 public key per line (lockhub rotate-key appends)
//
// lock up writes hub.key and locks.json; lockhub keygen writes hub.key
// alone.
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RetiredFile is the list of the hub keys used before hub.key, in the
// hub's data directory.
const RetiredFile = "retired-keys.pub"

// ParsePublics reads base64 Ed25519 public keys, one per line (blank
// lines skipped), in order. A repeated key is refused.
func ParsePublics(b []byte) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(l)
		if err != nil || len(k) != ed25519.PublicKeySize || Public(k) != l {
			return nil, fmt.Errorf("line %d: not a base64 Ed25519 public key", i+1)
		}
		for _, o := range out {
			if bytes.Equal(o, k) {
				return nil, fmt.Errorf("line %d: key listed twice", i+1)
			}
		}
		out = append(out, ed25519.PublicKey(k))
	}
	return out, nil
}

// FormatPublics is ParsePublics' format.
func FormatPublics(ks []ed25519.PublicKey) []byte {
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(Public(k) + "\n")
	}
	return []byte(b.String())
}

// LoadRetired reads the retired hub keys of the data directory dir
// (none when the file does not exist). current, the key of hub.key, is
// left out when it ends the list: a rotation that stopped after
// retiring it, before hub.key was replaced.
func LoadRetired(dir string, current ed25519.PublicKey) ([]ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, RetiredFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	ks, err := ParsePublics(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", RetiredFile, err)
	}
	if n := len(ks); n > 0 && bytes.Equal(ks[n-1], current) {
		ks = ks[:n-1]
	}
	for _, k := range ks {
		if bytes.Equal(k, current) {
			return nil, fmt.Errorf("%s: lists the current hub key before other keys", RetiredFile)
		}
	}
	return ks, nil
}

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

var instanceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

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
