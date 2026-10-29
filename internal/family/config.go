// Package family is `lock up`: it reads a workspace's lockfamily.yaml,
// reviews every change of configuration or keys with the human, and runs
// the hub and the declared locks with Docker Compose.
package family

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Config is lockfamily.yaml, version 1.
//
//	version: 1
//	hub:
//	  image: ghcr.io/davidgodefroid/lockhub@sha256:…
//	  facades: [tty, deck]           # default: tty, deck
//	  routing:                       # optional: narrow facades per instance
//	    crm-prod: [tty]
//	locks:
//	  crm-prod:
//	    type: locksql
//	    image: ghcr.io/davidgodefroid/locksql@sha256:…
//	    production: true
//	    credentials: vault:secret/crm   # a reference, never a secret
type Config struct {
	Version int             `yaml:"version"`
	Hub     Hub             `yaml:"hub"`
	Locks   map[string]Lock `yaml:"locks"`
}

// Hub configures the hub.
type Hub struct {
	Image   string              `yaml:"image"`
	Facades []string            `yaml:"facades"`
	Routing map[string][]string `yaml:"routing,omitempty"`
}

// Lock is one lock instance.
type Lock struct {
	Type        string `yaml:"type"`
	Image       string `yaml:"image"`
	Production  bool   `yaml:"production,omitempty"`
	Credentials string `yaml:"credentials,omitempty"`
}

// Types are the lock types lock up knows, and their image repositories.
var Types = []string{"locksql", "lockmq", "lockfile", "lockhttp"}

var digestRef = regexp.MustCompile(`^ghcr\.io/davidgodefroid/([a-z]+)@sha256:[0-9a-f]{64}$`)

// credentialRef is a reference to a secret: lock up never accepts one in
// clear.
var credentialRef = regexp.MustCompile(`^(vault:[A-Za-z0-9/_.-]+|file:/[^\s]+|keychain:[A-Za-z0-9._-]+|ask)$`)

// Load reads and validates path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decode(b, path, true)
}

// decode parses and validates a lockfamily.yaml; needLocks refuses one
// without locks (lock up has nothing to run then).
func decode(b []byte, path string, needLocks bool) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w (secrets are never written here: use credentials: vault:… / file:… / keychain:… / ask)", path, err)
	}
	if err := c.validate(needLocks); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Validate checks c and fills defaults.
func (c *Config) Validate() error { return c.validate(true) }

func (c *Config) validate(needLocks bool) error {
	if c.Version != 1 {
		return fmt.Errorf("version: want 1, got %d", c.Version)
	}
	if m := digestRef.FindStringSubmatch(c.Hub.Image); m == nil || m[1] != "lockhub" {
		return fmt.Errorf("hub.image: want ghcr.io/davidgodefroid/lockhub@sha256:<digest>, got %q", c.Hub.Image)
	}
	if len(c.Hub.Facades) == 0 {
		c.Hub.Facades = []string{route.TTY, route.Deck}
	}
	for _, f := range c.Hub.Facades {
		if !route.KnownFacade(f) {
			return fmt.Errorf("hub.facades: unknown facade %q", f)
		}
	}
	if needLocks && len(c.Locks) == 0 {
		return fmt.Errorf("locks: none declared")
	}
	for name, l := range c.Locks {
		if !keys.ValidInstance(name) {
			return fmt.Errorf("locks: bad instance name %q (lower case, digits and -)", name)
		}
		if !slices.Contains(Types, l.Type) {
			return fmt.Errorf("locks.%s.type: want one of %s", name, strings.Join(Types, ", "))
		}
		if m := digestRef.FindStringSubmatch(l.Image); m == nil || m[1] != l.Type {
			return fmt.Errorf("locks.%s.image: want ghcr.io/davidgodefroid/%s@sha256:<digest>", name, l.Type)
		}
		if l.Credentials != "" && !credentialRef.MatchString(l.Credentials) {
			return fmt.Errorf("locks.%s.credentials: a reference (vault:…, file:/…, keychain:…, ask), never a secret", name)
		}
	}
	for inst, fs := range c.Hub.Routing {
		if _, ok := c.Locks[inst]; !ok {
			return fmt.Errorf("hub.routing: unknown instance %q", inst)
		}
		if len(fs) == 0 {
			return fmt.Errorf("hub.routing.%s: no facade could answer it (list at least one)", inst)
		}
		for _, f := range fs {
			if !slices.Contains(c.Hub.Facades, f) {
				return fmt.Errorf("hub.routing.%s: facade %q is not enabled in hub.facades", inst, f)
			}
		}
	}
	return nil
}

// Instances are the instance names, sorted.
func (c *Config) Instances() []string {
	var out []string
	for n := range c.Locks {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
