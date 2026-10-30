// Package family is `lock up`: it reads a workspace's lockfamily.yaml,
// reviews every change of configuration or keys with the human, and runs
// the hub and the declared locks with Docker Compose.
package family

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
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
//
// A lock's profile (target, production, credentials) stays in the lock's
// own configuration; lockfamily.yaml only says which locks run and who
// may answer them.
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
	// Slack is who may answer on Slack (required when slack is enabled).
	Slack *chatconf.Slack `yaml:"slack,omitempty"`
	// Telegram is who may answer on Telegram (required when telegram is
	// enabled).
	Telegram *chatconf.Telegram `yaml:"telegram,omitempty"`
	// Mobile configures the mobile facade (required when mobile is
	// enabled).
	Mobile *Mobile `yaml:"mobile,omitempty"`
}

// Mobile is the mobile facade: the phone reaches the hub at Origin
// through the human's own TLS reverse proxy or tunnel, which forwards to
// 127.0.0.1:Port on the host (never the lock API, never the facade
// socket).
//
//	hub:
//	  facades: [tty, deck, mobile]
//	  mobile:
//	    origin: https://hub.example.ts.net
//	    port: 8444                       # default
//	    seal_clear: true                 # locks seal clear screens to paired phones
//	    require_device: [prod-write]     # locks accept only device-signed approvals of these
//	locks:
//	  crm-prod:
//	    type: locksql
//	    image: …
//	    devices: true                    # this lock pins the paired phones
type Mobile struct {
	Origin        string   `yaml:"origin"`
	Port          int      `yaml:"port,omitempty"`
	SealClear     bool     `yaml:"seal_clear,omitempty"`
	RequireDevice []string `yaml:"require_device,omitempty"`
}

func (m *Mobile) validate() error {
	u, err := url.Parse(m.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.String() != m.Origin || strings.ToLower(m.Origin) != m.Origin || u.Port() == "443" {
		return fmt.Errorf("mobile.origin: want an https origin as a browser writes it (https://host[:port], lowercase, no path), got %q", m.Origin)
	}
	if m.Port == 0 {
		m.Port = 8444
	}
	if m.Port < 1024 || m.Port > 65535 {
		return fmt.Errorf("mobile.port: want 1024-65535, got %d", m.Port)
	}
	for _, r := range m.RequireDevice {
		if !route.KnownRisk(r) {
			return fmt.Errorf("mobile.require_device: unknown risk class %q", r)
		}
	}
	return nil
}

// Lock is one lock instance.
type Lock struct {
	Type  string `yaml:"type"`
	Image string `yaml:"image"`
	// Profile is the name of the profile the console serves, in the
	// lock's own configuration (<workspace>/.<type>). Default: for
	// lockfile, whose console needs one, "default"; for the others, their
	// only profile, or the one typed at the console's terminal.
	Profile string `yaml:"profile,omitempty"`
	// Devices: the lock pins the paired phones (its image is on lockkit
	// v0.4.0 or later and takes --devices-file). Without it, the lock
	// refuses every decision taken on a phone.
	Devices bool `yaml:"devices,omitempty"`
}

var profileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Types are the lock types lock up knows, and their image repositories.
var Types = []string{"locksql", "lockmq", "lockfile", "lockhttp"}

var digestRef = regexp.MustCompile(`^ghcr\.io/davidgodefroid/([a-z]+)@sha256:[0-9a-f]{64}$`)

// Load reads and validates path.
func Load(path string) (*Config, error) {
	b, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	return decode(b, path, true)
}

// readConfig reads the lockfamily.yaml at path; in .lockfamily, only once
// the directory is the user's own that no one else writes (not a link).
func readConfig(path string) ([]byte, error) {
	if !Legacy(path) {
		if err := ownDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
	}
	return os.ReadFile(path)
}

// decode parses and validates a lockfamily.yaml; needLocks refuses one
// without locks (lock up has nothing to run then).
func decode(b []byte, path string, needLocks bool) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w (a lock's target, production flag and credentials belong to its own profile, never here)", path, err)
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
	switch on := slices.Contains(c.Hub.Facades, route.Slack); {
	case on && c.Hub.Slack == nil:
		return fmt.Errorf("hub.slack: the slack facade needs its allowlist (team, channel, users): run lock add slack")
	case !on && c.Hub.Slack != nil:
		return fmt.Errorf("hub.slack: set, but slack is not in hub.facades")
	case on:
		if err := c.Hub.Slack.Validate(); err != nil {
			return fmt.Errorf("hub.%w", err)
		}
	}
	switch on := slices.Contains(c.Hub.Facades, route.Telegram); {
	case on && c.Hub.Telegram == nil:
		return fmt.Errorf("hub.telegram: the telegram facade needs its allowlist (chats): run lock add telegram")
	case !on && c.Hub.Telegram != nil:
		return fmt.Errorf("hub.telegram: set, but telegram is not in hub.facades")
	case on:
		if err := c.Hub.Telegram.Validate(); err != nil {
			return fmt.Errorf("hub.%w", err)
		}
	}
	switch on := slices.Contains(c.Hub.Facades, route.Mobile); {
	case on && c.Hub.Mobile == nil:
		return fmt.Errorf("hub.mobile: the mobile facade needs its origin (hub.mobile.origin)")
	case !on && c.Hub.Mobile != nil:
		return fmt.Errorf("hub.mobile: set, but mobile is not in hub.facades")
	case on:
		if err := c.Hub.Mobile.validate(); err != nil {
			return fmt.Errorf("hub.%w", err)
		}
	}
	if needLocks && len(c.Locks) == 0 {
		return fmt.Errorf("locks: none declared")
	}
	for name, l := range c.Locks {
		if !keys.ValidInstance(name) {
			return fmt.Errorf("locks: bad instance name %q (lower case, digits and -)", name)
		}
		if name == "hub" {
			return fmt.Errorf("locks: %q is reserved (the hub's own network is egress-hub)", name)
		}
		if !slices.Contains(Types, l.Type) {
			return fmt.Errorf("locks.%s.type: want one of %s", name, strings.Join(Types, ", "))
		}
		if l.Profile != "" && !profileName.MatchString(l.Profile) {
			return fmt.Errorf("locks.%s.profile: a profile name (letters, digits, _ . -)", name)
		}
		if m := digestRef.FindStringSubmatch(l.Image); m == nil || m[1] != l.Type {
			return fmt.Errorf("locks.%s.image: want ghcr.io/davidgodefroid/%s@sha256:<digest>", name, l.Type)
		}
		if l.Devices && c.Hub.Mobile == nil {
			return fmt.Errorf("locks.%s.devices: set, but the mobile facade is not configured (hub.mobile)", name)
		}
	}
	if m := c.Hub.Mobile; m != nil && (m.SealClear || len(m.RequireDevice) > 0) && !c.anyDevices() {
		return fmt.Errorf("hub.mobile: seal_clear and require_device apply to the locks that pin the devices: set devices: true on them")
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

// ChatEnabled reports whether a chat facade (which needs a route out to
// its service) is enabled.
func (c *Config) ChatEnabled() bool {
	return slices.ContainsFunc(c.Hub.Facades, isChat)
}

func isChat(f string) bool { return f == route.Slack || f == route.Telegram }

// Instances are the instance names, sorted.
func (c *Config) Instances() []string {
	var out []string
	for n := range c.Locks {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
