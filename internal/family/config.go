// Package family is `lock up`: it reads a workspace's lockfamily.yaml,
// reviews every change of configuration or keys with the human, and runs
// the hub and the declared locks with Docker Compose.
package family

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
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
//	    push: true                       # payload-less Web Push to the paired phones
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
	// Push: the hub wakes the paired phones with payload-less Web Push
	// when a ticket they may answer is pending (the hub gets a route out,
	// to the known push services only).
	Push bool `yaml:"push,omitempty"`
}

func (m *Mobile) validate() error {
	u, err := url.Parse(m.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.String() != m.Origin || strings.ToLower(m.Origin) != m.Origin || u.Port() == "443" {
		return errors.New("mobile.origin: want an https origin as a browser writes it (https://host[:port], lowercase, no path, no user info)")
	}
	if m.Port == 0 {
		m.Port = 8444
	}
	if m.Port < 1024 || m.Port > 65535 {
		return fmt.Errorf("mobile.port: want 1024-65535, got %d", m.Port)
	}
	for i, r := range m.RequireDevice {
		if !route.KnownRisk(r) {
			return fmt.Errorf("mobile.require_device[%d]: unknown risk class (want one of %s)", i, strings.Join(route.Risks(), ", "))
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
	// refuses every decision taken on a phone. For lockhttp, the pins are
	// lea's gate's (up.json devices, lockhttp v0.4.0 or later, lea#209).
	Devices bool `yaml:"devices,omitempty"`
	// Reveal: the lock pins the host facades' keys (its image is on
	// lockkit v0.5.0 or later and takes --facade-keys-file), so Ctrl-O on
	// the terminal or the deck can reveal its clear screen. Without it the
	// lock refuses reveals; renewals need no facade key.
	Reveal bool `yaml:"reveal,omitempty"`
	// AllowedUIDs may reach the lock's console besides the members of its
	// clients group (`console --allowed-uids`, locksql v0.11.2, lockmq
	// v0.4.1 and lockfile v0.5.1 or later): the uid lea's agents run as
	// (the host user's), which names no account in the lock's image.
	// Not on lockhttp: a lockhttp lock is reached by lea's gate, an
	// account of its image.
	AllowedUIDs UIDList `yaml:"allowed_uids,omitempty"`
}

// UIDList is allowed_uids: a YAML list of plain decimal integers, as the
// consoles' --allowed-uids takes them. yaml.v3 alone would also take
// 1000.9, 0x3e8 or 1_000 for an int.
type UIDList []int

var plainUID = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)

// UnmarshalYAML takes a sequence of untagged or !!int decimal scalars.
func (u *UIDList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: allowed_uids: want a list of uids, [1000]", n.Line)
	}
	var out UIDList
	for i, e := range n.Content {
		if e.Kind != yaml.ScalarNode || e.Tag != "!!int" || !plainUID.MatchString(e.Value) {
			return fmt.Errorf("line %d: allowed_uids[%d]: not a uid (decimal, no sign, no leading zero)", e.Line, i)
		}
		v, err := strconv.ParseInt(e.Value, 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: allowed_uids[%d]: not a uid", e.Line, i)
		}
		out = append(out, int(v))
	}
	*u = out
	return nil
}

// MarshalYAML writes the list in flow style, [1000, 1001].
func (u UIDList) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, v := range u {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)})
	}
	return n, nil
}

// AllowedUIDTypes are the lock types whose console takes --allowed-uids.
var AllowedUIDTypes = []string{"locksql", "lockmq", "lockfile"}

// validAllowedUIDs checks a lock's allowed_uids: uids (not root, not the
// console's own, not -1), each once, for a type that takes them.
func validAllowedUIDs(name string, l Lock) error {
	if len(l.AllowedUIDs) == 0 {
		return nil
	}
	if !slices.Contains(AllowedUIDTypes, l.Type) {
		return fmt.Errorf("locks.%s.allowed_uids: a %s console takes none (only %s)", name, l.Type, strings.Join(AllowedUIDTypes, ", "))
	}
	for i, u := range l.AllowedUIDs {
		switch {
		case u <= 0 || int64(u) >= 1<<32-1: // 2^32-1 is (uid_t)-1
			return fmt.Errorf("locks.%s.allowed_uids: %d is root or not a uid", name, u)
		case u == 65534:
			return fmt.Errorf("locks.%s.allowed_uids: 65534 is nobody, the kernel's overflow uid", name)
		case strconv.Itoa(u) == Kinds[l.Type].UID:
			return fmt.Errorf("locks.%s.allowed_uids: %d is the console's own uid", name, u)
		case slices.Contains(l.AllowedUIDs[:i], u):
			return fmt.Errorf("locks.%s.allowed_uids: %d is listed twice", name, u)
		}
	}
	return nil
}

// AllowedUIDsFlag is the console's --allowed-uids value for l ("" when none).
func (l Lock) AllowedUIDsFlag() string {
	s := make([]string, len(l.AllowedUIDs))
	for i, u := range l.AllowedUIDs {
		s[i] = strconv.Itoa(u)
	}
	return strings.Join(s, ",")
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
		return nil, fmt.Errorf("%s: %w (a lock's target, production flag and credentials belong to its own profile, never here)", path, scrubYAML(err, b))
	}
	if err := c.validate(needLocks); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

var yamlTypeErr = regexp.MustCompile(`^line (\d+): cannot unmarshal .* into (\S+)$`)

// scrubYAML drops the values yaml.v3 quotes in its type errors ("cannot
// unmarshal !!str `glsa_Ca...` into int": up to ten characters of what
// was typed, maybe a pasted secret): the line, the key (found in b) and
// the wanted type stay.
func scrubYAML(err error, b []byte) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return err
	}
	var doc yaml.Node
	keys := map[int]string{}
	if yaml.Unmarshal(b, &doc) == nil {
		keyLines(&doc, "", keys)
	}
	out := make([]string, len(te.Errors))
	for i, e := range te.Errors {
		m := yamlTypeErr.FindStringSubmatch(strings.ReplaceAll(e, "\n", " "))
		switch {
		case m == nil && strings.Contains(e, "cannot unmarshal"):
			out[i] = "a value of the wrong type"
		case m == nil:
			out[i] = e
		default:
			out[i] = "line " + m[1] + ": "
			if n, _ := strconv.Atoi(m[1]); keys[n] != "" {
				out[i] += keys[n] + ": "
			}
			out[i] += "a value of the wrong type, want " + m[2]
		}
	}
	return &yaml.TypeError{Errors: out}
}

// keyLines maps the line of each value under n to its key path
// (hub.mobile.port, locks.crm.allowed_uids[0]); a line of several values
// (a flow list or mapping) to the path of the collection holding them.
func keyLines(n *yaml.Node, path string, out map[int]string) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			keyLines(c, path, out)
		}
		return
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if path != "" {
				p = path + "." + p
			}
			leaf(n.Content[i+1], p, path, out)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			leaf(c, path+"["+strconv.Itoa(i)+"]", path, out)
		}
	}
	if _, ok := out[n.Line]; !ok && path != "" {
		out[n.Line] = path
	}
}

func leaf(n *yaml.Node, path, parent string, out map[int]string) {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		keyLines(n, path, out)
		return
	}
	if p, ok := out[n.Line]; ok && p != path {
		out[n.Line] = parent
		return
	}
	out[n.Line] = path
}

// Validate checks c and fills defaults.
func (c *Config) Validate() error { return c.validate(true) }

func (c *Config) validate(needLocks bool) error {
	if c.Version != 1 {
		return fmt.Errorf("version: want 1, got %d", c.Version)
	}
	if m := digestRef.FindStringSubmatch(c.Hub.Image); m == nil || m[1] != "lockhub" {
		return errors.New("hub.image: want ghcr.io/davidgodefroid/lockhub@sha256:<digest>")
	}
	if len(c.Hub.Facades) == 0 {
		c.Hub.Facades = []string{route.TTY, route.Deck}
	}
	for i, f := range c.Hub.Facades {
		if !route.KnownFacade(f) {
			return fmt.Errorf("hub.facades[%d]: unknown facade (want one of %s)", i, strings.Join(route.Facades(), ", "))
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
		if err := validAllowedUIDs(name, l); err != nil {
			return err
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
		for i, f := range fs {
			if !slices.Contains(c.Hub.Facades, f) {
				return fmt.Errorf("hub.routing.%s[%d]: not a facade enabled in hub.facades (%s)", inst, i, strings.Join(c.Hub.Facades, ", "))
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

// MobilePush reports whether the mobile facade sends Web Push.
func (c *Config) MobilePush() bool { return c.Hub.Mobile != nil && c.Hub.Mobile.Push }

// HubEgress reports whether the hub needs a route out: a chat facade's
// service, the push services.
func (c *Config) HubEgress() bool { return c.ChatEnabled() || c.MobilePush() }

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
