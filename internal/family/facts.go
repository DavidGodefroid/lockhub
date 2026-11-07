package family

import (
	"fmt"
	"regexp"
	"strings"
)

// Facts are what the short review shows of a lock's profile: the few
// lines a human decides on, read from the [profiles.<name>] table of the
// profile's config.toml (lockkit's configuration refuses secrets in it).
// A value the review cannot show exactly as the profile says it (an
// escape, a multi-line array, a string where a boolean belongs) is not
// shown as a fact: Odd holds the profile's own text of it by key, and the
// short form prints that instead.
type Facts struct {
	Target, Credentials, VaultPath string
	Production                     bool
	Odd                            map[string]string
	// Profile is the profile directory, its table and its sha256 as the
	// review shows them, ".locksql/ [profiles.orders] sha256:…".
	Profile string
	// Changed: the profile differs from the one the last lox up applied.
	Changed bool
	// Egress is the lock's allowlist as the short review shows it.
	Egress string
	// Unreachable are what the profile names that the lock reaches by
	// nothing (Egress.None): a row each, so none hides in the egress row.
	Unreachable []string
}

// factKeys are the keys read per lock type for the target.
var factKeys = map[string][]string{
	"locksql":  {"engine", "host", "port", "database"},
	"lockmq":   {"url", "vhosts"},
	"lockfile": {"source", "bucket", "endpoint", "base_dir"},
}

var (
	profileHeader = regexp.MustCompile(`^\[profiles\.(?:"([^"]+)"|([A-Za-z0-9_-]+))\]\s*(?:#.*)?$`)
	tomlKey       = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(.*)$`)
	tomlLine      = regexp.MustCompile(`^config\.toml:([0-9]+) (.*)$`)
	bareValue     = regexp.MustCompile(`^(?:[0-9]+|true|false)$`)
)

// ProfileFacts reads the facts of the profile named profile (empty: the
// only one) of a lock of type typ, from p's "config.toml:N text" lines.
// Other profiles' lines are not read.
func ProfileFacts(p *Profile, typ, profile string) Facts {
	f := Facts{}
	if p == nil {
		return f
	}
	f.Profile = fmt.Sprintf(".%s/ %s", typ, p.Fingerprint)
	// The tables of config.toml: name -> key -> value text (last wins).
	secs := map[string]map[string]string{}
	var order []string
	cur := ""
	for _, l := range p.Lines {
		m := tomlLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		text := strings.TrimSpace(m[2])
		if strings.HasPrefix(text, "[") {
			cur = ""
			if h := profileHeader.FindStringSubmatch(text); h != nil {
				cur = h[1] + h[2]
				if _, ok := secs[cur]; !ok {
					secs[cur] = map[string]string{}
					order = append(order, cur)
				}
			}
			continue
		}
		if cur == "" {
			continue
		}
		if k := tomlKey.FindStringSubmatch(text); k != nil {
			secs[cur][k[1]] = k[2]
		}
	}
	name := profile
	if name == "" && len(order) == 1 {
		name = order[0]
	}
	sec, ok := secs[name]
	if !ok {
		return f
	}
	f.Profile = fmt.Sprintf(".%s/ [profiles.%s] %s", typ, name, p.Fingerprint)
	// use returns the value of key as the profile says it, or "" when it
	// is absent or cannot be shown exactly (then Odd has its text).
	use := func(key string, want byte) string {
		raw, ok := sec[key]
		if !ok {
			return ""
		}
		v, kind, ok := strictValue(raw)
		if !ok || (want != 0 && kind != want) {
			if f.Odd == nil {
				f.Odd = map[string]string{}
			}
			f.Odd[key] = key + " = " + strings.TrimSpace(raw)
			return ""
		}
		return v
	}
	var parts []string
	switch typ {
	case "locksql":
		addr := use("host", 0)
		if port := use("port", 0); port != "" {
			addr += ":" + port
		}
		if e := strings.TrimSpace(use("engine", 0) + " " + addr); e != "" {
			parts = append(parts, e)
		}
		if d := use("database", 0); d != "" {
			parts = append(parts, "database "+d)
		}
	case "lockmq":
		if u := use("url", 0); u != "" {
			parts = append(parts, u)
		}
		if v := use("vhosts", 'a'); v != "" {
			parts = append(parts, "vhosts "+v)
		}
	case "lockfile":
		for _, k := range factKeys[typ] {
			if v := use(k, 0); v != "" {
				parts = append(parts, k+" "+v)
			}
		}
	}
	f.Credentials = use("credentials", 's')
	f.VaultPath = use("vault_path", 's')
	switch pv := use("production", 'b'); pv {
	case "true":
		f.Production = true
	case "false", "":
	default:
		// A number is not a boolean: shown as the profile says it.
		if f.Odd == nil {
			f.Odd = map[string]string{}
		}
		f.Odd["production"] = "production = " + pv
	}
	for _, k := range factKeys[typ] {
		if o, ok := f.Odd[k]; ok {
			parts = append(parts, "? ("+o+" in the profile)")
		}
	}
	f.Target = strings.Join(parts, ", ")
	return f
}

// strictValue is a TOML value of one line that can be shown exactly: a
// simple string (no escape), an array of simple strings, or a bare
// integer or boolean, each followed by nothing or a comment. kind is 's',
// 'a' or 'b'.
func strictValue(raw string) (val string, kind byte, ok bool) {
	raw = strings.TrimSpace(raw)
	tail := func(r string) bool { r = strings.TrimSpace(r); return r == "" || strings.HasPrefix(r, "#") }
	str := func(s string) (string, string, bool) {
		if s == "" || (s[0] != '"' && s[0] != '\'') {
			return "", "", false
		}
		i := strings.IndexByte(s[1:], s[0])
		if i < 0 {
			return "", "", false
		}
		in := s[1 : 1+i]
		if strings.ContainsRune(in, '\\') {
			return "", "", false
		}
		return in, s[2+i:], true
	}
	switch {
	case strings.HasPrefix(raw, "["):
		rest := strings.TrimSpace(raw[1:])
		var out []string
		for !strings.HasPrefix(rest, "]") {
			v, r, ok := str(rest)
			if !ok {
				return "", 0, false
			}
			out = append(out, v)
			rest = strings.TrimSpace(r)
			if t, found := strings.CutPrefix(rest, ","); found {
				rest = strings.TrimSpace(t)
			} else if !strings.HasPrefix(rest, "]") {
				return "", 0, false
			}
		}
		if !tail(rest[1:]) {
			return "", 0, false
		}
		return strings.Join(out, ","), 'a', true
	case raw != "" && (raw[0] == '"' || raw[0] == '\''):
		v, r, ok := str(raw)
		if !ok || !tail(r) {
			return "", 0, false
		}
		return v, 's', true
	}
	b, _, _ := strings.Cut(raw, "#")
	b = strings.TrimSpace(b)
	if !bareValue.MatchString(b) {
		return "", 0, false
	}
	return b, 'b', true
}
