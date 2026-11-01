package family

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Facts are what the short review shows of a lock's profile: the few
// lines a human decides on, read from the [profiles.<name>] table of the
// profile's config.toml (lockkit's configuration refuses secrets in it).
type Facts struct {
	Target, Credentials, VaultPath string
	Production                     bool
	// Profile is the profile directory and its sha256 as the review shows
	// them, ".locksql/ sha256:…".
	Profile string
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
)

// ProfileFacts reads the facts of the profile named profile (empty: the
// only one) of a lock of type typ, from p's "config.toml:N text" lines.
// Other profiles' lines are not read.
func ProfileFacts(p *Profile, typ, profile string) Facts {
	f, _ := readFacts(p, typ, profile)
	return f
}

// readFacts is ProfileFacts and the profile lines it shows (the header
// and the last line of each key it read, as they appear in the summary
// after "profile <type> "): the short review must not hide any other.
func readFacts(p *Profile, typ, profile string) (Facts, []string) {
	f := Facts{}
	if p == nil {
		return f, nil
	}
	f.Profile = fmt.Sprintf(".%s/ %s", typ, p.Fingerprint)
	// The sections of config.toml: name -> key -> {value, raw line}.
	type kv struct{ val, raw string }
	secs := map[string]map[string]kv{}
	hdr := map[string]string{}
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
					secs[cur] = map[string]kv{}
					hdr[cur] = l
					order = append(order, cur)
				}
			}
			continue
		}
		if cur == "" {
			continue
		}
		if k := tomlKey.FindStringSubmatch(text); k != nil {
			secs[cur][k[1]] = kv{tomlValue(k[2]), l}
		}
	}
	name := profile
	if name == "" && len(order) == 1 {
		name = order[0]
	}
	sec, ok := secs[name]
	if !ok {
		return f, nil
	}
	covered := []string{hdr[name]}
	use := func(key string) string {
		v, ok := sec[key]
		if ok {
			covered = append(covered, v.raw)
		}
		return v.val
	}
	var parts []string
	switch typ {
	case "locksql":
		addr := use("host")
		if port := use("port"); port != "" {
			addr += ":" + port
		}
		if e := strings.TrimSpace(use("engine") + " " + addr); e != "" {
			parts = append(parts, e)
		}
		if d := use("database"); d != "" {
			parts = append(parts, "database "+d)
		}
	case "lockmq":
		if u := use("url"); u != "" {
			parts = append(parts, u)
		}
		if v := use("vhosts"); v != "" {
			parts = append(parts, "vhosts "+v)
		}
	case "lockfile":
		for _, k := range factKeys[typ] {
			if v := use(k); v != "" {
				parts = append(parts, k+" "+v)
			}
		}
	}
	f.Target = strings.Join(parts, ", ")
	f.Credentials = use("credentials")
	f.VaultPath = use("vault_path")
	f.Production, _ = strconv.ParseBool(use("production"))
	return f, covered
}

// tomlValue is a TOML value as text: a string without its quotes, an
// array as its elements joined by commas, anything else up to a comment.
func tomlValue(raw string) string {
	raw = strings.TrimSpace(raw)
	unq := func(s string) string {
		s = strings.TrimSpace(s)
		if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') {
			if i := strings.IndexByte(s[1:], s[0]); i >= 0 {
				return s[1 : 1+i]
			}
		}
		if i := strings.Index(s, " #"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		return s
	}
	if strings.HasPrefix(raw, "[") {
		if i := strings.IndexByte(raw, ']'); i >= 0 {
			raw = raw[1:i]
		}
		var out []string
		for _, e := range strings.Split(raw, ",") {
			if e = unq(e); e != "" {
				out = append(out, e)
			}
		}
		return strings.Join(out, ",")
	}
	return unq(raw)
}
