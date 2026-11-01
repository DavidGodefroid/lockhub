package family

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// RemoveLock takes the lock instance name out of the lockfamily.yaml at
// path (and out of hub.routing), keeping the file's comments and order.
// The lock's profile stays in its own directory. What would be written
// is validated first: a refusal leaves the file as it was. Nothing is
// stopped: lox up reviews the change, then removes the lock's container.
func RemoveLock(path, name string) error {
	b, err := readConfig(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, scrubYAML(err, b))
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a lockfamily.yaml mapping", path)
	}
	root := doc.Content[0]
	if !dropKey(lookup(root, "locks"), name) {
		return fmt.Errorf("no lock %q in %s", name, path)
	}
	if hub := lookup(root, "hub"); hub != nil {
		if r := lookup(hub, "routing"); r != nil {
			dropKey(r, name)
		}
	}
	out, c, err := encodeValid(&doc)
	if err != nil {
		return fmt.Errorf("%s: not changed: %w", path, err)
	}
	if slices.Contains(c.Instances(), name) {
		return fmt.Errorf("lock %q not removed", name)
	}
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	return writeFile(path, out)
}

// lookup is the mapping value of key in m (nil when absent or not a
// mapping).
func lookup(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i+1].Kind == yaml.MappingNode {
			return m.Content[i+1]
		}
	}
	return nil
}

// dropKey removes key from the mapping m and reports whether it was
// there.
func dropKey(m *yaml.Node, key string) bool {
	if m == nil {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// RemoveProfile takes the table [profiles.PROFILE] (and its sub-tables)
// out of dir/config.toml, a lock's own configuration, keeping the rest of
// the file as it is: the other profiles, the comments, the file's mode.
// The file is edited line by line, never parsed and rewritten, so a
// multi-line string (which could hide a table header) is refused: the
// file is then left as it was, and the human removes the table.
func RemoveProfile(dir, profile string) error {
	path := filepath.Join(dir, "config.toml")
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Contains(b, []byte(`"""`)) || bytes.Contains(b, []byte(`'''`)) {
		return fmt.Errorf("config.toml holds a multi-line string: remove [profiles.%s] by hand", profile)
	}
	lines := strings.SplitAfter(string(b), "\n")
	var out []string
	var found, skipping bool
	depth := 0
	// pending are the blank and comment lines met while skipping: they
	// belong to the next table when one follows, and stay.
	var pending []string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if depth == 0 && strings.HasPrefix(strings.TrimSpace(ln), "[") {
			segs, err := tableHeader(ln)
			if err != nil {
				return fmt.Errorf("%s: cannot be edited safely (%v): remove [profiles.%s] by hand", path, err, profile)
			}
			drop := len(segs) >= 2 && segs[0] == "profiles" && segs[1] == profile
			if skipping && !drop {
				out = appendKept(out, pending)
			}
			pending = nil
			skipping = drop
			found = found || drop
			if drop {
				continue
			}
			out = append(out, ln)
			continue
		}
		if skipping {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				pending = append(pending, ln)
				continue
			}
			// A value line belongs to the removed table: whatever was
			// pending sat inside it.
			pending = nil
			depth = max(0, depth+bracketDelta(ln))
			continue
		}
		depth = max(0, depth+bracketDelta(ln))
		out = append(out, ln)
	}
	if skipping {
		out = appendKept(out, pending)
	}
	if !found {
		return fmt.Errorf("no profile %q in %s", profile, path)
	}
	// Safety net: unbalanced brackets, or a result that a real TOML parser
	// does not read as the original less the profile, leave the file as it
	// is.
	res := []byte(strings.Join(out, ""))
	if depth != 0 {
		return fmt.Errorf("%s: cannot be edited safely (unbalanced brackets): remove [profiles.%s] by hand", path, profile)
	}
	if err := checkProfileEdit(b, res, profile); err != nil {
		return fmt.Errorf("%s: cannot be edited safely (%v): remove [profiles.%s] by hand", path, err, profile)
	}
	return WriteFileMode(path, res, fi.Mode().Perm())
}

// tableHeader parses a table header line ([a.b] or [[a.b]], a trailing
// comment allowed) into its key segments: bare, "basic" (with escapes) or
// 'literal' keys, whitespace trimmed outside quotes only.
func tableHeader(line string) ([]string, error) {
	t := strings.TrimSpace(cutComment(strings.TrimSpace(line)))
	inner, ok := strings.CutPrefix(t, "[[")
	if ok {
		if inner, ok = strings.CutSuffix(inner, "]]"); !ok {
			return nil, errors.New("unreadable table header")
		}
	} else {
		inner = strings.TrimPrefix(t, "[")
		if inner, ok = strings.CutSuffix(inner, "]"); !ok {
			return nil, errors.New("unreadable table header")
		}
	}
	var segs []string
	rs := []rune(inner)
	i := 0
	skip := func() {
		for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t') {
			i++
		}
	}
	for {
		skip()
		var seg strings.Builder
		switch {
		case i >= len(rs):
			return nil, errors.New("unreadable table header")
		case rs[i] == '\'':
			i++
			for i < len(rs) && rs[i] != '\'' {
				seg.WriteRune(rs[i])
				i++
			}
			if i >= len(rs) {
				return nil, errors.New("unreadable table header")
			}
			i++
		case rs[i] == '"':
			i++
			for {
				if i >= len(rs) {
					return nil, errors.New("unreadable table header")
				}
				if rs[i] == '"' {
					i++
					break
				}
				if rs[i] == '\\' {
					// The escaped character stands for itself or its
					// control character; a \u form is kept apart by its
					// raw text (no profile name is written so).
					i++
					if i >= len(rs) {
						return nil, errors.New("unreadable table header")
					}
					seg.WriteRune('\\')
				}
				seg.WriteRune(rs[i])
				i++
			}
		default:
			start := i
			for i < len(rs) && (rs[i] >= 'a' && rs[i] <= 'z' || rs[i] >= 'A' && rs[i] <= 'Z' || rs[i] >= '0' && rs[i] <= '9' || rs[i] == '_' || rs[i] == '-') {
				i++
			}
			if i == start {
				return nil, errors.New("unreadable table header")
			}
			seg.WriteString(string(rs[start:i]))
		}
		segs = append(segs, seg.String())
		skip()
		if i >= len(rs) {
			return segs, nil
		}
		if rs[i] != '.' {
			return nil, errors.New("unreadable table header")
		}
		i++
	}
}

// checkProfileEdit is the oracle: a real TOML parser reads the original
// and the result, and the result must be the original with only
// [profiles.PROFILE] gone. The line editor keeps the bytes; this decides
// whether its work may be written.
func checkProfileEdit(orig, out []byte, profile string) error {
	var before, after map[string]any
	if _, err := toml.Decode(string(orig), &before); err != nil {
		return errors.New("not valid TOML")
	}
	if _, err := toml.Decode(string(out), &after); err != nil {
		return errors.New("the result is not valid TOML")
	}
	profiles, ok := before["profiles"].(map[string]any)
	if !ok {
		return errors.New("no profiles table")
	}
	delete(profiles, profile)
	// An empty [profiles] is the same as none.
	if len(profiles) == 0 {
		delete(before, "profiles")
	}
	if p, ok := after["profiles"].(map[string]any); ok && len(p) == 0 {
		delete(after, "profiles")
	}
	if !reflect.DeepEqual(sameNaN(before), sameNaN(after)) {
		return errors.New("the result differs from the file less the profile")
	}
	return nil
}

// tomlNaN stands for a nan float: NaN is not equal to itself, so a file
// holding one would never compare equal to its unchanged self.
type tomlNaN struct{}

// sameNaN is v with every nan float replaced by tomlNaN{}.
func sameNaN(v any) any {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) {
			return tomlNaN{}
		}
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = sameNaN(e)
		}
		return m
	case []map[string]any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = sameNaN(e)
		}
		return s
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = sameNaN(e)
		}
		return s
	}
	return v
}

// cutComment is line without its trailing comment: a # inside a string
// (basic strings take backslash escapes, literal ones do not) is not one.
func cutComment(line string) string {
	var q rune
	esc := false
	for i, r := range line {
		switch {
		case esc:
			esc = false
		case q == '"' && r == '\\':
			esc = true
		case q != 0:
			if r == q {
				q = 0
			}
		case r == '"' || r == '\'':
			q = r
		case r == '#':
			return line[:i]
		}
	}
	return line
}

// bracketDelta is the opening minus the closing brackets of a value
// line, outside its strings and comment: an array spread over lines keeps
// its inner lines from being read as table headers.
func bracketDelta(line string) int {
	d := 0
	var q rune
	esc := false
	for _, r := range cutComment(line) {
		switch {
		case esc:
			esc = false
		case q == '"' && r == '\\':
			esc = true
		case q != 0:
			if r == q {
				q = 0
			}
		case r == '"' || r == '\'':
			q = r
		case r == '[':
			d++
		case r == ']':
			d--
		}
	}
	return d
}

// appendKept adds the blank and comment lines kept after a removed table,
// without a blank line to open the file or to double one: blank lines
// next to the removed table fold into the one already there.
func appendKept(out, kept []string) []string {
	for len(kept) > 0 && strings.TrimSpace(kept[0]) == "" && (len(out) == 0 || strings.TrimSpace(out[len(out)-1]) == "") {
		kept = kept[1:]
	}
	return append(out, kept...)
}
