package family

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
		if key, ok := tableHeader(ln); ok && depth == 0 {
			drop := key == "profiles."+profile || strings.HasPrefix(key, "profiles."+profile+".")
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
	return WriteFileMode(path, []byte(strings.Join(out, "")), fi.Mode().Perm())
}

// tableHeader reports whether line is a TOML table header ([a.b] or
// [[a.b]]) and gives its dotted key without spaces or quotes.
func tableHeader(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	if i := strings.Index(t, "#"); i >= 0 && !strings.Contains(t[:i], `"`) {
		t = strings.TrimSpace(t[:i])
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
	if strings.HasPrefix(inner, "[") {
		inner = strings.TrimSuffix(strings.TrimPrefix(inner, "["), "]")
	}
	if inner == "" || strings.ContainsAny(inner, "[]=,") {
		return "", false
	}
	return strings.NewReplacer(" ", "", `"`, "", "'", "").Replace(inner), true
}

// bracketDelta is the opening minus the closing brackets of a value
// line, outside its strings and comment: an array spread over lines keeps
// its inner lines from being read as table headers.
func bracketDelta(line string) int {
	d := 0
	var q rune
	for _, r := range line {
		switch {
		case q != 0:
			if r == q {
				q = 0
			}
		case r == '"' || r == '\'':
			q = r
		case r == '#':
			return d
		case r == '[':
			d++
		case r == ']':
			d--
		}
	}
	return d
}

// appendKept adds the blank and comment lines kept after a removed table,
// without a blank line to open the file or to double one.
func appendKept(out, kept []string) []string {
	for len(kept) > 0 && strings.TrimSpace(kept[0]) == "" && (len(out) == 0 || strings.TrimSpace(out[len(out)-1]) == "") {
		kept = kept[1:]
	}
	return append(out, kept...)
}
