package family

import (
	"fmt"
	"os"
	"slices"

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
