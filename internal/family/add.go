package family

import (
	"bytes"
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Add appends lock instance name of type typ (image pinned by digest) to
// the lockfamily.yaml at path, keeping its comments and order. The file
// is validated before it is written; nothing is started (run lock up).
func Add(path, typ, name, image string, production bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a lockfamily.yaml mapping", path)
	}
	root := doc.Content[0]
	var locks *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "locks" {
			locks = root.Content[i+1]
		}
	}
	if locks == nil {
		locks = &yaml.Node{Kind: yaml.MappingNode}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "locks"}, locks)
	}
	for i := 0; i < len(locks.Content); i += 2 {
		if locks.Content[i].Value == name {
			return fmt.Errorf("lock %q already declared", name)
		}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode}
	kv := func(k, v string, tag string) {
		entry.Content = append(entry.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: v, Tag: tag})
	}
	kv("type", typ, "")
	kv("image", image, "")
	if production {
		kv("production", "true", "!!bool")
	}
	locks.Content = append(locks.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: name}, entry)
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	// Validate what we are about to write.
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if !slices.Contains(c.Instances(), name) {
		return fmt.Errorf("lock %q not added", name)
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}
