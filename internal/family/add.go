package family

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

// AddOptions is one `lock add`.
type AddOptions struct {
	Type, Name string
	// Image is the lock's image, pinned by digest.
	Image string
	// HubImage starts a fresh lockfamily.yaml; ignored when one exists.
	HubImage string
}

// Add appends a lock instance to the lockfamily.yaml at path, keeping its
// comments and order, or creates the file. What would be written is
// validated first: a refusal leaves the file as it was. Nothing is
// started (run lock up, which reviews the change).
func Add(path string, o AddOptions) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if o.HubImage == "" {
			return fmt.Errorf("%s does not exist: give --hub-image ghcr.io/davidgodefroid/lockhub@sha256:<digest> to start it", path)
		}
		b = []byte("version: 1\nhub:\n  image: " + o.HubImage + "\n")
	} else if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a lockfamily.yaml mapping", path)
	}
	locks := child(doc.Content[0], "locks")
	for i := 0; i < len(locks.Content); i += 2 {
		if locks.Content[i].Value == o.Name {
			return fmt.Errorf("lock %q already declared", o.Name)
		}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode}
	kv := func(k, v, tag string) {
		entry.Content = append(entry.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: v, Tag: tag})
	}
	kv("type", o.Type, "!!str")
	kv("image", o.Image, "!!str")
	locks.Content = append(locks.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: o.Name}, entry)
	out, c, err := encodeValid(&doc)
	if err != nil {
		return fmt.Errorf("%s: not changed: %w", path, err)
	}
	if !slices.Contains(c.Instances(), o.Name) {
		return fmt.Errorf("lock %q not added", o.Name)
	}
	return writeFile(path, out)
}

// child is the value of key in mapping m, created (as a flow-free
// mapping) when absent or null.
func child(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			v := m.Content[i+1]
			if v.Kind != yaml.MappingNode {
				*v = yaml.Node{Kind: yaml.MappingNode}
			}
			v.Style = 0
			return v
		}
	}
	v := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
	return v
}

// encodeValid encodes doc and validates the result the way Load does.
func encodeValid(doc *yaml.Node) ([]byte, *Config, error) {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(out.Bytes()))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, nil, err
	}
	return out.Bytes(), &c, nil
}

// writeFile replaces path through a fresh temporary file in its
// directory (the workspace is agent-writable: never a predictable name
// that a planted link could redirect), so that a crash never leaves half
// a lockfamily.yaml.
func writeFile(path string, b []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".lockfamily-*.yaml")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
