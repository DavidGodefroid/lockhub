package family

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Merge folds the lockfamily.yaml configurations of sub-workspaces into
// base. An instance declared in several keeps its first declaration and
// the strictest routing (the facades that may answer it are those every
// declaration allows), and every difference is reported, for the human to read before lock up applies anything.
// The hub section comes from base; others are taken in the order of srcs.
func Merge(base *Config, srcs []string, others map[string]*Config) (*Config, []string) {
	out := *base
	out.Locks = map[string]Lock{}
	out.Hub.Routing = map[string][]string{}
	for k, v := range base.Locks {
		out.Locks[k] = v
	}
	for k, v := range base.Hub.Routing {
		out.Hub.Routing[k] = slices.Clone(v)
	}
	var notes []string
	for _, src := range srcs {
		o := others[src]
		for _, name := range o.Instances() {
			l := o.Locks[name]
			cur, ok := out.Locks[name]
			if !ok {
				out.Locks[name] = l
				fs := intersect(o.facadesOf(name), out.Hub.Facades)
				note := fmt.Sprintf("%s: adds lock %s (%s)", src, name, l.Type)
				if !sameSet(fs, out.Hub.Facades) {
					out.Hub.Routing[name] = fs
					note += ", routed only to " + strings.Join(fs, ",")
				}
				notes = append(notes, note)
				continue
			}
			if cur.Type != l.Type {
				notes = append(notes, fmt.Sprintf("%s: lock %s is a %s here, a %s there: kept %s, rename one", src, name, cur.Type, l.Type, cur.Type))
				continue
			}
			if cur.Image != l.Image {
				notes = append(notes, fmt.Sprintf("%s: lock %s pins another image (%s): kept %s", src, name, l.Image, cur.Image))
			}
			before := out.facadesOf(name)
			after := intersect(before, o.facadesOf(name))
			if !slices.Equal(before, after) {
				out.Hub.Routing[name] = after
				if len(after) == 0 {
					notes = append(notes, fmt.Sprintf("%s: lock %s: no facade left that every declaration allows", src, name))
				} else {
					notes = append(notes, fmt.Sprintf("%s: lock %s routing narrowed to %s", src, name, strings.Join(after, ",")))
				}
			}
			out.Locks[name] = cur
		}
	}
	return &out, notes
}

// facadesOf are the facades that may answer instance name.
func (c *Config) facadesOf(name string) []string {
	if fs, ok := c.Hub.Routing[name]; ok {
		return slices.Clone(fs)
	}
	return slices.Clone(c.Hub.Facades)
}

func intersect(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	return len(intersect(a, b)) == len(a) && len(intersect(b, a)) == len(b)
}

// Import merges the lockfamily.yaml files srcs (sub-projects) into the
// one at path, creating it from the first source's hub section when it
// does not exist. The result is validated before it is written; comments
// outside the locks and the routing are kept. It returns the notes to
// show the human; lock up reviews the change before applying it.
func Import(path string, srcs []string) ([]string, error) {
	if len(srcs) == 0 {
		return nil, errors.New("no lockfamily.yaml to import")
	}
	others := map[string]*Config{}
	for _, s := range srcs {
		if _, dup := others[s]; dup {
			return nil, fmt.Errorf("%s given twice", s)
		}
		c, err := Load(s)
		if err != nil {
			return nil, err
		}
		others[s] = c
	}
	var notes []string
	var doc yaml.Node
	var base *Config
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		first := srcs[0]
		h := others[first].Hub
		// Chat facades need their own allowlist: lock add slack.
		fs := slices.DeleteFunc(slices.Clone(h.Facades), isChat)
		base = &Config{Version: 1, Hub: Hub{Image: h.Image, Facades: fs}}
		notes = append(notes, fmt.Sprintf("%s does not exist: hub section from %s", path, first))
		if len(fs) != len(h.Facades) {
			notes = append(notes, "chat facades not enabled here: run lock add slack / lock add telegram to give them their allowlist")
		}
		b = []byte("version: 1\nhub:\n  image: " + h.Image + "\n  facades: [" + strings.Join(fs, ", ") + "]\n")
	case err != nil:
		return nil, err
	default:
		// The workspace may declare only its hub.
		if base, err = decode(b, path, false); err != nil {
			return nil, err
		}
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	merged, mn := Merge(base, srcs, others)
	notes = append(notes, mn...)

	root := doc.Content[0]
	locks := child(root, "locks")
	var ln yaml.Node
	if err := ln.Encode(merged.Locks); err != nil {
		return nil, err
	}
	*locks = ln
	hub := child(root, "hub")
	if len(merged.Hub.Routing) == 0 {
		remove(hub, "routing")
	} else {
		var rn yaml.Node
		if err := rn.Encode(merged.Hub.Routing); err != nil {
			return nil, err
		}
		*child(hub, "routing") = rn
	}
	out, _, err := encodeValid(&doc)
	if err != nil {
		return notes, fmt.Errorf("%s: not changed: %w", path, err)
	}
	return notes, writeFile(path, out)
}

func remove(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = slices.Delete(m.Content, i, i+2)
			return
		}
	}
}
