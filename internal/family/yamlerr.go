package family

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	yamlTypeErr = regexp.MustCompile(`^line (\d+): cannot unmarshal .* into (\S+)$`)
	// yamlQuoted is what yaml.v3 quotes of the input in its other
	// errors: 'anchor' or `value`.
	yamlQuoted = regexp.MustCompile("'[^']*'|`[^`]*`")
	// aliasLine is a "key: *alias" or "- *alias" line.
	aliasLine = regexp.MustCompile(`^\s*(?:-\s+)*(?:([^\s:#'"][^:#]*?)\s*:\s+)?\*`)
)

// scrubYAML drops the values yaml.v3 quotes in its errors (a type error
// quotes up to ten characters of what was typed, "cannot decode !!str
// `…` as a !!int" and "unknown anchor '…'" all of it: maybe a pasted
// secret). The line and the key path (found in b) stay, as does the
// wanted type.
func scrubYAML(err error, b []byte) error {
	if err == nil {
		return nil
	}
	var doc yaml.Node
	parsed := yaml.Unmarshal(b, &doc) == nil
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "unknown anchor"):
			where := ""
			for i, l := range strings.Split(string(b), "\n") {
				if m := aliasLine.FindStringSubmatch(l); m != nil {
					where = "line " + strconv.Itoa(i+1) + ": "
					if m[1] != "" {
						where += m[1] + ": "
					}
					break
				}
			}
			return errors.New("yaml: " + where + "an alias (*…) to an unknown anchor: quote a value that starts with *")
		case strings.Contains(msg, "cannot decode") && parsed:
			if where := badTag(&doc); where != "" {
				return errors.New("yaml: " + where + ": a value that is not of its explicit tag")
			}
		}
		return errors.New(yamlQuoted.ReplaceAllString(msg, "(value)"))
	}
	keys := map[int]string{}
	if parsed {
		keyLines(&doc, "", keys)
	}
	out := make([]string, len(te.Errors))
	for i, e := range te.Errors {
		m := yamlTypeErr.FindStringSubmatch(strings.ReplaceAll(e, "\n", " "))
		switch {
		case m == nil && strings.Contains(e, "cannot unmarshal"):
			out[i] = "a value of the wrong type"
		case m == nil:
			out[i] = yamlQuoted.ReplaceAllString(e, "(value)")
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

// badTag is "line N: key.path" of the first explicitly tagged scalar
// under n its tag does not decode (version: !!int abc), "" if none.
func badTag(n *yaml.Node) string {
	var found string
	walkYAML(n, "", func(c *yaml.Node, path string) {
		if found != "" || c.Kind != yaml.ScalarNode || c.Style&yaml.TaggedStyle == 0 {
			return
		}
		var v any
		if c.Decode(&v) != nil {
			found = "line " + strconv.Itoa(c.Line)
			if path != "" {
				found += ": " + path
			}
		}
	})
	return found
}

func walkYAML(n *yaml.Node, path string, fn func(*yaml.Node, string)) {
	fn(n, path)
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walkYAML(c, path, fn)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			p := n.Content[i].Value
			if path != "" {
				p = path + "." + p
			}
			walkYAML(n.Content[i+1], p, fn)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			walkYAML(c, path+"["+strconv.Itoa(i)+"]", fn)
		}
	}
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
