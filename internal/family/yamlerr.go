package family

import (
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DavidGodefroid/lockhub/internal/keys"
)

var (
	yamlTypeErr = regexp.MustCompile(`^line (\d+): cannot unmarshal .* into (\S+)$`)
	// yamlQuoted is what yaml.v3 quotes of the input in its other
	// errors: 'anchor' or `value`.
	yamlQuoted = regexp.MustCompile("(?s)'.*'|`.*`|\".*\"")
	// yamlOne is a quoted single character: the parser quotes
	// punctuation, ':' or ']', which may stay.
	yamlOne = regexp.MustCompile("'[^']'")
	// yamlLong is a quoted span of more than one character.
	yamlLong  = regexp.MustCompile("(?s)'[^']{2,}'|`[^`]{2,}`|\"[^\"]{2,}\"|'[^']*$|`[^`]*$|\"[^\"]*$")
	yamlField = regexp.MustCompile(`^line (\d+): field (.*) not found in type (\S+)$`)
	yamlDup   = regexp.MustCompile(`^line (\d+): mapping key .* already defined at line (\d+)$`)
	// fieldNames are the keys lockfamily.yaml knows: the only ones shown
	// (besides instance names), never a value pasted as a key.
	fieldNames = yamlFields(reflect.TypeOf(Config{}), map[string]bool{})
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
					if fieldNames[m[1]] {
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
			return errors.New("yaml: a value or key that is not of its explicit tag")
		case strings.Contains(msg, "cannot decode"):
			return errors.New("yaml: a value or key that is not of its explicit tag")
		}
		return errors.New(unquote(msg))
	}
	keys := map[int]string{}
	if parsed {
		keyLines(&doc, "", keys)
	}
	out := make([]string, len(te.Errors))
	for i, e := range te.Errors {
		e1 := strings.ReplaceAll(e, "\n", " ")
		m := yamlTypeErr.FindStringSubmatch(e1)
		if f := yamlField.FindStringSubmatch(e1); f != nil {
			out[i] = "line " + f[1] + ": an unknown key in " + f[3]
			if fieldNames[f[2]] {
				out[i] = "line " + f[1] + ": unknown key " + f[2] + " in " + f[3]
			}
			continue
		}
		if d := yamlDup.FindStringSubmatch(e1); d != nil {
			out[i] = "line " + d[1] + ": a key already defined at line " + d[2]
			continue
		}
		switch {
		case m == nil && strings.Contains(e, "cannot unmarshal"):
			out[i] = "a value of the wrong type"
		case m == nil:
			out[i] = unquote(e)
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
			p := showKey(path, n.Content[i].Value)
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
			p := showKey(path, n.Content[i].Value)
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

// showKey is k, a key under path, if it is a lockfamily.yaml key or an
// instance name (under locks and hub.routing), "(key)" otherwise.
func showKey(path, k string) string {
	if fieldNames[k] && path != "locks" && path != "hub.routing" || (path == "locks" || path == "hub.routing") && keys.ValidInstance(k) {
		return k
	}
	return "(key)"
}

// yamlFields adds the yaml key names of t's fields, and of the structs
// they hold, to seen.
func yamlFields(t reflect.Type, seen map[string]bool) map[string]bool {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return seen
	}
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); name != "" && name != "-" {
			seen[name] = true
		}
		yamlFields(f.Type, seen)
	}
	return seen
}

// unquote drops what msg quotes, unless it quotes single characters only.
func unquote(msg string) string {
	if !yamlLong.MatchString(yamlOne.ReplaceAllString(msg, "")) {
		return msg
	}
	return yamlQuoted.ReplaceAllString(msg, "(value)")
}
