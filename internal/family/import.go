package family

import (
	"fmt"
	"slices"
)

// Merge folds the lockfamily.yaml configurations of sub-workspaces into
// one. An instance declared in several keeps the strictest settings
// (routing is the intersection) and every difference is
// reported, for the human to read before lock up applies anything.
// The hub section comes from base.
func Merge(base *Config, others map[string]*Config) (*Config, []string) {
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
	var srcs []string
	for s := range others {
		srcs = append(srcs, s)
	}
	slices.Sort(srcs)
	for _, src := range srcs {
		o := others[src]
		for _, name := range o.Instances() {
			l := o.Locks[name]
			cur, ok := out.Locks[name]
			if !ok {
				out.Locks[name] = l
				if r, ok := o.Hub.Routing[name]; ok {
					out.Hub.Routing[name] = intersect(slices.Clone(r), out.Hub.Facades)
				}
				notes = append(notes, fmt.Sprintf("%s: adds lock %s (%s)", src, name, l.Type))
				continue
			}
			if cur.Type != l.Type {
				notes = append(notes, fmt.Sprintf("%s: lock %s is a %s here, a %s there: kept %s, rename one", src, name, cur.Type, l.Type, cur.Type))
				continue
			}
			if cur.Image != l.Image {
				notes = append(notes, fmt.Sprintf("%s: lock %s pins another image: kept %s", src, name, cur.Image))
			}
			if r, ok := o.Hub.Routing[name]; ok {
				before, had := out.Hub.Routing[name]
				if !had {
					before = slices.Clone(out.Hub.Facades)
				}
				after := intersect(slices.Clone(before), r)
				if !slices.Equal(before, after) {
					notes = append(notes, fmt.Sprintf("%s: lock %s routing narrowed to %v", src, name, after))
				}
				out.Hub.Routing[name] = after
			}
			out.Locks[name] = cur
		}
	}
	return &out, notes
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
