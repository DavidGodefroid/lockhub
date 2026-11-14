package family

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// netSpec is a network as a compose file lox run made declares it: what
// lox run sets and the engine shows back.
type netSpec struct {
	internal bool
	subnets  []string
}

// declaredNets are the networks of a compose file lox run made, by
// compose key.
func declaredNets(composeYAML []byte) (map[string]netSpec, error) {
	var f struct {
		Networks map[string]*struct {
			Internal bool `yaml:"internal"`
			IPAM     struct {
				Config []struct {
					Subnet string `yaml:"subnet"`
				} `yaml:"config"`
			} `yaml:"ipam"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(composeYAML, &f); err != nil {
		return nil, fmt.Errorf("the compose file's networks: %w", err)
	}
	out := map[string]netSpec{}
	for k, n := range f.Networks {
		var s netSpec
		if n != nil {
			s.internal = n.Internal
			for _, c := range n.IPAM.Config {
				if p, err := netip.ParsePrefix(c.Subnet); err == nil {
					s.subnets = append(s.subnets, p.Masked().String())
				}
			}
		}
		slices.Sort(s.subnets)
		out[k] = s
	}
	return out, nil
}

// staleNets are the networks of project in place (nets, as the engine
// shows them) that the compose file about to be applied (want) declares
// differently: compose would remove and create them again, which fails
// while a container uses them (lockhub#199). A network the file sets no
// subnet for keeps whichever the engine gave it. Sorted, by compose key.
func staleNets(project string, want map[string]netSpec, nets []EngineNet) []string {
	var out []string
	for _, n := range nets {
		k := n.Labels["com.docker.compose.network"]
		w, ok := want[k]
		if !ok || n.Labels["com.docker.compose.project"] != project || n.Name != project+"_"+k {
			continue
		}
		var have []string
		for _, p := range n.Prefixes() {
			have = append(have, p.String())
		}
		slices.Sort(have)
		if n.Internal != w.internal || (len(w.subnets) > 0 && !slices.Equal(have, w.subnets)) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// projectContainers are the containers of project, running or not.
func projectContainers(ctx context.Context, run Runner, project string) ([]string, error) {
	out, err := run.Run(ctx, nil, "docker", "ps", "-a", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return nil, fmt.Errorf("listing the containers of %s: %w", project, err)
	}
	return strings.Fields(string(out)), nil
}

// StopStack stops and removes the containers of project and its
// networks; its volumes (the hub key, the profiles, the consoles' homes
// and sockets) are kept, and so is lox run's state directory. It tells
// how many containers and networks it removed. Nothing to stop is not an
// error.
func StopStack(ctx context.Context, run Runner, project string) (ctrs, nets int, err error) {
	ids, err := projectContainers(ctx, run, project)
	if err != nil {
		return 0, 0, err
	}
	if len(ids) > 0 {
		// Stopped first, as compose down does: the hub closes its
		// database. Without -v: no volume goes with them.
		if _, err := run.Run(ctx, nil, "docker", append([]string{"stop"}, ids...)...); err != nil {
			return 0, 0, fmt.Errorf("stopping the containers of %s: %w", project, err)
		}
		if _, err := run.Run(ctx, nil, "docker", append([]string{"rm"}, ids...)...); err != nil {
			return 0, 0, fmt.Errorf("removing the containers of %s: %w", project, err)
		}
	}
	out, err := run.Run(ctx, nil, "docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return len(ids), 0, fmt.Errorf("listing the networks of %s: %w", project, err)
	}
	ns := strings.Fields(string(out))
	if len(ns) > 0 {
		if _, err := run.Run(ctx, nil, "docker", append([]string{"network", "rm"}, ns...)...); err != nil {
			if why := InTheWay(err); why != "" {
				return len(ids), 0, errors.New(why)
			}
			return len(ids), 0, fmt.Errorf("removing the networks of %s: %w", project, err)
		}
	}
	return len(ids), len(ns), nil
}

// activeEndpoints is the engine refusing to remove a network a container
// still uses, with the network and, from Docker 25, the container.
var activeEndpoints = regexp.MustCompile(`network (\S+) has active endpoints(?: \(name:"?([^" ]+)"?)?`)

// IsActiveEndpoints reports whether err is the engine refusing to remove
// a network a container still uses (its message is on the command's
// stderr).
func IsActiveEndpoints(err error) bool {
	var re *RunError
	return errors.As(err, &re) && activeEndpoints.Match(re.Stderr) || err != nil && activeEndpoints.MatchString(err.Error())
}

// InTheWay explains an active endpoints refusal: the network, the
// container that uses it and how to clear it. "" for any other error.
func InTheWay(err error) string {
	if !IsActiveEndpoints(err) {
		return ""
	}
	s := err.Error()
	var re *RunError
	if errors.As(err, &re) && activeEndpoints.Match(re.Stderr) {
		s = string(re.Stderr)
	}
	m := activeEndpoints.FindStringSubmatch(s)
	nw, ctr := m[1], m[2]
	if ctr == "" {
		return fmt.Sprintf("the network %s of this workspace is still used by a container that is not this stack's (docker network inspect %s lists it): stop it or disconnect it (docker network disconnect %s CONTAINER), then lox run again", nw, nw, nw)
	}
	return fmt.Sprintf("the network %s of this workspace is still used by the container %s, which lox down did not stop: stop it (docker stop %s) or disconnect it (docker network disconnect %s %s), then lox run again", nw, ctr, ctr, nw, ctr)
}

// reconcile takes down the stack in place when the compose file about to
// be applied declares one of its networks differently and containers of
// the project are there to hold it (a stack an earlier lox made, left up
// or brought back by the engine): compose would recreate the network
// under them and fail (lockhub#199). Volumes and the state directory are
// kept. A dry run stops instead: it applies nothing. why names the
// upgrade, for the line said.
func (u *Up) reconcile(ctx context.Context, project string, composeYAML []byte, nets []EngineNet, why string) error {
	want, err := declaredNets(composeYAML)
	if err != nil {
		return err
	}
	stale := staleNets(project, want, nets)
	if len(stale) == 0 {
		return nil
	}
	ids, err := projectContainers(ctx, u.Run, project)
	if err != nil || len(ids) == 0 {
		// No container holds them: compose creates them again itself.
		return err
	}
	if u.DryRun {
		return fmt.Errorf("dry run: the stack in place declares its networks (%s) as an earlier lox did: lox run stops it first (volumes kept), a dry run changes nothing", strings.Join(stale, ", "))
	}
	if _, _, err := StopStack(ctx, u.Run, project); err != nil {
		return fmt.Errorf("stopping the previous stack: %w", err)
	}
	fmt.Fprintf(u.Out, "previous stack stopped (%s)\n", why)
	return nil
}

// upgradeWhy names what makes the stack in place an earlier one, for
// reconcile's line: the hub's upgrade when there is one.
func upgradeWhy(ups []upgraded) string {
	for _, g := range ups {
		if g.lock == "" && g.from != "" && g.to != "" {
			return "lockhub " + g.from + " → " + g.to
		}
	}
	return "its networks changed"
}

// endpointRetry is a Runner whose compose calls refused on a network
// still in use take the project's stack down and run once more
// (lockhub#199); the second refusal is explained (InTheWay).
type endpointRetry struct {
	Runner
	project string
	out     io.Writer
	// apply: the stack may be taken down (not a probe nor a dry run).
	apply bool
}

func (r endpointRetry) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	out, err := r.Runner.Run(ctx, stdin, name, args...)
	if err == nil || name != "docker" || len(args) == 0 || args[0] != "compose" || !IsActiveEndpoints(err) {
		return out, err
	}
	if !r.apply {
		return out, fmt.Errorf("%s (%w)", InTheWay(err), err)
	}
	if _, _, serr := StopStack(ctx, r.Runner, r.project); serr != nil {
		return out, fmt.Errorf("%w; stopping the stack to try again: %v", err, serr)
	}
	fmt.Fprintln(r.out, "a network of this workspace was still in use: previous stack stopped (volumes kept), trying again")
	out, err = r.Runner.Run(ctx, stdin, name, args...)
	if err != nil && IsActiveEndpoints(err) {
		return out, fmt.Errorf("%s (%w)", InTheWay(err), err)
	}
	return out, err
}
