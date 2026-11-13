package family

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DefaultNetworkPool is the range lox run takes its networks' subnets
// from when lockfamily.yaml sets no network.pool (lockhub#175). Each
// network gets a small subnet of its own, set in the compose file: none
// comes from the engine's default address pools, which a few compose
// projects exhaust (about 31 networks on a stock Docker).
const DefaultNetworkPool = "10.123.0.0/16"

// Subnet sizes: the hub's network holds the hub, every lock and lea's
// gates; the others two or three containers each.
const (
	hubNetBits  = 24
	lockNetBits = 28
)

// netBits is the prefix length of network key's subnet.
func netBits(key string) int {
	if key == "lockhub" {
		return hubNetBits
	}
	return lockNetBits
}

// Pool is the range lox run takes subnets from: network.pool, or
// DefaultNetworkPool.
func (c *Config) Pool() netip.Prefix {
	if c.Network != nil && c.Network.Pool != "" {
		if p, err := netip.ParsePrefix(c.Network.Pool); err == nil {
			return p
		}
	}
	return netip.MustParsePrefix(DefaultNetworkPool)
}

// validPool is the rule of network.pool: a private IPv4 range that holds
// at least the hub's network.
func validPool(s string) error {
	p, err := netip.ParsePrefix(s)
	bad := errors.New("network.pool: want a private IPv4 range of /8 to /24 in CIDR form, e.g. " + DefaultNetworkPool)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > hubNetBits || p.Masked() != p {
		return bad
	}
	for _, r := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if rp := netip.MustParsePrefix(r); rp.Bits() <= p.Bits() && rp.Contains(p.Addr()) {
			return nil
		}
	}
	return bad
}

// NetKeys are the compose networks lockfamily.yaml can give the
// workspace, in the compose file's order: a lock's locknet, gwlink and
// out-<name> whether or not its plan and allowlist need them (a subnet
// is only taken once the network exists).
func NetKeys(c *Config) []string {
	keys := []string{"lockhub"}
	if c.HubEgress() {
		keys = append(keys, "egress-hub")
	}
	if c.Hub.Mobile != nil {
		keys = append(keys, "mobile-hub")
	}
	for _, n := range c.Instances() {
		if Kinds[c.Locks[n].Type].Gate {
			keys = append(keys, "egress-"+n)
			continue
		}
		keys = append(keys, "locknet-"+n, "gwlink-"+n, "out-"+n)
	}
	return keys
}

// EngineNet is a network the engine has, as docker network inspect
// prints it (Docker's form, or Podman's subnets).
type EngineNet struct {
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
	IPAM   struct {
		Config []struct {
			Subnet string `json:"Subnet"`
		} `json:"Config"`
	} `json:"IPAM"`
	Subnets []struct {
		Subnet string `json:"subnet"`
	} `json:"subnets"`
}

// Prefixes are the network's IPv4 subnets.
func (n EngineNet) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	add := func(s string) {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	for _, c := range n.IPAM.Config {
		add(c.Subnet)
	}
	for _, s := range n.Subnets {
		add(s.Subnet)
	}
	return out
}

// ReadEngineNets lists the engine's networks with their subnets.
func ReadEngineNets(ctx context.Context, run Runner) ([]EngineNet, error) {
	out, err := run.Run(ctx, nil, "docker", "network", "ls", "-q", "--no-trunc")
	if err != nil {
		return nil, fmt.Errorf("listing the engine's networks: %w", err)
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return nil, nil
	}
	out, err = run.Run(ctx, nil, "docker", append([]string{"network", "inspect"}, ids...)...)
	if err != nil {
		return nil, fmt.Errorf("reading the engine's networks: %w", err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}
	var nets []EngineNet
	if err := json.Unmarshal(out, &nets); err != nil {
		return nil, fmt.Errorf("reading the engine's networks: %w", err)
	}
	return nets, nil
}

// ErrPoolFull is a network pool with no free subnet left for a network
// of the workspace.
var ErrPoolFull = errors.New("no free subnet left in the network pool")

// AllocSubnets gives each of keys a subnet of pool that no other network
// of the engine overlaps. A network the project has already keeps its
// subnet when it is still a free one of the right size in pool, so that
// lox run leaves it (and its containers) as they are; the others take
// the first free block, in keys' order. Two workspaces never get
// overlapping subnets: each one's networks are the other's used ones.
func AllocSubnets(pool netip.Prefix, project string, keys []string, nets []EngineNet) (map[string]netip.Prefix, error) {
	mine := map[string]bool{}
	for _, k := range keys {
		mine[k] = true
	}
	var used []netip.Prefix
	have := map[string][]netip.Prefix{}
	for _, n := range nets {
		if k := n.Labels["com.docker.compose.network"]; n.Labels["com.docker.compose.project"] == project && mine[k] && n.Name == project+"_"+k {
			have[k] = n.Prefixes()
			continue
		}
		used = append(used, n.Prefixes()...)
	}
	free := func(p netip.Prefix, taken []netip.Prefix) bool {
		for _, u := range taken {
			if u.Overlaps(p) {
				return false
			}
		}
		return true
	}
	out := map[string]netip.Prefix{}
	for _, k := range keys {
		if ps := have[k]; len(ps) == 1 && ps[0].Bits() == netBits(k) && pool.Bits() <= ps[0].Bits() && pool.Contains(ps[0].Addr()) && free(ps[0], used) {
			out[k] = ps[0]
			used = append(used, ps[0])
		}
	}
	for _, k := range keys {
		if _, ok := out[k]; ok {
			continue
		}
		p, ok := firstFree(pool, netBits(k), func(p netip.Prefix) bool { return free(p, used) })
		if !ok {
			return nil, fmt.Errorf("%w: %s holds no free /%d for network %s (%d networks of the engine use it): docker network prune removes the unused ones, or set network.pool in lockfamily.yaml to a larger private range (docs/networks.md)", ErrPoolFull, pool, netBits(k), k, inPool(pool, used))
		}
		out[k] = p
		used = append(used, p)
	}
	return out, nil
}

// firstFree is the first block of /bits in pool that ok accepts.
func firstFree(pool netip.Prefix, bits int, ok func(netip.Prefix) bool) (netip.Prefix, bool) {
	if bits < pool.Bits() || bits > 32 {
		return netip.Prefix{}, false
	}
	step := uint32(1) << (32 - bits)
	b := pool.Masked().Addr().As4()
	start := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := uint64(1) << (bits - pool.Bits())
	for i := uint64(0); i < n; i++ {
		a := start + uint32(i)*step
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)}), bits)
		if ok(p) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// inPool counts the subnets of used inside pool.
func inPool(pool netip.Prefix, used []netip.Prefix) int {
	n := 0
	for _, u := range used {
		if u.Overlaps(pool) {
			n++
		}
	}
	return n
}

// AddressPool is one of the engine's default address pools: base split
// into subnets of /size.
type AddressPool struct {
	Base string `json:"Base"`
	Size int    `json:"Size"`
}

// DockerDefaultPools are a stock Docker daemon's default address pools
// (no default-address-pools in /etc/docker/daemon.json): 31 networks.
var DockerDefaultPools = []AddressPool{{"172.17.0.0/16", 16}, {"172.18.0.0/16", 16}, {"172.19.0.0/16", 16}, {"172.20.0.0/14", 16}, {"172.24.0.0/14", 16}, {"172.28.0.0/14", 16}, {"192.168.0.0/16", 20}}

// FreeInPools counts the subnets of pools no network in used overlaps,
// and all of them.
func FreeInPools(pools []AddressPool, used []netip.Prefix) (free, total int) {
	for _, ap := range pools {
		base, err := netip.ParsePrefix(ap.Base)
		if err != nil || !base.Addr().Is4() || ap.Size < base.Bits() || ap.Size > 32 || ap.Size-base.Bits() > 16 {
			continue
		}
		n := 1 << (ap.Size - base.Bits())
		total += n
		firstFree(base, ap.Size, func(p netip.Prefix) bool {
			ok := true
			for _, u := range used {
				if u.Overlaps(p) {
					ok = false
					break
				}
			}
			if ok {
				free++
			}
			return false
		})
	}
	return free, total
}

// poolErrors are the engine's refusals of a network for want of
// addresses, or for a subnet another network took meanwhile.
var poolErrors = []string{
	"all predefined address pools have been fully subnetted",
	"could not find an available, non-overlapping",
	"Pool overlaps with other one on this address space",
	"networks have overlapping",
	"subnet is already used",
}

// IsPoolError reports whether err is the engine refusing a network for
// its addresses (its message is on the command's stderr).
func IsPoolError(err error) bool {
	var re *RunError
	if !errors.As(err, &re) {
		return false
	}
	for _, s := range poolErrors {
		if strings.Contains(string(re.Stderr), s) {
			return true
		}
	}
	return false
}
