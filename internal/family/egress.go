package family

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/lockhub/internal/egress"
)

// A lock's egress (lockhub#123). Every lock but lockhttp (whose egress is
// its job, under its own policy) sits on an internal network, locknet-<n>:
// no route out, no cloud metadata, no host. Its gateway, gw-<n>, is on
// that network under the names of the endpoints its reviewed profile
// connects to (network aliases: host names and TLS server names stay the
// profile's), and forwards each endpoint's port to gwout-<n>, the only
// container with a route out (out-<n>), which dials that endpoint and no
// other. The allowlist is read from the reviewed copy of the profile, the
// one lox run copies into the lock, never from the workspace: an agent
// that edits .locksql changes nothing until the human reviews it again.
//
// Fail closed: what the allowlist cannot name exactly (a value it cannot
// read, a proxy command) is reached by nothing, and the review says why.
// An IP address is refused outright (lockhub#145): the gateway answers by
// host name only, so the lock could never reach it, and lox run stops
// before anything starts instead of the console failing at connection
// time with a bare "network is unreachable".

// Endpoint is one host:port a lock may reach.
type Endpoint struct {
	Host string
	Port int
	// TLS: the connection starts with a TLS ClientHello (https, amqps,
	// …), so a port shared with another endpoint can be routed by its
	// server name. A database's STARTTLS, SSH or plain protocols cannot.
	TLS bool
	// What names the endpoint in the review ("database", "vault", …).
	What string
}

// Addr is host:port.
func (e Endpoint) Addr() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// Egress is a lock's allowlist.
type Egress struct {
	// Own: the lock's egress is its own policy's (lockhttp): no gateway.
	Own bool
	// Endpoints, sorted by host then port.
	Endpoints []Endpoint
	// None are the reasons something the profile names is reached by
	// nothing (fail closed).
	None []string
	// Refused are the values the egress can never reach and lox run
	// refuses to apply (an IP address): each names its key and the fix.
	Refused []string
}

// IPHost is the refusal of host when it is an IP address a lock's egress
// cannot reach (any but loopback, the lock's own container), else "".
func IPHost(host string) string {
	h := strings.Trim(strings.TrimSuffix(host, "."), "[]")
	if ip := net.ParseIP(h); ip == nil || ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("%s is an IP address, which a lock cannot reach: its egress gateway answers by host name only; name the host instead (a DNS name that resolves to it, or host.docker.internal for this machine)", host)
}

// gwBase is the first port of gwout-<n>: endpoint i (in Endpoints order)
// is gwBase+i there.
const gwBase = 20000

// maxEndpoints bounds a lock's allowlist.
const maxEndpoints = 64

// Egresses computes every lock's allowlist from the reviewed profiles.
// It refuses an allowlist the gateway cannot serve: two endpoints on one
// port that are not both TLS, or a name lox run's own services use.
func Egresses(c *Config, profiles map[string]*Profile) (map[string]Egress, error) {
	out := map[string]Egress{}
	for _, n := range c.Instances() {
		e, err := lockEgress(c, n, profiles[c.Locks[n].Type])
		if err == nil && len(e.Refused) > 0 {
			err = errors.New(strings.Join(e.Refused, "; "))
		}
		if err != nil {
			return nil, fmt.Errorf("egress of lock %s: %w", n, err)
		}
		out[n] = e
	}
	return out, nil
}

func lockEgress(c *Config, name string, p *Profile) (Egress, error) {
	l := c.Locks[name]
	if Kinds[l.Type].Gate {
		return Egress{Own: true}, nil
	}
	var e Egress
	// key names where host is set, for a refusal ("profiles.p.ssh.host").
	add := func(host string, port int, tls bool, what, key string) {
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		switch ip := net.ParseIP(strings.Trim(h, "[]")); {
		case h == "":
			e.None = append(e.None, what+": no host in the profile")
		case h == "localhost" || (ip != nil && ip.IsLoopback()):
			// The lock's own container: no egress involved.
		case ip != nil:
			e.Refused = append(e.Refused, fmt.Sprintf("%s (%s): %s", key, what, IPHost(host)))
		case !hostName.MatchString(h):
			e.None = append(e.None, fmt.Sprintf("%s: host %q is not a plain DNS name", what, host))
		case port < 1 || port > 65535:
			e.None = append(e.None, fmt.Sprintf("%s %s: no usable port", what, h))
		default:
			for i, x := range e.Endpoints {
				if x.Host == h && x.Port == port {
					e.Endpoints[i].TLS = x.TLS && tls
					if !strings.Contains(x.What, what) {
						e.Endpoints[i].What += ", " + what
					}
					return
				}
			}
			e.Endpoints = append(e.Endpoints, Endpoint{Host: h, Port: port, TLS: tls, What: what})
		}
	}
	if l.Vault && c.Vault != nil {
		if u, err := url.Parse(c.Vault.Address); err == nil {
			add(u.Hostname(), urlPort(u, map[string]int{"http": 80, "https": 443}), u.Scheme == "https", "vault", "vault.address in lockfamily.yaml")
		} else {
			e.None = append(e.None, "vault: the address cannot be read")
		}
	}
	if p == nil {
		e.None = append(e.None, "no reviewed profile")
	} else if err := profileEndpoints(l, p, add, func(s string) { e.None = append(e.None, s) }); err != nil {
		e.None = append(e.None, err.Error())
	}
	slices.SortFunc(e.Endpoints, func(a, b Endpoint) int {
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return a.Port - b.Port
	})
	if len(e.Endpoints) > maxEndpoints {
		return e, fmt.Errorf("%d endpoints, at most %d", len(e.Endpoints), maxEndpoints)
	}
	for _, x := range e.Endpoints {
		if reservedHost(x.Host) {
			return e, fmt.Errorf("%s (%s): a name of lox run's own services: rename it in the profile", x.Host, x.What)
		}
	}
	// One gateway port per endpoint port: a shared port is routed by TLS
	// server name, which only TLS endpoints send.
	for i, a := range e.Endpoints {
		for _, b := range e.Endpoints[i+1:] {
			if a.Port == b.Port && (!a.TLS || !b.TLS) {
				plain := a
				if a.TLS {
					plain = b
				}
				return e, fmt.Errorf("%s (%s) and %s (%s) share port %d on the lock's gateway, and %s does not start with TLS, so the gateway cannot tell them apart: move one to another port", a.Addr(), a.What, b.Addr(), b.What, a.Port, plain.Addr())
			}
		}
	}
	return e, nil
}

// hostName is a DNS name as the gateway answers for it.
var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$`)

// reservedHost: a name compose resolves to one of lox run's services.
func reservedHost(h string) bool {
	if h == "lockhub" || h == "hubkey" {
		return true
	}
	for _, p := range []string{"lock-", "gw-", "gwout-", "gatehome-", "gatekey-", "rotkey-", "profile-"} {
		if strings.HasPrefix(h, p) && !strings.Contains(h, ".") {
			return true
		}
	}
	return false
}

func urlPort(u *url.URL, def map[string]int) int {
	if s := u.Port(); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0
		}
		return n
	}
	return def[strings.ToLower(u.Scheme)]
}

// configTOML is the reviewed config.toml of p.
func configTOML(p *Profile) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(p.Tar))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Name == "config.toml" && h.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
}

// profileEndpoints reads the endpoints of the lock's profile (or of every
// profile of config.toml when the lock names none: the human picks one at
// the console) from the reviewed copy.
func profileEndpoints(l Lock, p *Profile, add func(string, int, bool, string, string), none func(string)) error {
	b, err := configTOML(p)
	if err != nil {
		return fmt.Errorf("the reviewed profile cannot be read: %v", err)
	}
	if b == nil {
		return errors.New("no config.toml in the reviewed profile")
	}
	var doc struct {
		Profiles map[string]map[string]any `toml:"profiles"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return errors.New("config.toml is not TOML the allowlist can read")
	}
	names := []string{LockProfile(l)}
	if names[0] == "" {
		for n := range doc.Profiles {
			names = append(names, n)
		}
		names = names[1:]
		slices.Sort(names)
	}
	if len(names) == 0 {
		return errors.New("config.toml has no profile")
	}
	for _, n := range names {
		pr, ok := doc.Profiles[n]
		if !ok {
			none(fmt.Sprintf("profile %s: not in config.toml", n))
			continue
		}
		readProfile(l.Type, n, pr, func(h string, port int, tls bool, what, key string) {
			add(h, port, tls, what, "profiles."+n+"."+key+" in config.toml")
		}, none)
	}
	return nil
}

// add's last argument is the key that sets the host, under the profile.
func readProfile(typ, name string, pr map[string]any, add func(string, int, bool, string, string), none func(string)) {
	str := func(k string) (string, bool) {
		v, ok := pr[k]
		if !ok {
			return "", true
		}
		s, ok := v.(string)
		return s, ok
	}
	num := func(m map[string]any, k string) (int, bool) {
		v, ok := m[k]
		if !ok {
			return 0, true
		}
		n, ok := v.(int64)
		return int(n), ok
	}
	bad := func(k string) { none(fmt.Sprintf("profile %s: %s cannot be read", name, k)) }
	// An SSH tunnel: the lock reaches the bastion only, the target is on
	// the far side.
	if v, ok := pr["ssh"]; ok {
		t, ok := v.(map[string]any)
		h, hok := t["host"].(string)
		port, pok := num(t, "port")
		if !ok || !hok || !pok {
			bad("ssh")
			return
		}
		if port == 0 {
			port = 22
		}
		add(h, port, false, "ssh", "ssh.host")
		return
	}
	if _, ok := pr["proxy_command"]; ok {
		none(fmt.Sprintf("profile %s: proxy_command runs a program the gateway cannot follow", name))
		return
	}
	switch typ {
	case "locksql":
		eng, eok := str("engine")
		h, hok := str("host")
		port, pok := num(pr, "port")
		if !eok || !hok || !pok {
			bad("engine, host or port")
			return
		}
		if eng == "sqlite" {
			return
		}
		if port == 0 {
			port = map[string]int{"postgres": 5432, "mysql": 3306, "mariadb": 3306}[eng]
		}
		add(h, port, false, "database", "host")
	case "lockmq":
		for _, k := range []struct {
			key, what string
			def       map[string]int
			tls       []string
		}{
			{"url", "broker management API", map[string]int{"http": 80, "https": 443}, []string{"https"}},
			{"amqp_url", "broker AMQP", map[string]int{"amqp": 5672, "amqps": 5671}, []string{"amqps"}},
			{"stream_url", "broker stream", map[string]int{"rabbitmq-stream": 5552, "rabbitmq-stream+tls": 5551}, []string{"rabbitmq-stream+tls"}},
		} {
			s, ok := str(k.key)
			if !ok {
				bad(k.key)
				continue
			}
			if s == "" {
				continue
			}
			u, err := url.Parse(s)
			if err != nil {
				bad(k.key)
				continue
			}
			add(u.Hostname(), urlPort(u, k.def), slices.Contains(k.tls, strings.ToLower(u.Scheme)), k.what, k.key)
		}
	case "lockfile":
		src, ok := str("source")
		if !ok {
			bad("source")
			return
		}
		switch src {
		case "s3":
			ep, eok := str("endpoint")
			region, rok := str("region")
			bucket, bok := str("bucket")
			if !eok || !rok || !bok {
				bad("endpoint, region or bucket")
				return
			}
			if ep != "" {
				u, err := url.Parse(ep)
				if err != nil {
					bad("endpoint")
					return
				}
				add(u.Hostname(), urlPort(u, map[string]int{"http": 80, "https": 443}), strings.EqualFold(u.Scheme, "https"), "s3", "endpoint")
				return
			}
			// Virtual-hosted style, as the AWS SDK addresses a bucket.
			add(bucket+".s3."+region+".amazonaws.com", 443, true, "s3", "bucket")
		case "sftp":
			h, hok := str("host")
			port, pok := num(pr, "port")
			if !hok || !pok {
				bad("host or port")
				return
			}
			if port == 0 {
				port = 22
			}
			add(h, port, false, "sftp", "host")
		case "local", "":
		default:
			bad("source")
		}
	case "lockssh":
		// One SSH host per profile (no bastion: lockssh has no ProxyJump).
		h, hok := str("host")
		port, pok := num(pr, "port")
		if !hok || !pok {
			bad("host or port")
			return
		}
		if port == 0 {
			port = 22
		}
		add(h, port, false, "ssh", "host")
	case "locklog":
		// The remote sources (Loki, Elasticsearch, OpenSearch): their url,
		// http or https. File, journald and docker sources read mounts.
		srcs, ok := pr["sources"].(map[string]any)
		if _, set := pr["sources"]; set && !ok {
			bad("sources")
			return
		}
		var names []string
		for n := range srcs {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			src, ok := srcs[n].(map[string]any)
			if !ok {
				bad("sources." + n)
				continue
			}
			kind, _ := src["kind"].(string)
			if kind != "loki" && kind != "elastic" && kind != "opensearch" {
				continue
			}
			s, ok := src["url"].(string)
			u, err := url.Parse(s)
			scheme := ""
			if err == nil {
				scheme = strings.ToLower(u.Scheme)
			}
			if !ok || (scheme != "http" && scheme != "https") {
				bad("sources." + n + ".url")
				continue
			}
			add(u.Hostname(), urlPort(u, map[string]int{"http": 80, "https": 443}), scheme == "https", kind+" source "+n, "sources."+n+".url")
		}
	}
}

// Lines are the egress summary lines of lock n, reviewed and fingerprinted
// with the rest: a profile change that changes them is reviewed again.
func (e Egress) Lines(n string) []string {
	if e.Own {
		return nil
	}
	var s []string
	for _, x := range e.Endpoints {
		s = append(s, fmt.Sprintf("lock %s egress %s (%s)", n, x.Addr(), x.What))
	}
	for _, r := range e.None {
		s = append(s, fmt.Sprintf("lock %s egress unreachable: %s", n, r))
	}
	if len(e.Endpoints) == 0 {
		s = append(s, fmt.Sprintf("lock %s egress none: the lock reaches no host", n))
	}
	return s
}

// Short is the egress row of the short review; the None reasons are
// rows of their own (Facts.Unreachable).
func (e Egress) Short() string {
	if e.Own {
		return "its own policy (lockhttp)"
	}
	var a []string
	for _, x := range e.Endpoints {
		a = append(a, x.Addr())
	}
	s := "only " + strings.Join(a, ", ")
	if len(a) == 0 {
		s = "none"
	}
	return s
}

// localLogEgress is the egress of a locklog lock whose plan reads no
// remote source: none, whatever its profile or vault name. Its console is
// on the hub's network alone (lockNet).
func localLogEgress() Egress {
	return Egress{None: []string{"local log sources only: the console is on the hub's network alone, with no route out"}}
}

// formerNets are the lock networks of lox before lockhub#123 (bridges
// with a route out), named egress-<n>: lox run removes them once no
// container uses them.
func formerNets(c *Config) map[string]bool {
	m := map[string]bool{}
	for _, n := range c.Instances() {
		if !Kinds[c.Locks[n].Type].Gate {
			m["egress-"+n] = true
		}
	}
	return m
}

// egressLine tells summary lines of a lock's egress from the others.
var egressLine = regexp.MustCompile(`^lock \S+ egress `)

// forwards are the gateway's --forward flags of e: the front's (on the
// lock's network) and the back's (with the route out).
func (e Egress) forwards(name string) (front, back []egress.Forward) {
	shared := map[int]int{}
	for _, x := range e.Endpoints {
		shared[x.Port]++
	}
	for i, x := range e.Endpoints {
		f := egress.Forward{Listen: x.Port, Host: "gwout-" + name, Port: gwBase + i}
		if shared[x.Port] > 1 {
			f.SNI = x.Host
		}
		front = append(front, f)
		back = append(back, egress.Forward{Listen: gwBase + i, Host: x.Host, Port: x.Port})
	}
	return front, back
}

// aliases are the distinct names the front answers for.
func (e Egress) aliases() []string {
	var a []string
	for _, x := range e.Endpoints {
		if !slices.Contains(a, x.Host) {
			a = append(a, x.Host)
		}
	}
	return a
}

// hostGateway: an endpoint is this machine (host.docker.internal).
func (e Egress) hostGateway() bool {
	return slices.ContainsFunc(e.Endpoints, func(x Endpoint) bool { return x.Host == "host.docker.internal" })
}
