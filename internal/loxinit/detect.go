package loxinit

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The kinds of data source lox init detects.
const (
	KindPostgres = "postgres"
	KindMySQL    = "mysql"
	KindMariaDB  = "mariadb"
	KindRabbitMQ = "rabbitmq"
)

// DockerHost is the host machine as a lock's console (a container) names
// it. lockmq refuses a loopback --url (it would be the console's own
// container) and locksql's non-interactive default host is 127.0.0.1:
// a source on this machine is always given as DockerHost.
const DockerHost = "host.docker.internal"

// Source is one data source found in the project's files. It never holds
// a secret: a password is dropped where it is parsed.
type Source struct {
	Kind string
	// Service is the compose service, if the source is one.
	Service string
	Host    string
	// Port is the database's port, or RabbitMQ's management API port.
	Port     int
	User     string
	Database string
	// VHost is RabbitMQ's virtual host ("" the lock's default).
	VHost string
	// AMQPPort is RabbitMQ's AMQP port, when known.
	AMQPPort int
	// MgmtTLS: RabbitMQ's management API is https.
	MgmtTLS bool
	// TLS is the database TLS mode the files say (locksql's names), "" when
	// they say none.
	TLS string
	// Local: on this machine (a loopback host, a compose service with a
	// published port).
	Local bool
	// Unpublished: a compose service whose port is not published on the
	// host: a lock's console cannot reach the compose network.
	Unpublished bool
	// From says where it was found: file names and keys, never values.
	From []string
	// Notes are what to check before using it.
	Notes []string

	rawHost string // the host as written, to merge with a compose service
}

// Lock is the lock type that serves the source.
func (s Source) Lock() string {
	if s.Kind == KindRabbitMQ {
		return "lockmq"
	}
	return "locksql"
}

// Label is the source's product name.
func (s Source) Label() string {
	switch s.Kind {
	case KindPostgres:
		return "PostgreSQL"
	case KindMySQL:
		return "MySQL"
	case KindMariaDB:
		return "MariaDB"
	case KindRabbitMQ:
		return "RabbitMQ"
	}
	return s.Kind
}

// Target is the source's address as the review shows it.
func (s Source) Target() string {
	if s.Kind == KindRabbitMQ {
		return s.MgmtURL()
	}
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// MgmtURL is RabbitMQ's management API URL (lockmq --url).
func (s Source) MgmtURL() string {
	scheme := "http"
	if s.MgmtTLS {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// AMQPURL is RabbitMQ's AMQP URL without credentials (lockmq
// --amqp-url), "" when the port is unknown.
func (s Source) AMQPURL() string {
	if s.AMQPPort == 0 {
		return ""
	}
	return "amqp://" + net.JoinHostPort(s.Host, strconv.Itoa(s.AMQPPort))
}

func defaultPort(kind string) int {
	switch kind {
	case KindPostgres:
		return 5432
	case KindMySQL, KindMariaDB:
		return 3306
	case KindRabbitMQ:
		return 15672
	}
	return 0
}

// maxFile bounds a file detection reads.
const maxFile = 256 << 10

// secretWords make a key secret wherever they are in its name
// (PGPASSWORD, CLIENTSECRET); secretParts only as a whole part of it
// (DB_PASS, API_KEY, but not KEYCLOAK_URL).
var (
	secretWords = []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL", "PRIVATE"}
	secretParts = []string{"PASS", "PWD", "KEY", "APIKEY", "AUTH", "SALT", "COOKIE", "SESSION", "CERT", "PEM"}
)

// SecretKey reports a key named like a secret (DB_PASSWORD,
// RABBITMQ_DEFAULT_PASS, API_TOKEN...): its value is skipped before it is
// kept anywhere.
func SecretKey(k string) bool {
	u := strings.ToUpper(k)
	for _, w := range secretWords {
		if strings.Contains(u, w) {
			return true
		}
	}
	parts := strings.FieldsFunc(u, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	for _, p := range parts {
		if slices.Contains(secretParts, p) {
			return true
		}
	}
	return false
}

// Detect finds the data sources of the project at root, reading only its
// .env files, its compose files and its config/ directory (no link is
// followed, no file over 256 KiB is read). It writes nothing and keeps no
// secret: values of keys named like secrets are skipped, and a URL keeps
// its user name but never its password. Warnings name files, never
// values.
func Detect(root string) ([]Source, []string) {
	d := &detector{root: root, env: map[string]string{}}
	d.readEnvFiles()
	d.readCompose()
	d.envSources()
	d.readConfig()
	d.finish()
	return d.sources, d.warnings
}

type detector struct {
	root     string
	env      map[string]string // the non-secret keys of the .env files
	envFrom  map[string]string // key -> file
	services map[string]string // compose service -> kind
	sources  []Source
	warnings []string
}

// readFile reads a regular file of the project (not a link), bounded.
func (d *detector) readFile(rel string) ([]byte, bool) {
	p := filepath.Join(d.root, rel)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	if fi.Size() > maxFile {
		d.warnings = append(d.warnings, rel+": over 256 KiB, not read")
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		d.warnings = append(d.warnings, rel+": not readable")
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(b) > maxFile {
		return nil, false
	}
	return b, true
}

// rootFiles are the root's files matching one of the patterns, sorted,
// the plain names first.
func (d *detector) rootFiles(patterns ...string) []string {
	var out []string
	for _, p := range patterns {
		m, _ := filepath.Glob(filepath.Join(d.root, p))
		sort.Strings(m)
		for _, f := range m {
			rel := filepath.Base(f)
			if !slices.Contains(out, rel) {
				out = append(out, rel)
			}
		}
	}
	return out
}

// parseEnv parses a .env file: KEY=VALUE lines (export, quotes and
// comments allowed). Keys named like secrets are dropped here.
func parseEnv(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || SecretKey(k) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[k] = v
	}
	return out
}

func (d *detector) readEnvFiles() {
	d.envFrom = map[string]string{}
	for _, f := range d.rootFiles(".env", ".env.*") {
		b, ok := d.readFile(f)
		if !ok {
			continue
		}
		for k, v := range parseEnv(b) {
			if _, seen := d.env[k]; !seen {
				d.env[k], d.envFrom[k] = v, f
			}
		}
	}
}

var interp = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expand resolves ${VAR}, ${VAR:-default} and $VAR from the non-secret
// keys of the .env files: a secret one resolves to its default, or "".
func (d *detector) expand(v string) string {
	return interp.ReplaceAllStringFunc(v, func(m string) string {
		g := interp.FindStringSubmatch(m)
		name, def := g[1], g[2]
		if name == "" {
			name = g[3]
		}
		if !SecretKey(name) {
			if val, ok := d.env[name]; ok && val != "" {
				return val
			}
		}
		return def
	})
}

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Image       string    `yaml:"image"`
	Ports       yaml.Node `yaml:"ports"`
	Environment yaml.Node `yaml:"environment"`
}

// ports maps a service's container ports to the host ports it publishes
// (0: published on an ephemeral port).
func ports(n yaml.Node) map[int]int {
	out := map[int]int{}
	if n.Kind != yaml.SequenceNode {
		return out
	}
	for _, e := range n.Content {
		switch e.Kind {
		case yaml.ScalarNode:
			s := strings.SplitN(e.Value, "/", 2)[0]
			parts := strings.Split(s, ":")
			c, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				continue
			}
			h := 0
			if len(parts) >= 2 {
				h, _ = strconv.Atoi(parts[len(parts)-2])
			}
			out[c] = h
		case yaml.MappingNode:
			var m struct {
				Target    string `yaml:"target"`
				Published string `yaml:"published"`
			}
			if e.Decode(&m) != nil {
				continue
			}
			c, err := strconv.Atoi(m.Target)
			if err != nil {
				continue
			}
			h, _ := strconv.Atoi(m.Published)
			out[c] = h
		}
	}
	return out
}

// environment is a service's non-secret environment, expanded.
func (d *detector) environment(n yaml.Node) map[string]string {
	out := map[string]string{}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if !SecretKey(k) {
				out[k] = d.expand(n.Content[i+1].Value)
			}
		}
	case yaml.SequenceNode:
		for _, e := range n.Content {
			k, v, _ := strings.Cut(e.Value, "=")
			if !SecretKey(k) {
				out[k] = d.expand(v)
			}
		}
	}
	return out
}

// imageKind is the kind of a service's image ("" none lox init knows).
func imageKind(image string) string {
	name := image
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name, _, _ = strings.Cut(name, "@")
	name, _, _ = strings.Cut(name, ":")
	switch {
	case strings.Contains(name, "postgres"), strings.Contains(name, "postgis"), strings.Contains(name, "timescaledb"):
		return KindPostgres
	case strings.Contains(name, "mariadb"):
		return KindMariaDB
	case strings.Contains(name, "mysql"):
		return KindMySQL
	case strings.Contains(name, "rabbitmq"):
		return KindRabbitMQ
	}
	return ""
}

func first(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

func (d *detector) readCompose() {
	d.services = map[string]string{}
	files := d.rootFiles("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml",
		"compose.*.yaml", "compose.*.yml", "docker-compose.*.yaml", "docker-compose.*.yml")
	for _, f := range files {
		b, ok := d.readFile(f)
		if !ok {
			continue
		}
		var c composeFile
		if err := yaml.Unmarshal(b, &c); err != nil {
			d.warnings = append(d.warnings, f+": not a compose file lox init can read")
			continue
		}
		names := make([]string, 0, len(c.Services))
		for n := range c.Services {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			svc := c.Services[name]
			kind := imageKind(d.expand(svc.Image))
			if kind == "" {
				continue
			}
			d.services[name] = kind
			env := d.environment(svc.Environment)
			pub := ports(svc.Ports)
			s := Source{Kind: kind, Service: name, rawHost: name, From: []string{fmt.Sprintf("%s (service %s)", f, name)}}
			cport := defaultPort(kind)
			switch kind {
			case KindPostgres:
				s.User = first(env, "POSTGRES_USER")
				if s.User == "" {
					s.User = "postgres"
				}
				s.Database = first(env, "POSTGRES_DB")
				if s.Database == "" {
					s.Database = s.User
				}
			case KindMySQL:
				s.User = first(env, "MYSQL_USER")
				s.Database = first(env, "MYSQL_DATABASE")
			case KindMariaDB:
				s.User = first(env, "MARIADB_USER", "MYSQL_USER")
				s.Database = first(env, "MARIADB_DATABASE", "MYSQL_DATABASE")
			case KindRabbitMQ:
				s.User = first(env, "RABBITMQ_DEFAULT_USER")
				if s.User == "" {
					s.User = "guest"
				}
				s.VHost = first(env, "RABBITMQ_DEFAULT_VHOST")
				if h, ok := pub[5672]; ok && h != 0 {
					s.AMQPPort = h
				}
				if _, ok := pub[15672]; !ok && !strings.Contains(svc.Image, "management") {
					s.Notes = append(s.Notes, "the management API (port 15672) is not published: lockmq needs it (a *-management image, ports: [\"15672:15672\"])")
				}
			}
			if h, ok := pub[cport]; ok && h != 0 {
				s.Host, s.Port, s.Local = DockerHost, h, true
			} else {
				s.Host, s.Port, s.Unpublished = name, cport, true
				s.Notes = append(s.Notes, fmt.Sprintf("port %d is not published on the host: a lock's console cannot reach the compose network (publish it: ports: [\"%d:%d\"])", cport, cport, cport))
			}
			d.add(s)
		}
	}
}

// fromURL is the source a URL names, without its password: nil when it is
// not one lox init knows or does not parse (it is never quoted).
func fromURL(raw string) *Source {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil
	}
	s := &Source{}
	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql", "pgsql":
		s.Kind = KindPostgres
	case "mysql":
		s.Kind = KindMySQL
	case "mariadb":
		s.Kind = KindMariaDB
	case "amqp", "amqps":
		s.Kind = KindRabbitMQ
	default:
		return nil
	}
	if u.User != nil {
		s.User = u.User.Username() // the password is never read
	}
	s.rawHost = u.Hostname()
	p, _ := strconv.Atoi(u.Port())
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	path, _ = url.PathUnescape(path)
	if s.Kind == KindRabbitMQ {
		if p == 0 {
			p = 5672
			if strings.EqualFold(u.Scheme, "amqps") {
				p = 5671
			}
		}
		s.AMQPPort = p
		s.VHost = path
		return s
	}
	s.Port = p
	s.Database = path
	q := u.Query()
	s.TLS = tlsMode(first(map[string]string{"a": q.Get("sslmode"), "b": q.Get("ssl-mode"), "c": q.Get("ssl_mode"), "d": q.Get("tls")}, "a", "b", "c", "d"))
	return s
}

// tlsMode maps a URL's TLS setting to locksql's modes ("" unknown).
func tlsMode(v string) string {
	switch strings.ToLower(strings.ReplaceAll(v, "_", "-")) {
	case "disable", "disabled", "false":
		return "disable"
	case "allow", "prefer", "preferred":
		return "prefer"
	case "require", "required", "true", "skip-verify":
		return "require"
	case "verify-ca":
		return "verify-ca"
	case "verify-full", "verify-identity":
		return "verify-full"
	}
	return ""
}

// urlKeys are the env keys whose value is a source URL.
func urlKey(k string) bool {
	switch k {
	case "DATABASE_URL", "DB_URL", "POSTGRES_URL", "POSTGRESQL_URL", "PG_URL", "MYSQL_URL", "MARIADB_URL",
		"RABBITMQ_URL", "AMQP_URL", "CLOUDAMQP_URL", "BROKER_URL":
		return true
	}
	return strings.HasSuffix(k, "_DATABASE_URL")
}

// envSources are the sources the .env files name: a URL, or a group of
// discrete keys with a host (DB_HOST, PGHOST, ...). Keys without a host
// only serve compose's interpolation.
func (d *detector) envSources() {
	keys := make([]string, 0, len(d.env))
	for k := range d.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !urlKey(k) {
			continue
		}
		if s := fromURL(d.env[k]); s != nil {
			s.From = []string{fmt.Sprintf("%s (%s)", d.envFrom[k], k)}
			d.add(*s)
		}
	}
	type group struct {
		hostKey, kind                   string
		portKey, userKey, dbKey, tlsKey string
		kindFrom                        func() string
	}
	groups := []group{
		{hostKey: "DB_HOST", portKey: "DB_PORT", userKey: "DB_USERNAME", dbKey: "DB_DATABASE", kindFrom: func() string {
			switch strings.ToLower(first(d.env, "DB_CONNECTION", "DB_ENGINE", "DB_DRIVER")) {
			case "pgsql", "postgres", "postgresql":
				return KindPostgres
			case "mysql":
				return KindMySQL
			case "mariadb":
				return KindMariaDB
			}
			return ""
		}},
		{hostKey: "PGHOST", kind: KindPostgres, portKey: "PGPORT", userKey: "PGUSER", dbKey: "PGDATABASE", tlsKey: "PGSSLMODE"},
		{hostKey: "POSTGRES_HOST", kind: KindPostgres, portKey: "POSTGRES_PORT", userKey: "POSTGRES_USER", dbKey: "POSTGRES_DB"},
		{hostKey: "MYSQL_HOST", kind: KindMySQL, portKey: "MYSQL_PORT", userKey: "MYSQL_USER", dbKey: "MYSQL_DATABASE"},
		{hostKey: "MARIADB_HOST", kind: KindMariaDB, portKey: "MARIADB_PORT", userKey: "MARIADB_USER", dbKey: "MARIADB_DATABASE"},
		{hostKey: "RABBITMQ_HOST", kind: KindRabbitMQ, portKey: "RABBITMQ_MANAGEMENT_PORT", userKey: "RABBITMQ_USER", dbKey: "RABBITMQ_VHOST"},
	}
	for _, g := range groups {
		host, ok := d.env[g.hostKey]
		if !ok {
			continue
		}
		kind := g.kind
		if g.kindFrom != nil {
			kind = g.kindFrom()
		}
		if kind == "" {
			continue
		}
		s := Source{Kind: kind, rawHost: host, From: []string{fmt.Sprintf("%s (%s)", d.envFrom[g.hostKey], g.hostKey)}}
		s.Port, _ = strconv.Atoi(d.env[g.portKey])
		s.User = d.env[g.userKey]
		if g.userKey == "DB_USERNAME" && s.User == "" {
			s.User = d.env["DB_USER"]
		}
		if kind == KindRabbitMQ {
			if s.User == "" {
				s.User = d.env["RABBITMQ_DEFAULT_USER"]
			}
			s.VHost = d.env[g.dbKey]
			if p, err := strconv.Atoi(d.env["RABBITMQ_PORT"]); err == nil {
				s.AMQPPort = p
			}
		} else {
			s.Database = d.env[g.dbKey]
			if g.dbKey == "DB_DATABASE" && s.Database == "" {
				s.Database = d.env["DB_NAME"]
			}
			if g.tlsKey != "" {
				s.TLS = tlsMode(d.env[g.tlsKey])
			}
		}
		d.add(s)
	}
}

var urlInText = regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|amqps?)://[^\s"'<>` + "`" + `,;]+`)

var configExts = []string{".yaml", ".yml", ".toml", ".json", ".env", ".ini", ".conf", ".properties"}

// readConfig scans config/ (depth 3, no link followed) for source URLs.
func (d *detector) readConfig() {
	base := filepath.Join(d.root, "config")
	fi, err := os.Lstat(base)
	if err != nil || !fi.IsDir() {
		return
	}
	var walk func(rel string, depth int)
	walk = func(rel string, depth int) {
		ents, err := os.ReadDir(filepath.Join(d.root, rel))
		if err != nil {
			return
		}
		for _, e := range ents {
			r := filepath.Join(rel, e.Name())
			switch {
			case e.Type()&os.ModeSymlink != 0:
			case e.IsDir():
				if depth < 3 {
					walk(r, depth+1)
				}
			case e.Type().IsRegular() && slices.Contains(configExts, strings.ToLower(filepath.Ext(e.Name()))):
				b, ok := d.readFile(r)
				if !ok {
					continue
				}
				for _, m := range urlInText.FindAllString(string(b), -1) {
					if s := fromURL(m); s != nil {
						s.From = []string{filepath.ToSlash(r)}
						d.add(*s)
					}
				}
			}
		}
	}
	walk("config", 1)
}

func loopback(h string) bool {
	switch strings.ToLower(h) {
	case "", "localhost", "127.0.0.1", "::1", "0.0.0.0", "ip6-localhost":
		return true
	}
	return strings.HasPrefix(h, "127.")
}

func sameFamily(a, b string) bool {
	if a == b {
		return true
	}
	my := func(k string) bool { return k == KindMySQL || k == KindMariaDB }
	return my(a) && my(b)
}

// add merges s into a source already found (the same compose service, or
// the same host and port), else appends it, its host made what a lock's
// console reaches.
func (d *detector) add(s Source) {
	if s.Service == "" {
		if kind, ok := d.services[s.rawHost]; ok && sameFamily(kind, s.Kind) {
			// A URL naming a compose service: the service's published port
			// counts, not the container's.
			for i := range d.sources {
				if d.sources[i].Service == s.rawHost {
					merge(&d.sources[i], s)
					return
				}
			}
		}
		switch {
		case loopback(s.rawHost):
			s.Host, s.Local = DockerHost, true
		case strings.EqualFold(s.rawHost, DockerHost):
			s.Host, s.Local = DockerHost, true
		default:
			s.Host = s.rawHost
		}
		if s.Kind == KindRabbitMQ && s.Port == 0 {
			s.Port = 15672
			s.Notes = append(s.Notes, "the management API port is not in the files: 15672 assumed")
		}
		if s.Port == 0 {
			s.Port = defaultPort(s.Kind)
		}
	}
	for i := range d.sources {
		e := &d.sources[i]
		if !sameFamily(e.Kind, s.Kind) {
			continue
		}
		if (s.Service != "" && e.Service == s.Service) || (e.Host == s.Host && e.Port == s.Port && e.Host != "") ||
			(s.Kind == KindRabbitMQ && e.Host == s.Host && s.AMQPPort != 0 && e.AMQPPort == s.AMQPPort) {
			merge(e, s)
			return
		}
	}
	d.sources = append(d.sources, s)
}

func merge(e *Source, s Source) {
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	fill(&e.User, s.User)
	fill(&e.Database, s.Database)
	fill(&e.VHost, s.VHost)
	fill(&e.TLS, s.TLS)
	if e.AMQPPort == 0 {
		e.AMQPPort = s.AMQPPort
	}
	for _, f := range s.From {
		if !slices.Contains(e.From, f) {
			e.From = append(e.From, f)
		}
	}
	for _, n := range s.Notes {
		if !slices.Contains(e.Notes, n) {
			e.Notes = append(e.Notes, n)
		}
	}
}

func (d *detector) finish() {
	for i := range d.sources {
		s := &d.sources[i]
		if s.Kind == KindRabbitMQ && s.User == "guest" {
			s.Notes = append(s.Notes, "guest: RabbitMQ refuses it from outside localhost; the lock needs another user")
		}
		if s.Kind != KindRabbitMQ && s.User == "" {
			s.Notes = append(s.Notes, "no user in the files: the lock's default applies")
		}
	}
}
