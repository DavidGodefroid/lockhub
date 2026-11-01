package loxinit

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// lockDesc is what a lock does, for the checklist.
var lockDesc = map[string]string{
	"locksql":  "databases: PostgreSQL, MySQL, MariaDB, SQLite",
	"lockmq":   "RabbitMQ: queues and streams",
	"lockfile": "files: a local directory, S3, SFTP",
	"lockhttp": "the web requests of lea's agents, held at lea's gate",
	"locklog":  "logs",
}

// BuildItems is the manual checklist: lea, each lock type, then the
// locks declared already. A row that cannot be checked is greyed with
// the reason; lea unchecked greys lockhttp.
func BuildItems(e Env, pre Prereqs, decl []Declared, sources []Source) []Item {
	has := func(lock string) bool {
		return slices.ContainsFunc(sources, func(s Source) bool { return s.Lock() == lock && !s.Unpublished })
	}
	items := []Item{{Key: "lea", Name: "lea", Desc: "runs the agents; they reach the locks", Checked: pre.Lea != ""}}
	if pre.Lea == "" {
		items[0].Grey = "not found: " + LeaHint
	}
	for _, l := range Locks {
		it := Item{Key: l, Name: l, Desc: lockDesc[l]}
		switch {
		case l == "locklog" && !slices.Contains(e.Types, l):
			it.Grey = "not available yet: no release, and lox up does not run it"
		case l == "locklog":
			it.Grey = "lox init does not set it up yet: lox add locklog INSTANCE"
		case !slices.Contains(e.Types, l):
			it.Grey = "lox up does not run it"
		case l == "lockfile" && e.GOOS != "linux":
			it.Grey = "Linux only (this machine runs " + e.GOOS + ")"
		case pre.Launchers[l] == "":
			it.Grey = "launcher not installed: " + LauncherHint(l)
		default:
			it.Checked = has(l)
		}
		items = append(items, it)
	}
	for _, d := range decl {
		items = append(items, Item{Key: "declared:" + d.Instance, Name: d.Instance, Desc: declDesc(d), Checked: true})
	}
	return greyLockHTTP(items)
}

// greyLockHTTP greys lockhttp while lea is not checked (its gate is
// lea's), and lifts that once lea is.
func greyLockHTTP(items []Item) []Item {
	lea := items[0].Checked && items[0].Grey == ""
	for i := range items {
		if items[i].Key != "lockhttp" {
			continue
		}
		const needs = "needs lea (its gate is lea's)"
		switch {
		case !lea && items[i].Grey == "":
			items[i].Grey, items[i].Checked = needs, false
		case lea && items[i].Grey == needs:
			items[i].Grey = ""
		}
	}
	return items
}

// checklist runs the checklist until the human presses Enter.
func (in *Init) checklist(items []Item) ([]Item, error) {
	for {
		RenderChecklist(in.Out, items)
		a, err := in.ask(">", "")
		if err != nil {
			return nil, err
		}
		if a == "" {
			return items, nil
		}
		for _, f := range strings.Fields(strings.ReplaceAll(a, ",", " ")) {
			k, err := strconv.Atoi(f)
			switch {
			case err != nil || k < 1 || k > len(items):
				in.say("  %q: not a number of the list", f)
			case items[k-1].Grey != "":
				in.say("  %s: %s", items[k-1].Name, items[k-1].Grey)
			default:
				items[k-1].Checked = !items[k-1].Checked
			}
		}
		items = greyLockHTTP(items)
	}
}

// manual is manual mode: the checklist, then each new lock's target.
func (in *Init) manual(pre Prereqs, decl []Declared, sources []Source) (plans []Planned, kept, removals []Declared, lea bool, err error) {
	items, err := in.checklist(BuildItems(in.Env, pre, decl, sources))
	if err != nil {
		return nil, nil, nil, false, err
	}
	lea = items[0].Checked && items[0].Grey == ""
	taken := func(n string) bool {
		return slices.ContainsFunc(decl, func(d Declared) bool { return d.Instance == n }) ||
			slices.ContainsFunc(plans, func(p Planned) bool { return p.Instance == n })
	}
	for _, it := range items {
		if inst, ok := strings.CutPrefix(it.Key, "declared:"); ok {
			i := slices.IndexFunc(decl, func(d Declared) bool { return d.Instance == inst })
			if it.Checked {
				kept = append(kept, decl[i])
			} else {
				removals = append(removals, decl[i])
			}
			continue
		}
		if it.Key == "lea" || !it.Checked || it.Grey != "" {
			continue
		}
		in.say("")
		in.say("%s", it.Name)
		var p Planned
		switch it.Key {
		case "locksql":
			p, err = in.askSQL(sources)
		case "lockmq":
			p, err = in.askMQ(sources)
		case "lockfile":
			p, err = in.askFile()
		case "lockhttp":
			p, err = in.askHTTP()
		}
		if err != nil {
			return nil, nil, nil, false, err
		}
		if p.Instance, err = in.askName("Instance name (lockfamily.yaml):", uniqueName(p.Instance, taken), taken); err != nil {
			return nil, nil, nil, false, err
		}
		if p.Profile == "" {
			p.Profile = p.Instance
		}
		p.AllowedUIDs = uidsFor(p.Lock, lea, in.Env.UID)
		plans = append(plans, p)
	}
	return plans, kept, removals, lea, nil
}

var instanceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (in *Init) askName(prompt, def string, taken func(string) bool) (string, error) {
	for {
		n, err := in.ask(prompt, def)
		if err != nil {
			return "", err
		}
		switch {
		case !instanceRe.MatchString(n) || n == "hub":
			in.say("  a name: lower case letters, digits and -, not hub")
		case taken(n):
			in.say("  %s is declared already", n)
		default:
			return n, nil
		}
	}
}

// pickSource offers the detected sources of lock, or another typed in.
func (in *Init) pickSource(sources []Source, lock string) (*Source, error) {
	var cands []int
	for i, s := range sources {
		if s.Lock() == lock {
			cands = append(cands, i)
		}
	}
	if len(cands) == 0 {
		return nil, nil
	}
	for k, i := range cands {
		in.say("  %d) %s %s %s", k+1, sources[i].Label(), sources[i].Target(), sourceDesc(sources[i]))
	}
	in.say("  %d) another", len(cands)+1)
	for {
		a, err := in.ask("Which one?", "1")
		if err != nil {
			return nil, err
		}
		k, err := strconv.Atoi(a)
		switch {
		case err != nil || k < 1 || k > len(cands)+1:
			in.say("  a number from 1 to %d", len(cands)+1)
		case k == len(cands)+1:
			return nil, nil
		default:
			s := sources[cands[k-1]]
			return &s, nil
		}
	}
}

func (in *Init) askSQL(sources []Source) (Planned, error) {
	s, err := in.pickSource(sources, "locksql")
	if err != nil {
		return Planned{}, err
	}
	d := Source{Kind: KindPostgres, Host: DockerHost, Port: 5432, Local: true}
	if s != nil {
		d = *s
	}
	p := Planned{Lock: "locksql", Source: s}
	engine, err := in.askChoice("Engine (postgres, mysql, mariadb, sqlite):", d.Kind, []string{"postgres", "mysql", "mariadb", "sqlite"})
	if err != nil {
		return p, err
	}
	if engine == "sqlite" {
		path, err := in.askValue("Database file (an absolute path):", "")
		if err != nil {
			return p, err
		}
		p.Target = []string{"--engine", "sqlite", "--path", path}
		p.Instance = cleanName(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
		if p.Instance == "" {
			p.Instance = "db"
		}
		return p, nil
	}
	if engine != d.Kind {
		d.Kind, d.Port = engine, defaultPort(engine)
	}
	if d.Host, err = in.askValue("Host (host.docker.internal is this machine):", d.Host); err != nil {
		return p, err
	}
	port, err := in.askPort("Port:", d.Port)
	if err != nil {
		return p, err
	}
	d.Port = port
	if d.User, err = in.askValue("User:", d.User); err != nil {
		return p, err
	}
	if d.Database, err = in.askValue("Database:", d.Database); err != nil {
		return p, err
	}
	tls := d.TLS
	if tls == "" {
		d.Local = d.Host == DockerHost
		tls = DefaultTLS(d, false)
	}
	if tls, err = in.askChoice("TLS ("+strings.Join(TLSModes, ", ")+"):", tls, TLSModes); err != nil {
		return p, err
	}
	p.Target = SQLTarget(d, tls)
	p.Instance = SuggestName(d)
	return p, nil
}

func (in *Init) askMQ(sources []Source) (Planned, error) {
	s, err := in.pickSource(sources, "lockmq")
	if err != nil {
		return Planned{}, err
	}
	d := Source{Kind: KindRabbitMQ, Host: DockerHost, Port: 15672, AMQPPort: 5672}
	if s != nil {
		d = *s
	}
	p := Planned{Lock: "lockmq", Source: s}
	mgmt, err := in.askValue("Management API URL (http(s)://host:port; host.docker.internal is this machine):", d.MgmtURL())
	if err != nil {
		return p, err
	}
	user, err := in.askValue("User:", d.User)
	if err != nil {
		return p, err
	}
	vhost, err := in.askValue("Vhost (Enter: the lock's default):", d.VHost)
	if err != nil {
		return p, err
	}
	amqp, err := in.askValue("AMQP URL, for stream reads (- for none):", map[bool]string{true: d.AMQPURL(), false: "-"}[d.AMQPURL() != ""])
	if err != nil {
		return p, err
	}
	p.Target = []string{"--url", mgmt}
	if user != "" {
		p.Target = append(p.Target, "--user", user)
	}
	if vhost != "" {
		p.Target = append(p.Target, "--vhost", vhost)
	}
	if amqp != "" && amqp != "-" {
		p.Target = append(p.Target, "--amqp-url", amqp)
	}
	d.VHost = vhost
	p.Instance = SuggestName(d)
	return p, nil
}

func (in *Init) askFile() (Planned, error) {
	p := Planned{Lock: "lockfile", Instance: "files"}
	src, err := in.askChoice("Source (local, s3, sftp):", "local", []string{"local", "s3", "sftp"})
	if err != nil {
		return p, err
	}
	p.Target = []string{"--source", src}
	add := func(flag, prompt, def string, required bool) error {
		for {
			v, err := in.askValue(prompt, def)
			if err != nil {
				return err
			}
			if v == "" && required {
				in.say("  required")
				continue
			}
			if v != "" {
				p.Target = append(p.Target, flag, v)
			}
			return nil
		}
	}
	switch src {
	case "local":
		for {
			v, err := in.askValue("Directory (an absolute path):", in.Root)
			if err != nil {
				return p, err
			}
			if !filepath.IsAbs(v) {
				in.say("  an absolute path")
				continue
			}
			p.Target = append(p.Target, "--path", v)
			break
		}
	case "s3":
		for _, f := range []struct {
			flag, prompt string
			req          bool
		}{{"--bucket", "Bucket:", true}, {"--region", "Region:", true}, {"--endpoint", "Endpoint (Enter: AWS):", false}, {"--prefix", "Prefix (Enter: none):", false}} {
			if err := add(f.flag, f.prompt, "", f.req); err != nil {
				return p, err
			}
		}
	case "sftp":
		if err := add("--host", "Host:", "", true); err != nil {
			return p, err
		}
		port, err := in.askPort("Port:", 22)
		if err != nil {
			return p, err
		}
		p.Target = append(p.Target, "--port", strconv.Itoa(port))
		for _, f := range []struct {
			flag, prompt string
			req          bool
		}{{"--user", "User:", true}, {"--base-dir", "Base directory:", true}, {"--known-hosts", "known_hosts file (Enter: the lock's default):", false}} {
			if err := add(f.flag, f.prompt, "", f.req); err != nil {
				return p, err
			}
		}
	}
	return p, nil
}

func (in *Init) askHTTP() (Planned, error) {
	p := Planned{Lock: "lockhttp", Instance: "web"}
	prof, err := in.askName("Profile (in .lockhttp/config.toml):", "default", func(string) bool { return false })
	if err != nil {
		return p, err
	}
	p.Profile = prof
	return p, nil
}

func (in *Init) askChoice(prompt, def string, choices []string) (string, error) {
	for {
		v, err := in.ask(prompt, def)
		if err != nil {
			return "", err
		}
		if slices.Contains(choices, v) {
			return v, nil
		}
		in.say("  one of %s", strings.Join(choices, ", "))
	}
}

func (in *Init) askPort(prompt string, def int) (int, error) {
	for {
		v, err := in.ask(prompt, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 && n < 65536 {
			return n, nil
		}
		in.say("  a port: 1 to 65535")
	}
}

// String is a plan's one-line summary (for errors and logs).
func (p Planned) String() string { return fmt.Sprintf("%s %s", p.Lock, p.Instance) }
