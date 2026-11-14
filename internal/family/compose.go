package family

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockhub/internal/egress"
)

// Paths lox up uses on the host.
type Paths struct {
	// Workspace is the workspace's directory (the parent of .lockfamily).
	// A lock's own profile directory (<workspace>/.locksql, …) is mounted
	// read-only at the same path, so that the console and lea's agents
	// (which see the workspace at the same path) agree on the socket's
	// name, which derives from the project's path.
	Workspace string
	// HubData is the hub's data directory (outside the projects
	// directory: no agent container mounts it).
	HubData string
	// FacadeDir holds the facade socket ($XDG_RUNTIME_DIR/lockhub).
	FacadeDir string
	// Facades is the facade keys file (FacadesFile), mounted read-only
	// in locks at LockFacadesPath; empty: none.
	Facades string
	// User is the uid:gid the hub runs as, so that the host user owns
	// the facade socket and the data ("0:0" under rootless engines, where
	// root is the host user).
	User string
	// Devices is the pinned devices file (host state dir), mounted
	// read-only in every lock; "" when no device is paired. DevicesID
	// names its content: as a label of every lock, a change of the
	// paired devices recreates the locks, which read the file at start.
	Devices   string
	DevicesID string
	// Config is the fingerprint of the applied configuration (keys,
	// routing). As a label of the hub service, a change of it makes
	// compose recreate the hub, which reads its config at start.
	Config string
	// Profiles are the fingerprints of the reviewed profile copies, by
	// type: a lock's label, so that a new copy recreates its console.
	Profiles map[string]string
	// Rotate are the locks whose key lox run --rotate replaces: each gets
	// the setup service rotkey-<instance> (rotate.go).
	Rotate []string
	// VaultCA is the reviewed copy of vault.ca_file (<state>/vault-ca.pem),
	// mounted read-only in the locks with vault: true; "" until it exists.
	VaultCA string
	// VaultCASum is its sha256 (hex): a label of the locks that mount it,
	// so that a changed CA recreates them (a file bind keeps the old inode).
	VaultCASum string
	// Seccomp is the copy of LockfileSeccomp (<state>/lockfile-seccomp.json)
	// the lockfile locks run under; "" until it exists (Docker's default).
	// SeccompSum is its sha256 (hex): their label, so that a new profile
	// recreates them (compose sends the content once, at creation).
	Seccomp, SeccompSum string
	// Egress are the locks' allowlists (egress.go), from the reviewed
	// profiles: a lock without one reaches no host.
	Egress map[string]Egress
	// Logs are the checked mount plans of the locks whose kind takes one
	// (Kind.Mounts), by instance: their binds, groups and map. A lock
	// with none yet (before the review) mounts no log.
	Logs map[string]*LogPlan
	// ProfileIDs are the device:inode of each type's profile volume, as
	// its copy service printed it (Kind.Mounts: LOCKLOG_EXPECT_DIR).
	ProfileIDs map[string]string
	// NCPU is the Docker host's processor count (docker info), which
	// caps a kind's CPUs: compose refuses more CPUs than the host has.
	// lox run reads it only when a lock's kind sets CPUs; 0: unknown, the
	// kind's CPUs as they are.
	NCPU int
	// Project is the compose project: it names a locklog lock's network
	// as the engine knows it (LOCKLOG_NETWORK, <project>_locknet-<n>).
	Project string
	// Subnets are the networks' subnets, by compose key (AllocSubnets),
	// set in the file: none is left to the engine's default address
	// pools. A network without one takes the engine's choice.
	Subnets map[string]string
	// Managed is the fingerprint of the managed directory lox run copies
	// into the volume managed (Managed.Fingerprint): mounted read-only at
	// ManagedDir in every lock, and their label, so that a change
	// recreates them. "": no managed file, no volume, no mount.
	Managed string
}

// lockNet reports whether lock l sits on its own network, locknet-<n>
// (and its gateway, for an allowlist): every kind but lockhttp (whose
// egress is its own policy's), except a locklog lock whose plan reads no
// remote source (local sources only, or no plan yet). That one is on the
// hub's network alone, which is internal: no route out, no other
// network.
func lockNet(l Lock, lp *LogPlan) bool {
	k := Kinds[l.Type]
	if k.Gate {
		return false
	}
	if k.Mounts {
		return lp != nil && lp.Remote
	}
	return true
}

// LockNetwork is the engine's name of lock inst's network, locknet-<n>,
// in the compose project.
func LockNetwork(project, inst string) string { return project + "_locknet-" + inst }

// VaultCAPath is where the locks with vault: true see the reviewed CA.
const VaultCAPath = "/run/lockfamily-vault/ca.pem"

// Kind is what lox up knows of a lock type's image: the console's
// account and its clients group (the image's /etc/<type>/system.toml),
// and where the console reads its profile.
type Kind struct {
	// UID and GID are the console's account and the clients group: the
	// console refuses to serve as any other account (lockkit's
	// isolation), and lea's agents join the group to reach the socket.
	UID, GID string
	// Project is true when the console reads <workspace>/.<type> (its
	// project's profile, which also names the socket); false when it
	// reads only ~/.config/<type>, where lox up mounts <workspace>/.<type>.
	Project bool
	// Gate is lockhttp: the hub is asked by the gate (lea runs it beside
	// its proxy), not by the console, which only serves the policy.
	Gate bool
	// Mem and Pids are the console's limits, as the lock's own launcher
	// sets them.
	Mem  string
	Pids int
	// CPUs, when set, caps the console's CPUs (compose's cpus) at
	// min(CPUs, the Docker host's NCPU), as lox run renders it; 0: no cap.
	CPUs int
	// Mounts is locklog: the console reads host logs through the mount
	// plan its image derives from the profile (locklog mounts), which
	// lox run checks, reviews and mounts (locklog.go).
	Mounts bool
	// HomeFiles is locksql, lockssh and lockfile: their profiles name
	// files (tls_ca, ssh.key; key, known_hosts) the console reads, "~/"
	// being its home volume; lox run checks them there (homefiles.go).
	HomeFiles bool
	// Rules is locklog and lockssh: lox run reads the profiles' auto
	// rules with `<type> profile rules --json`, run in the image as Agent
	// (the image's agent account, uid:gid) on the reviewed copy, and
	// applies them in its engine (locklog_rules.go, lockssh.go).
	Rules bool
	Agent string
}

// Kinds are the lock types' images (their Dockerfiles).
var Kinds = map[string]Kind{
	"locksql":  {UID: "10001", GID: "10000", Project: true, Mem: "1g", Pids: 256, HomeFiles: true},
	"lockmq":   {UID: "10011", GID: "10010", Project: true, Mem: "1g", Pids: 256},
	"lockfile": {UID: "10031", GID: "10030", Mem: "4g", Pids: 512, HomeFiles: true},
	"lockhttp": {UID: "10021", GID: "10020", Gate: true, Mem: "1g", Pids: 256},
	// locklog's console scans and masks the logs itself: at most two of
	// the host's CPUs, as its launcher.
	"locklog": {UID: "10051", GID: "10050", Project: true, Mem: "1g", Pids: 256, CPUs: 2, Mounts: true, Rules: true, Agent: agentAccount},
	// lockssh's console holds the SSH key in its home volume (its key and
	// known_hosts files, checked there) and runs one command per session:
	// its launcher's limits.
	"lockssh": {UID: "10041", GID: "10040", Project: true, Mem: "1g", Pids: 256, HomeFiles: true, Rules: true, Agent: "10042:10040"},
}

// cpus is the console's CPU cap on a host of ncpu processors (0:
// unknown), or 0 when the kind sets none.
func (k Kind) cpus(ncpu int) int {
	if k.CPUs <= 0 {
		return 0
	}
	if ncpu > 0 {
		return min(k.CPUs, ncpu)
	}
	return k.CPUs
}

// needsNCPU reports whether a lock of c has a kind that sets CPUs: lox
// run then reads the Docker host's NCPU.
func needsNCPU(c *Config) bool {
	for _, t := range types(c) {
		if Kinds[t].CPUs > 0 {
			return true
		}
	}
	return false
}

// LocksqlPIIDir is where a locksql console keeps its PII rule sets
// (LOCKSQL_PII_DIR, locksql v0.11.0 or later): its home volume, since the
// copy of its profile is read-only.
const LocksqlPIIDir = "/home/locksql/pii-rules"

// The lockhttp gate's account in lockhttp's image (lockhttp-clients).
const gateUID, gateGID = "10003", "10020"

// Labels that lea reads (with compose's own project label) before it
// mounts a lock's volume in an agent's container: only a socket volume
// is ever mounted there.
const (
	LabelRole      = "dev.lockfamily.role"
	LabelInstance  = "dev.lockfamily.instance"
	LabelType      = "dev.lockfamily.type"
	LabelWorkspace = "dev.lockfamily.workspace"
	// RoleSocket is the console's socket volume (agents may mount it),
	// RoleGateHome the lockhttp gate's own volume (only lea's gate),
	// RoleHub the hub's network (only lea's proxy, under a lockhttp gate).
	RoleSocket   = "socket"
	RoleGateHome = "gate-home"
	RoleHub      = "hub"
)

// HubKeyDir is where the hub's public key is mounted in the locks (the
// volume hubkey, read-only): a root-owned 0644 file in a root-owned
// directory, which the consoles accept as a pinned key.
const HubKeyDir = "/run/lockfamily"

func q(s string) string { return fmt.Sprintf("%q", s) }

// restartPolicy is the hub's, the locks' and the gateways': none. A lock
// is of no use without lox run (fail closed), and the hub cannot come
// back by itself after a reboot (its facade directory is on a tmpfs): the
// engine never starts the stack on its own, at its start or a host's
// boot. lox run starts a console that stopped while it runs
// (lockconsoles).
const restartPolicy = `"no"`

// Compose renders the compose file. Output is deterministic.
func Compose(c *Config, p Paths) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	labels := func(role, inst, typ string) {
		w("    labels:")
		w("      %s: %s", LabelRole, q(role))
		if inst != "" {
			w("      %s: %s", LabelInstance, q(inst))
			w("      %s: %s", LabelType, q(typ))
		}
		w("      %s: %s", LabelWorkspace, q(p.Workspace))
	}
	w("# Generated by lox up from lockfamily.yaml. Do not edit: run lox up.")
	w("services:")
	w("  lockhub:")
	w("    image: %s", q(c.Hub.Image))
	w("    user: %s", q(p.User))
	if m := c.Hub.Mobile; m != nil {
		push := ""
		if m.Push {
			push = `, "--mobile-push"`
		}
		w("    command: [\"serve\", \"--listen\", \":8443\", \"--data\", \"/var/lib/lockhub\", \"--facade-socket\", \"/run/lockhub-facade/facade.sock\", \"--mobile-listen\", \":8444\", \"--mobile-origin\", %s%s]", q(m.Origin), push)
		// Published on the host's loopback only: the human's reverse
		// proxy or tunnel forwards the origin to it.
		w("    ports: [%s]", q(fmt.Sprintf("127.0.0.1:%d:8444", m.Port)))
	} else {
		w("    command: [\"serve\", \"--listen\", \":8443\", \"--data\", \"/var/lib/lockhub\", \"--facade-socket\", \"/run/lockhub-facade/facade.sock\"]")
	}
	hardening(w)
	w("    volumes:")
	w("      - type: bind")
	w("        source: %s", q(p.HubData))
	w("        target: /var/lib/lockhub")
	w("      - type: bind")
	w("        source: %s", q(p.FacadeDir))
	w("        target: /run/lockhub-facade")
	// Never made by the engine: it would make a missing one as root, mode
	// 0755, which the hub refuses (lockhub#112). Missing, the hub does not
	// start until lox up makes it, the user's, mode 0700.
	w("        bind:")
	w("          create_host_path: false")
	// The hub has no route out, unless a chat facade must reach its
	// service or the mobile facade the push services: then through its own
	// network, never a lock's. Its own networks: that route out, the
	// mobile listener's published port (an internal network publishes
	// none).
	nets := []string{"lockhub"}
	if c.HubEgress() {
		nets = append(nets, q("egress-hub"))
	}
	if c.Hub.Mobile != nil {
		nets = append(nets, q("mobile-hub"))
	}
	w("    networks: [%s]", strings.Join(nets, ", "))
	if p.Config != "" {
		w("    labels:")
		w("      lockfamily.config: %s", q(p.Config))
	}
	w("    restart: %s", restartPolicy)
	// hubkey writes the hub's public key into the volume the locks mount
	// read-only (lox up runs it; never started by up). As root, so that
	// the key is root's: a lock refuses a key file its own or another
	// account could rewrite.
	w("  hubkey:")
	w("    image: %s", q(c.Hub.Image))
	w("    profiles: [setup]")
	w("    user: \"0:0\"")
	w("    entrypoint: [\"/bin/sh\", \"-c\", %s, \"hubkey\"]", q(`umask 022 && printf '%s\n' "$1" > /k/hub.pub.new && mv /k/hub.pub.new /k/hub.pub`))
	w("    network_mode: none")
	hardening(w)
	w("    volumes:")
	w("      - hubkey:/k")
	for _, name := range c.Instances() {
		l := c.Locks[name]
		k := Kinds[l.Type]
		home := "/home/" + l.Type
		w("  lock-%s:", name)
		w("    image: %s", q(l.Image))
		w("    user: %s", q(k.UID+":"+k.GID))
		// The console asks the human at its terminal: its policy on the
		// first start and after a loosening, and the credentials its
		// profile does not take from Vault. lox run reaches it through a
		// pty of its own (lockconsoles); lox attach too.
		w("    tty: true")
		w("    stdin_open: true")
		w("    environment:")
		w("      HOME: %s", q(home))
		if l.Type == "locksql" {
			// Its profile copy is read-only: the console keeps its PII
			// rule sets in its own volume, seeded from the profile's.
			w("      LOCKSQL_PII_DIR: %s", q(LocksqlPIIDir))
		}
		lp := p.Logs[name]
		if k.Mounts {
			// The PII rule sets in the home volume; the device and inode of
			// the profile copy and of each bound root, which the console
			// checks on its mount points before it opens anything.
			w("      LOCKLOG_PII_DIR: %s", q(LocklogPIIDir))
			if id := p.ProfileIDs[l.Type]; id != "" {
				w("      LOCKLOG_EXPECT_DIR: %s", q(id))
			}
			if lp != nil {
				w("      LOCKLOG_EXPECT_ROOTS: %s", q(lp.Expect))
				if lp.DockerRoot != "" {
					w("      LOCKLOG_DOCKER_ROOT: %s", q(lp.DockerRoot))
				}
			}
			if len(l.LogRoots) > 0 {
				// The reviewed log_roots, as the launcher passes the ones it
				// took: part of the console's policy.
				w("      LOCKLOG_EXTRA_ROOTS: %s", q(strings.Join(l.LogRoots, " ")))
			}
			if lockNet(l, lp) && p.Project != "" {
				// A remote source is reached on the lock's own network,
				// through its gateway; no agent joins it.
				w("      LOCKLOG_NETWORK: %s", q(LockNetwork(p.Project, name)))
			}
		}
		// Where the lock reads its secrets: its address and namespace, and
		// the reviewed CA. Never the token (typed at the console's start).
		vaultCA := false
		if v := c.Vault; l.Vault && v != nil {
			w("      VAULT_ADDR: %s", q(v.Address))
			if v.Namespace != "" {
				w("      VAULT_NAMESPACE: %s", q(v.Namespace))
			}
			if p.VaultCA != "" {
				vaultCA = true
				w("      VAULT_CACERT: %s", q(VaultCAPath))
			}
		}
		cmd := []string{"console"}
		if prof := l.Profile; prof != "" || l.Type == "lockfile" {
			if prof == "" {
				prof = "default"
			}
			cmd = append(cmd, "--profile", prof)
		}
		if len(l.AllowedUIDs) > 0 {
			cmd = append(cmd, "--allowed-uids", l.AllowedUIDsFlag())
		}
		if !k.Gate {
			cmd = append(cmd, "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", HubKeyDir+"/hub.pub", "--instance", name)
			cmd = append(cmd, deviceArgs(c, l, p)...)
			if p.Facades != "" && l.Reveal {
				cmd = append(cmd, "--facade-keys-file", LockFacadesPath)
			}
		}
		if k.Project {
			// The console finds its project from its working directory.
			w("    working_dir: %s", q(p.Workspace))
		}
		w("    command: [%s]", quoteAll(cmd))
		// Docker's log of a console's terminal would keep every screen
		// (statements, results, personal data) for anyone who runs docker
		// logs: none, as the locks' own launchers.
		w("    logging:")
		w("      driver: none")
		// A gate kind's console only serves the policy: its devices go to
		// the gate (lea's), through up.json, not to the console.
		fp, dev := p.Profiles[l.Type], p.DevicesID != "" && l.Devices && !k.Gate
		vsum := ""
		if vaultCA {
			vsum = p.VaultCASum
		}
		// lockfile's console runs under the seccomp profile lockfile ships,
		// as its own launcher runs it, never Docker's default.
		var sec []string
		ssum := ""
		if usesSeccomp(l.Type) && p.Seccomp != "" {
			sec, ssum = []string{"seccomp=" + p.Seccomp}, p.SeccompSum
		}
		if fp != "" || dev || vsum != "" || ssum != "" || k.Mounts || p.Managed != "" {
			w("    labels:")
			if k.Mounts {
				// A locklog console: never in a containers map.
				w("      %s: \"1\"", LocklogConsoleLabel)
			}
			if fp != "" {
				w("      lockfamily.profile: %s", q(fp))
			}
			if dev {
				w("      lockfamily.devices: %s", q(p.DevicesID))
			}
			if vsum != "" {
				w("      lockfamily.vault-ca: %s", q(vsum))
			}
			if ssum != "" {
				w("      lockfamily.seccomp: %s", q(ssum))
			}
			if p.Managed != "" {
				w("      lockfamily.managed: %s", q(p.Managed))
			}
		}
		limits(w, k.Mem, k.Pids, sec...)
		if n := k.cpus(p.NCPU); n > 0 {
			w("    cpus: %d", n)
		}
		if lp != nil && len(lp.GIDs) > 0 {
			g := make([]string, len(lp.GIDs))
			for i, x := range lp.GIDs {
				g[i] = q(strconv.FormatUint(uint64(x), 10))
			}
			w("    group_add: [%s]", strings.Join(g, ", "))
		}
		w("    volumes:")
		w("      - %s", q(name+"-run:/run/"+l.Type))
		w("      - %s", q(name+"-home:"+home))
		w("      - hubkey:%s:ro", HubKeyDir)
		if p.Managed != "" {
			// The company's managed file, where the lock reads it.
			w("      - managed:%s:ro", ManagedDir)
		}
		// The reviewed copy of the lock's profile, never the workspace's
		// directory itself (agents can write it).
		if k.Project {
			w("      - %s", q("profile-"+l.Type+":"+profileDir(p.Workspace, l.Type)+":ro"))
		} else {
			w("      - %s", q("profile-"+l.Type+":"+home+"/.config/"+l.Type+":ro"))
		}
		if lp != nil {
			// The plan's log directories, read-only and non-recursive (no
			// submount of them appears), at their own paths.
			for _, d := range lp.Binds {
				w("      - type: bind")
				w("        source: %s", q(d))
				w("        target: %s", q(d))
				w("        read_only: true")
				w("        bind:")
				w("          recursive: disabled")
			}
			if lp.MapDir != "" {
				w("      - type: bind")
				w("        source: %s", q(lp.MapDir))
				w("        target: %s", q(LocklogMapTarget))
				w("        read_only: true")
			}
		}
		if p.Devices != "" && l.Devices && !k.Gate {
			w("      - type: bind")
			w("        source: %s", q(p.Devices))
			w("        target: /run/lockfamily-devices/devices.json")
			w("        read_only: true")
		}
		if vaultCA {
			w("      - type: bind")
			w("        source: %s", q(p.VaultCA))
			w("        target: %s", q(VaultCAPath))
			w("        read_only: true")
		}
		if p.Facades != "" && l.Reveal && !k.Gate {
			w("      - type: bind")
			w("        source: %s", q(p.Facades))
			w("        target: %s", q(LockFacadesPath))
			w("        read_only: true")
		}
		if k.Gate {
			// The gate asks the hub, from lea's proxy: the console only
			// serves the policy and has no hub network.
			w("    networks: [%s]", q("egress-"+name))
		} else if !lockNet(l, lp) {
			// A locklog console with local sources only: the hub's network
			// alone (internal: no route out).
			w("    networks: [lockhub]")
			w("    depends_on: [lockhub]")
		} else {
			// locknet-<name> is internal: the lock reaches the hosts of its
			// reviewed profile through its gateway only (egress.go).
			w("    networks: [lockhub, %s]", q("locknet-"+name))
			if eg := p.Egress[name]; len(eg.Endpoints) > 0 {
				w("    depends_on: [lockhub, %s]", q("gw-"+name))
			} else {
				w("    depends_on: [lockhub]")
			}
		}
		w("    restart: %s", restartPolicy)
		if eg := p.Egress[name]; lockNet(l, lp) && len(eg.Endpoints) > 0 {
			gateway(w, c.Hub.Image, name, eg)
		}
		if k.Gate {
			// The gate's own volume (0700, the gate's account), with its
			// instance key: lox up makes it and reads the key; lea's gate
			// mounts it as --home.
			w("  gatehome-%s:", name)
			w("    image: %s", q(l.Image))
			w("    profiles: [setup]")
			w("    user: \"0:0\"")
			w("    entrypoint: [\"/bin/sh\", \"-c\", %s]", q("chmod 0700 /g && chown "+gateUID+":"+gateGID+" /g"))
			w("    network_mode: none")
			hardening(w)
			// Again on every lox up: /g is the gate's by then.
			w("    cap_add: [CHOWN, FOWNER]")
			w("    volumes:")
			w("      - %s", q(name+"-gate:/g"))
			w("  gatekey-%s:", name)
			w("    image: %s", q(l.Image))
			w("    profiles: [setup]")
			w("    user: %s", q(gateUID+":"+gateGID))
			w("    command: [\"hub-key\", \"--instance\", %s, \"--home\", \"/g\"]", q(name))
			w("    network_mode: none")
			hardening(w)
			w("    volumes:")
			w("      - %s", q(name+"-gate:/g"))
		}
	}
	for _, name := range c.Instances() {
		l := c.Locks[name]
		k := Kinds[l.Type]
		if !k.Mounts && !k.Rules {
			continue
		}
		type setup struct {
			svc  string
			args []string
		}
		var svcs []setup
		if k.Mounts {
			// mounts-<instance> derives the mount plan from the reviewed
			// copy (on its stdin, unpacked in a tmpfs at the workspace's
			// path), as the image's agent with no network, as the
			// launcher's read_plan.
			args := []string{"/bin/sh", "-c", fmt.Sprintf(`mkdir -p "$0/.%s" && head -c %d | tar -x -C "$0/.%s" && cd "$0" && exec %s mounts "$@"`, l.Type, maxTar, l.Type, l.Type), p.Workspace}
			if l.Profile != "" {
				args = append(args, "--profile", l.Profile)
			}
			svcs = append(svcs, setup{"mounts-" + name, args})
		}
		if k.Rules {
			// rules-<instance> reads the profiles' auto rules from the same
			// copy, the same way (<type> profile rules --json): no network,
			// no volume, so the rules are the reviewed file's.
			rules := []string{"/bin/sh", "-c", fmt.Sprintf(`mkdir -p "$0/.%s" && head -c %d | tar -x -C "$0/.%s" && cd "$0" && exec %s profile rules --json "$@"`, l.Type, maxTar, l.Type, l.Type), p.Workspace}
			if l.Profile != "" {
				rules = append(rules, "--profile", l.Profile)
			}
			svcs = append(svcs, setup{"rules-" + name, rules})
		}
		uid, gid, _ := strings.Cut(k.Agent, ":")
		for _, s := range svcs {
			w("  %s:", q(s.svc))
			w("    image: %s", q(l.Image))
			w("    profiles: [setup]")
			w("    user: %s", q(k.Agent))
			w("    environment:")
			w("      HOME: \"/tmp\"")
			w("    entrypoint: [%s]", quoteAll(s.args))
			w("    network_mode: none")
			w("    read_only: true")
			w("    cap_drop: [ALL]")
			w("    security_opt: [\"no-new-privileges:true\"]")
			w("    tmpfs: [\"/tmp:size=16m\", %s]", q(p.Workspace+":size=2m,uid="+uid+",gid="+gid+",mode=0700"))
			w("    pids_limit: 64")
			w("    mem_limit: 256m")
		}
	}
	for _, name := range p.Rotate {
		l, ok := c.Locks[name]
		if !ok {
			continue
		}
		k := Kinds[l.Type]
		home, vol, user := "/home/"+l.Type, name+"-home", k.UID+":"+k.GID
		if k.Gate {
			home, vol, user = "/g", name+"-gate", gateUID+":"+gateGID
		}
		// rotkey-<instance> drops or applies the new key lox run --rotate
		// made in the lock's own volume, as the key's owner.
		w("  %s:", q("rotkey-"+name))
		w("    image: %s", q(l.Image))
		w("    profiles: [setup]")
		w("    user: %s", q(user))
		w("    entrypoint: [\"/bin/sh\", \"-c\", %s, \"rotkey\"]", q(rotkeyScript(home, name)))
		w("    network_mode: none")
		hardening(w)
		w("    volumes:")
		w("      - %s", q(vol+":"+home))
	}
	for _, name := range c.Instances() {
		l := c.Locks[name]
		k := Kinds[l.Type]
		if !k.HomeFiles {
			continue
		}
		// homefiles-<instance> tells, as the console's account, what each
		// path on its stdin is in the console's filesystem (its home
		// volume); homecopy-<instance> writes its stdin to the path it is
		// given there (lox add, a file the human named after the review).
		for _, s := range []struct{ svc, script string }{{"homefiles-", homeFilesScript}, {"homecopy-", homeCopyScript}} {
			w("  %s:", q(s.svc+name))
			w("    image: %s", q(l.Image))
			w("    profiles: [setup]")
			w("    user: %s", q(k.UID+":"+k.GID))
			if s.svc == "homefiles-" && k.Project {
				w("    working_dir: %s", q(p.Workspace))
			}
			// $$: compose would otherwise read the script's own $ as its variables.
			w("    entrypoint: [\"/bin/sh\", \"-c\", %s, %s]", q(strings.ReplaceAll(s.script, "$", "$$")), q(s.svc[:len(s.svc)-1]))
			w("    network_mode: none")
			hardening(w)
			w("    volumes:")
			w("      - %s", q(name+"-home:"+ConsoleHome(l.Type)))
			if s.svc == "homefiles-" {
				// The profile's copy where the console sees it (a project
				// kind's working directory, where a relative path resolves;
				// lockfile's ~/.config/lockfile), as in the console. Paths
				// into it are checked in the reviewed copy, not here: this
				// one is the last applied (homefiles.go).
				w("      - %s", q("profile-"+l.Type+":"+ConsoleProfileDir(p.Workspace, l.Type)+":ro"))
			}
		}
	}
	if p.Managed != "" {
		managedServices(w, c, p)
	}
	// profile-<type> copies the reviewed profile into its volume (lox
	// up runs it after the human's yes), as root: the lock reads it only.
	for _, t := range types(c) {
		w("  %s:", q("profile-"+t))
		w("    image: %s", q(firstImage(c, t)))
		w("    profiles: [setup]")
		w("    user: \"0:0\"")
		script := fmt.Sprintf("find /p -mindepth 1 -delete && head -c %d | tar -x -C /p && chown %s:%s /p && chmod 0700 /p", maxTar, Kinds[t].UID, Kinds[t].GID)
		if Kinds[t].Mounts {
			// The copy's device and inode, for LOCKLOG_EXPECT_DIR.
			script += " && stat -c %d:%i /p"
		}
		w("    entrypoint: [\"/bin/sh\", \"-c\", %s]", q(script))
		w("    network_mode: none")
		hardening(w)
		// The archive's owner (the console) and modes, kept by root, which
		// also clears the console's previous copy (its 0700 directories):
		// a service with no network that only unpacks what lox up sends.
		w("    cap_add: [CHOWN, FOWNER, DAC_OVERRIDE]")
		w("    volumes:")
		w("      - %s", q("profile-"+t+":/p"))
	}
	// Each network's own small subnet, when lox run gave it one.
	ipam := func(key string) {
		if s := p.Subnets[key]; s != "" {
			w("    ipam:")
			w("      config:")
			w("        - subnet: %s", q(s))
		}
	}
	network := func(key string, internal bool) {
		if !internal && p.Subnets[key] == "" {
			w("  %s: {}", q(key))
			return
		}
		w("  %s:", q(key))
		if internal {
			w("    internal: true")
		}
		ipam(key)
	}
	w("networks:")
	w("  lockhub:")
	w("    internal: true")
	labels(RoleHub, "", "")
	ipam("lockhub")
	if c.HubEgress() {
		network("egress-hub", false)
	}
	if c.Hub.Mobile != nil {
		network("mobile-hub", false)
	}
	var joins []string
	for _, name := range c.Instances() {
		if Kinds[c.Locks[name].Type].Gate {
			// lockhttp's egress is its own policy's.
			network("egress-"+name, false)
			continue
		}
		if !lockNet(c.Locks[name], p.Logs[name]) {
			continue
		}
		network("locknet-"+name, true)
		if eg := p.Egress[name]; len(eg.Endpoints) > 0 {
			network("gwlink-"+name, true)
			if eg.routeOut() {
				network("out-"+name, false)
			}
			for _, j := range eg.joinedNets() {
				if !slices.Contains(joins, j) {
					joins = append(joins, j)
				}
			}
		}
	}
	// The existing networks a gateway joins: never created, nor removed
	// (compose leaves an external network be).
	for _, j := range joins {
		w("  %s:", q(JoinNetKey(j)))
		w("    external: true")
		w("    name: %s", q(j))
	}
	w("volumes:")
	w("  hubkey: {}")
	if p.Managed != "" {
		w("  managed: {}")
	}
	for _, t := range types(c) {
		w("  %s: {}", q("profile-"+t))
	}
	for _, name := range c.Instances() {
		l := c.Locks[name]
		w("  %s:", q(name+"-run"))
		labels(RoleSocket, name, l.Type)
		w("  %s: {}", q(name+"-home"))
		if Kinds[l.Type].Gate {
			w("  %s:", q(name+"-gate"))
			labels(RoleGateHome, name, l.Type)
		}
	}
	return b.String()
}

// managedServices writes the setup services of the managed file:
// managed, which copies it into its volume (the archive on its stdin, as
// root: the locks refuse a managed file or directory another account
// could write), and managedcheck-<instance>, which runs the lock's
// `<type> managed check` on the reviewed copy of its profile (on its
// stdin, unpacked in a tmpfs where the console sees it) under that
// volume, as the console's account, with no network: the lock's own
// verdict on the managed bounds, before it is started.
func managedServices(w func(string, ...any), c *Config, p Paths) {
	w("  managed:")
	w("    image: %s", q(c.Hub.Image))
	w("    profiles: [setup]")
	w("    user: \"0:0\"")
	w("    entrypoint: [\"/bin/sh\", \"-c\", %s]", q(fmt.Sprintf("find /m -mindepth 1 -delete && head -c %d | tar -x -C /m && chown -R 0:0 /m && chmod 0755 /m && chmod 0644 /m/*", 4*maxManaged)))
	w("    network_mode: none")
	hardening(w)
	w("    cap_add: [CHOWN, FOWNER, DAC_OVERRIDE]")
	w("    volumes:")
	w("      - managed:/m")
	for _, name := range c.Instances() {
		l := c.Locks[name]
		k := Kinds[l.Type]
		// The console's working directory and the tmpfs that holds the
		// copy: the workspace for a project kind, else its home.
		dir, wd := ConsoleProfileDir(p.Workspace, l.Type), ConsoleHome(l.Type)
		if k.Project {
			wd = p.Workspace
		}
		// $$: compose would otherwise read the script's own $ as its variables.
		script := fmt.Sprintf(`mkdir -p "$0" && head -c %d | tar -x -C "$0" && chmod 0700 "$0" && cd "$1" && shift && exec %s managed check "$@"`, maxTar, l.Type)
		args := []string{"/bin/sh", "-c", strings.ReplaceAll(script, "$", "$$"), dir, wd}
		if prof := l.Profile; prof != "" || l.Type == "lockfile" {
			if prof == "" {
				prof = "default"
			}
			args = append(args, "--profile", prof)
		}
		w("  %s:", q("managedcheck-"+name))
		w("    image: %s", q(l.Image))
		w("    profiles: [setup]")
		w("    user: %s", q(k.UID+":"+k.GID))
		w("    environment:")
		w("      HOME: %s", q(ConsoleHome(l.Type)))
		w("    entrypoint: [%s]", quoteAll(args))
		w("    network_mode: none")
		w("    read_only: true")
		w("    cap_drop: [ALL]")
		w("    security_opt: [\"no-new-privileges:true\"]")
		w("    tmpfs: [\"/tmp:size=16m\", %s]", q(wd+":size=4m,uid="+k.UID+",gid="+k.GID+",mode=0700"))
		w("    pids_limit: 64")
		w("    mem_limit: 256m")
		w("    volumes:")
		w("      - managed:%s:ro", ManagedDir)
	}
}

// gateway writes a lock's egress gateway (egress.go): gw-<name>, on the
// lock's internal network under the endpoints' names, and gwout-<name>,
// the only one with a route out, each forwarding only the allowlist.
// Both run the hub's image (lockhub egress-gateway), its own account.
func gateway(w func(string, ...any), image, name string, eg Egress) {
	front, back, joined := eg.forwards(name)
	args := func(fs []egress.Forward) string {
		a := []string{"egress-gateway"}
		for _, f := range fs {
			a = append(a, "--forward", f.String())
		}
		return quoteAll(a)
	}
	common := func() {
		w("    image: %s", q(image))
		limits(w, "64m", 64)
		// Ports below 1024 (https) for its own account, as Docker sets it.
		w("    sysctls:")
		w("      net.ipv4.ip_unprivileged_port_start: \"0\"")
		w("    restart: %s", restartPolicy)
	}
	w("  %s:", q("gw-"+name))
	common()
	w("    command: [%s]", args(front))
	w("    networks:")
	w("      %s:", q("locknet-"+name))
	w("        aliases: [%s]", quoteAll(eg.aliases()))
	w("      %s: {}", q("gwlink-"+name))
	if len(back) > 0 {
		w("  %s:", q("gwout-"+name))
		common()
		w("    command: [%s]", args(back))
		if eg.hostGateway() {
			// A database or broker on this machine, named so in the profile.
			w("    extra_hosts: [\"host.docker.internal:host-gateway\"]")
		}
		w("    networks: [%s, %s]", q("gwlink-"+name), q("out-"+name))
	}
	if len(joined) > 0 {
		// The joined networks' half (lockhub#194): never on out-<n>, so a
		// container there reaches through it only what it reaches anyway,
		// and no name of the route out is resolved on those networks.
		nets := []string{q("gwlink-" + name)}
		for _, j := range eg.joinedNets() {
			nets = append(nets, q(JoinNetKey(j)))
		}
		w("  %s:", q("gwnet-"+name))
		common()
		w("    command: [%s]", args(joined))
		w("    networks: [%s]", strings.Join(nets, ", "))
	}
}

// deviceArgs are a lock's flags for the paired devices: pinned, and as
// hub.mobile asks, sealed to and required; only for a lock that takes
// them (locks.<name>.devices).
func deviceArgs(c *Config, l Lock, p Paths) []string {
	if p.Devices == "" || !l.Devices {
		return nil
	}
	out := []string{"--devices-file", "/run/lockfamily-devices/devices.json"}
	if m := c.Hub.Mobile; m != nil {
		if m.SealClear {
			out = append(out, "--seal-clear")
		}
		if len(m.RequireDevice) > 0 {
			out = append(out, "--require-device", strings.Join(m.RequireDevice, ","))
		}
	}
	return out
}

// types are the lock types c runs, sorted.
func types(c *Config) []string {
	var out []string
	for _, n := range c.Instances() {
		if t := c.Locks[n].Type; !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// firstImage is the image of the first instance of type t.
func firstImage(c *Config, t string) string {
	for _, n := range c.Instances() {
		if c.Locks[n].Type == t {
			return c.Locks[n].Image
		}
	}
	return ""
}

// profileDir is the lock's own configuration in the workspace.
func profileDir(ws, typ string) string { return filepath.Join(ws, "."+typ) }

func quoteAll(a []string) string {
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = q(x)
	}
	return strings.Join(s, ", ")
}

func hardening(w func(string, ...any)) { limits(w, "512m", 256) }

// limits writes the hardening every service gets; sec are more
// security_opt entries (a lockfile lock's seccomp profile).
func limits(w func(string, ...any), mem string, pids int, sec ...string) {
	w("    read_only: true")
	w("    cap_drop: [ALL]")
	w("    security_opt: [%s]", quoteAll(append([]string{"no-new-privileges:true"}, sec...)))
	w("    tmpfs: [\"/tmp:size=16m\"]")
	w("    pids_limit: %d", pids)
	w("    mem_limit: %s", mem)
}
