package family

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/egress"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Doctor is one `lox doctor`: it checks a workspace's hub and locks and
// says what to do. It changes nothing: no file, no container, no account.
type Doctor struct {
	// File, State and Runtime are as in Up.
	File, State, Runtime string
	// Root is the host's root ("/"), where leftover host accounts of the
	// pre-hub setup are looked for.
	Root string
	Run  Runner
	Out  io.Writer
}

// Do runs the checks and returns the number of failures.
func (d *Doctor) Do(ctx context.Context) int {
	fails := 0
	ok := func(f string, a ...any) { fmt.Fprintf(d.Out, "ok   "+f+"\n", a...) }
	warn := func(f string, a ...any) { fmt.Fprintf(d.Out, "warn "+f+"\n", a...) }
	fail := func(f string, a ...any) { fails++; fmt.Fprintf(d.Out, "FAIL "+f+"\n", a...) }

	c, err := Load(d.File)
	if err != nil {
		fail("lockfamily.yaml: %v", err)
	} else {
		ok("lockfamily.yaml: %d lock(s): %s", len(c.Locks), strings.Join(c.Instances(), ", "))
		// The locks the last lox run did not start: said once here, and
		// left out of the checks of what it applied.
		ns, err := ReadNotStarted(d.State)
		if err != nil {
			fail("locks not started: %v", err)
		}
		skip := map[string]string{}
		for _, n := range c.Instances() {
			if why, has := ns[n]; has {
				fail("lock %s: not started: %s (fix it, then lox run: the other locks are served)", n, why)
				skip[n] = why
			}
		}
		c = c.without(skip)
	}

	engine := true
	if out, err := d.Run.Run(ctx, nil, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		engine = false
		fail("engine: docker info: %v", err)
	} else {
		ok("engine: %s", strings.TrimSpace(string(out)))
	}

	if c != nil && engine {
		for _, img := range images(c) {
			if _, err := d.Run.Run(ctx, nil, "docker", "image", "inspect", "--format", "{{.Id}}", img); err != nil {
				warn("image %s: not pulled yet (lox run pulls it after checking its signature)", img)
			} else {
				ok("image %s", img)
			}
		}
	}

	upRan := true
	hubData := filepath.Join(d.State, "hub")
	for _, dir := range []struct{ name, path string }{{"state", d.State}, {"hub data", hubData}, {"facade dir", filepath.Join(d.Runtime, "lockhub")}} {
		switch err := checkPrivate(dir.path); {
		case errors.Is(err, os.ErrNotExist):
			upRan = false
			fail("%s %s: missing: run lox run", dir.name, dir.path)
		case err != nil && dir.name == "facade dir":
			// Docker made it as root while it was missing (a tmpfs, wiped at
			// reboot): lox up repairs it, or says what to run.
			fail("%s: %v: run lox run (it repairs it, or says what to run)", dir.name, err)
		case err != nil:
			fail("%s: %v", dir.name, err)
		default:
			ok("%s %s: yours, 0700", dir.name, dir.path)
		}
	}
	if !upRan {
		d.accounts(warn)
		return fails
	}

	// Keys: the hub's, and the lock list lox up gave the hub.
	hubPub := ""
	if b, err := os.ReadFile(filepath.Join(d.State, "hub.pub")); err != nil {
		fail("hub key: %v", err)
	} else if hubPub = strings.TrimSpace(string(b)); !validPub(hubPub) {
		fail("hub key %s: not a base64 Ed25519 public key", filepath.Join(d.State, "hub.pub"))
	} else {
		ok("hub key %s", hubPub)
	}
	locks, err := keys.LoadLocks(filepath.Join(hubData, "locks.json"))
	if err != nil {
		fail("hub lock list: %v", err)
	} else if c != nil {
		var have []string
		for n := range locks {
			have = append(have, n)
		}
		slices.Sort(have)
		if !slices.Equal(have, c.Instances()) {
			fail("hub lock list: the hub knows %s, lockfamily.yaml declares %s: run lox run", strings.Join(have, ", "), strings.Join(c.Instances(), ", "))
		} else {
			ok("hub lock list: a key for each lock")
		}
	}
	if c != nil && c.Hub.Slack != nil {
		var bad []string
		for _, f := range []string{chatconf.SlackAppToken, chatconf.SlackBotToken} {
			if _, err := chatconf.ReadSecret(filepath.Join(hubData, f)); err != nil {
				bad = append(bad, err.Error())
			}
		}
		if len(bad) > 0 {
			fail("slack tokens: %s: run lox add slack", strings.Join(bad, "; "))
		} else {
			ok("slack tokens present, 0600")
		}
	}
	if c != nil && c.Hub.Telegram != nil {
		if _, err := chatconf.ReadSecret(filepath.Join(hubData, chatconf.TelegramToken)); err != nil {
			fail("telegram token: %v: run lox add telegram", err)
		} else {
			ok("telegram token present, 0600")
		}
	}
	if c != nil {
		d.routing(c, ok, fail)
		d.applied(c, warn)
	}

	// The facade socket: the human's only, never other users'.
	sock := filepath.Join(d.Runtime, "lockhub", "facade.sock")
	if fi, err := os.Lstat(sock); err != nil {
		fail("facade socket %s: %v (is the hub running?)", sock, err)
	} else if fi.Mode()&os.ModeSocket == 0 {
		fail("facade socket %s: not a socket (%v)", sock, fi.Mode())
	} else if fi.Mode().Perm()&0o007 != 0 {
		fail("facade socket %s: mode %v gives other users access", sock, fi.Mode().Perm())
	} else if st, ok2 := fi.Sys().(*syscall.Stat_t); ok2 && int(st.Uid) != os.Getuid() {
		fail("facade socket %s: owned by uid %d, not by you", sock, st.Uid)
	} else {
		ok("facade socket %s", sock)
		d.hubLimits(ctx, sock, c, ok, warn, fail)
	}

	if c != nil && engine {
		d.stack(ctx, c, ok, fail)
		d.logMaps(ctx, c, ok, warn, fail)
	}
	d.accounts(warn)
	return fails
}

// logMaps checks the containers map of each locklog lock with a docker
// source against the containers its approved globs name now: a stale map
// serves containers since removed, and not the new ones, until lox
// refresh rewrites it (lox run runs no map loop).
func (d *Doctor) logMaps(ctx context.Context, c *Config, ok, warn, fail func(string, ...any)) {
	for _, n := range c.Instances() {
		if !Kinds[c.Locks[n].Type].Mounts {
			continue
		}
		// A workspace applied before lox run kept mount plans: nothing
		// is broken, the next lox run derives and reviews the plan.
		if _, err := os.Lstat(filepath.Join(logDir(d.State, n), planFile)); errors.Is(err, fs.ErrNotExist) {
			warn("lock %s mount plan: none applied yet (a workspace from before lox run derived mount plans): run lox run to review and apply it", n)
			continue
		}
		msg, stale, err := logMapStale(ctx, d.Run, d.State, n)
		switch {
		case err != nil:
			fail("lock %s containers map: %v", n, err)
		case stale:
			warn("lock %s containers map: %s", n, msg)
		case msg != "":
			ok("lock %s containers map: %s", n, msg)
		}
	}
}

// routing checks that the hub applies the routing lockfamily.yaml
// declares (lox up writes routing.json; the hub reads it at start).
func (d *Doctor) routing(c *Config, ok, fail func(string, ...any)) {
	p := filepath.Join(d.State, "hub", "routing.json")
	b, err := os.ReadFile(p)
	if err != nil {
		fail("hub routing: %v (without it the hub runs the local facades only, no chat: run lox run)", err)
		return
	}
	var r route.Rules
	if err := json.Unmarshal(b, &r); err != nil {
		fail("hub routing %s: %v", p, err)
		return
	}
	// What lox run writes: hub.routing, narrowed (mobile, locklog,
	// lockssh's local risks).
	want := Routes(c)
	if !sameSet(r.Enabled, want.Enabled) || len(r.Only) != len(want.Only) || len(r.LocalRisks) != len(want.LocalRisks) {
		fail("hub routing %s differs from lockfamily.yaml: run lox run", p)
		return
	}
	for inst, fs := range want.Only {
		if got, has := r.Only[inst]; !has || !sameSet(got, fs) {
			fail("hub routing %s: %s differs from lockfamily.yaml: run lox run", p, inst)
			return
		}
	}
	for inst, rs := range want.LocalRisks {
		if got, has := r.LocalRisks[inst]; !has || !sameSet(got, rs) {
			fail("hub routing %s: %s differs from lockfamily.yaml: run lox run", p, inst)
			return
		}
	}
	ok("hub routing: facades %s", strings.Join(r.Enabled, ","))
}

// applied warns when lockfamily.yaml no longer matches what the last
// confirmed lox up applied (keys aside: they are the locks' to report), and when a chat token
// was rotated since.
func (d *Doctor) applied(c *Config, warn func(string, ...any)) {
	b, err := os.ReadFile(filepath.Join(d.State, "applied.json"))
	if err != nil {
		warn("lockfamily.yaml never applied: run lox run")
		return
	}
	var a Applied
	if json.Unmarshal(b, &a) != nil {
		warn("applied.json unreadable: run lox run")
		return
	}
	noKeys := func(s []string) []string {
		return slices.DeleteFunc(slices.Clone(s), func(l string) bool {
			// The allowlists and the mount plans derive from the
			// profiles, not from the yaml.
			return strings.Contains(l, " key ") || strings.HasPrefix(l, "profile ") || strings.HasPrefix(l, "hub secret ") || strings.HasPrefix(l, "device ") || egressLine.MatchString(l) || logPlanLine.MatchString(l) || notStartedRe.MatchString(l)
		})
	}
	if ch := diff(noKeys(a.Summary), noKeys(Summary(c, "", nil, nil))); len(ch) > 0 {
		warn("lockfamily.yaml changed since the last lox run (run lox run to review it): %s", strings.Join(ch, "; "))
	}
	// Devices paired or revoked since: the locks pin them at the next lox up.
	if devs, err := ReadDevices(d.State); err != nil {
		warn("paired devices: %v", err)
	} else {
		onlyDevices := func(s []string) []string {
			return slices.DeleteFunc(slices.Clone(s), func(l string) bool { return !strings.HasPrefix(l, "device ") })
		}
		if ch := diff(onlyDevices(a.Summary), devicesSummary(devs)); len(ch) > 0 {
			warn("paired devices changed since the last lox run (run lox run to pin them at the locks): %s", strings.Join(ch, "; "))
		}
	}
	// The hub reads its chat tokens at start: one rotated since is not in
	// use until lox up recreates it. Only tokens the last lox up applied
	// compare (a facade added since is the yaml's change; a summary from
	// before token identities has none).
	applied := map[string]string{}
	for _, l := range a.Summary {
		if f, ok := secretFile(l); ok {
			applied[f] = l
		}
	}
	var ch []string
	for _, l := range chatTokens(c, filepath.Join(d.State, "hub")) {
		if f, _ := secretFile(l); applied[f] != "" && applied[f] != l {
			ch = append(ch, "- "+applied[f], "+ "+l)
		}
	}
	if len(ch) > 0 {
		warn("a chat token changed since the last lox run (run lox run to apply it): %s", strings.Join(ch, "; "))
	}
}

// stack checks the compose project's containers and its internal network.
func (d *Doctor) stack(ctx context.Context, c *Config, ok, fail func(string, ...any)) {
	ws, _ := filepath.Abs(Workspace(d.File))
	project := Project(ws)
	compose := filepath.Join(d.State, "compose.yaml")
	out, err := d.Run.Run(ctx, nil, "docker", "compose", "-p", project, "--project-directory", d.State, "--env-file", os.DevNull, "-f", compose, "ps", "--all", "--format", "json")
	if err != nil {
		fail("compose project %s: %v", project, err)
		return
	}
	state, err := psStates(out)
	if err != nil {
		fail("compose project %s: %v", project, err)
		return
	}
	want := []string{"lockhub"}
	for _, n := range c.Instances() {
		want = append(want, "lock-"+n)
	}
	for _, s := range want {
		switch st := state[s]; st {
		case "running":
			ok("%s running", s)
		case "":
			fail("%s not created: run lox run", s)
		default:
			fail("%s %s: docker compose -p %s -f %s logs %s", s, st, project, compose, s)
		}
	}
	d.egress(ctx, c, project, state, ok, fail)
	// I2: no route out of the hub's network.
	net := project + "_lockhub"
	if out, err := d.Run.Run(ctx, nil, "docker", "network", "inspect", "--format", "{{.Internal}}", net); err != nil {
		fail("network %s: %v", net, err)
	} else if strings.TrimSpace(string(out)) != "true" {
		fail("network %s is not internal: the hub must have no route out (run lox run)", net)
	} else {
		ok("network %s internal", net)
	}
}

// egress checks each lock's effective egress (lockhub#123): every network
// the lock's container is on is internal, and its gateway runs and
// forwards exactly the allowlist the last lox run applied.
func (d *Doctor) egress(ctx context.Context, c *Config, project string, state map[string]string, ok, fail func(string, ...any)) {
	var applied Applied
	if b, err := os.ReadFile(filepath.Join(d.State, "applied.json")); err == nil {
		json.Unmarshal(b, &applied)
	}
	for _, n := range c.Instances() {
		if Kinds[c.Locks[n].Type].Gate {
			continue
		}
		if state["lock-"+n] != "running" {
			continue
		}
		var want []string
		for _, l := range applied.Summary {
			if rest, found := strings.CutPrefix(l, "lock "+n+" egress "); found {
				if addr, _, found := strings.Cut(rest, " ("); found && !strings.HasPrefix(rest, "unreachable:") && !strings.HasPrefix(rest, "none:") {
					want = append(want, addr)
				}
			}
		}
		out, err := d.Run.Run(ctx, nil, "docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", project+"-lock-"+n+"-1")
		var nets map[string]json.RawMessage
		if err == nil {
			err = json.Unmarshal(out, &nets)
		}
		if err != nil || len(nets) == 0 {
			fail("lock %s egress: its networks cannot be read: %v", n, err)
			continue
		}
		var names []string
		for k := range nets {
			names = append(names, k)
		}
		slices.Sort(names)
		open := ""
		for _, k := range names {
			if out, err := d.Run.Run(ctx, nil, "docker", "network", "inspect", "--format", "{{.Internal}}", k); err != nil || strings.TrimSpace(string(out)) != "true" {
				open = k
				break
			}
		}
		if open != "" {
			fail("lock %s egress: its network %s is not internal, it has a route out: run lox run", n, open)
			continue
		}
		if len(want) == 0 {
			ok("lock %s egress: none (internal networks, no gateway)", n)
			continue
		}
		bad := false
		for _, s := range []string{"gw-" + n, "gwout-" + n} {
			if st := state[s]; st != "running" {
				fail("lock %s egress: its gateway %s is %s, the lock reaches nothing: docker compose -p %s logs %s (a hub image without lockhub egress-gateway? lox run upgrades it)", n, s, orNone(st), project, s)
				bad = true
			}
		}
		if bad {
			continue
		}
		out, err = d.Run.Run(ctx, nil, "docker", "inspect", "-f", "{{json .Config.Cmd}}", project+"-gwout-"+n+"-1")
		var cmd []string
		if err == nil {
			err = json.Unmarshal(out, &cmd)
		}
		if err != nil {
			fail("lock %s egress: the gateway's forwards cannot be read: %v", n, err)
			continue
		}
		var got []string
		for i := 0; i+1 < len(cmd); i++ {
			if cmd[i] == "--forward" {
				if f, err := egress.ParseForward(cmd[i+1]); err == nil {
					got = append(got, net.JoinHostPort(f.Host, strconv.Itoa(f.Port)))
				}
			}
		}
		sg, sw := slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
		if !slices.Equal(sg, sw) {
			fail("lock %s egress: the gateway forwards to %s, the last lox run reviewed %s: run lox run", n, strings.Join(got, ", "), strings.Join(want, ", "))
			continue
		}
		ok("lock %s egress: only %s (internal networks, gateway running)", n, strings.Join(want, ", "))
	}
}

func orNone(s string) string {
	if s == "" {
		return "not created"
	}
	return s
}

// psStates reads `docker compose ps --format json`: one object per line
// (Compose ≥ 2.21) or one array (older).
func psStates(out []byte) (map[string]string, error) {
	type svc struct{ Service, State string }
	var all []svc
	s := strings.TrimSpace(string(out))
	if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &all); err != nil {
			return nil, err
		}
	} else {
		for _, l := range strings.Split(s, "\n") {
			if l = strings.TrimSpace(l); l == "" {
				continue
			}
			var v svc
			if err := json.Unmarshal([]byte(l), &v); err != nil {
				return nil, err
			}
			all = append(all, v)
		}
	}
	m := map[string]string{}
	for _, v := range all {
		m[v.Service] = v.State
	}
	return m, nil
}

// accounts reports what the pre-hub, host-installed consoles left: an
// account, a clients group, /etc/<tool> and /run/<tool>. It prints the
// commands that remove them, and never runs them.
func (d *Doctor) accounts(warn func(string, ...any)) {
	users := names(filepath.Join(d.Root, "etc", "passwd"))
	groups := names(filepath.Join(d.Root, "etc", "group"))
	for _, t := range Types {
		var cmds []string
		if users[t] {
			cmds = append(cmds, "sudo userdel "+t)
		}
		if groups[t+"-clients"] {
			cmds = append(cmds, "sudo groupdel "+t+"-clients")
		}
		for _, dir := range []string{"etc", "run"} {
			if _, err := os.Lstat(filepath.Join(d.Root, dir, t)); err == nil {
				cmds = append(cmds, "sudo rm -r /"+dir+"/"+t)
			}
		}
		if len(cmds) > 0 {
			warn("host setup of %s left from before the hub (the hub's locks do not use it). Once no standalone %s console runs, remove it yourself:\n       %s", t, t, strings.Join(cmds, "\n       "))
		}
	}
}

// names are the first fields of a passwd or group file.
func names(path string) map[string]bool {
	m := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if n, _, ok := strings.Cut(s.Text(), ":"); ok {
			m[n] = true
		}
	}
	return m
}

// images are the distinct images of c, sorted.
func images(c *Config) []string {
	out := []string{c.Hub.Image}
	for _, n := range c.Instances() {
		if !slices.Contains(out, c.Locks[n].Image) {
			out = append(out, c.Locks[n].Image)
		}
	}
	slices.Sort(out)
	return out
}

// checkPrivate is privateDir's check, without creating anything.
func checkPrivate(d string) error {
	return checkPrivateAs(d, ownedByMe)
}

// checkPrivateAs is checkPrivate, mine saying whether a directory is the
// user's.
func checkPrivateAs(d string, mine func(os.FileInfo) bool) error {
	fi, err := os.Lstat(d)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory (a link?)", d)
	}
	if !mine(fi) {
		return fmt.Errorf("%s: owned by uid %d, not by you", d, owner(fi))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: mode %v, want 0700", d, fi.Mode().Perm())
	}
	return nil
}
