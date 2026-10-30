package family

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Doctor is one `lock doctor`: it checks a workspace's hub and locks and
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
				warn("image %s: not pulled yet (lock up pulls it after checking its signature)", img)
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
			fail("%s %s: missing: run lock up", dir.name, dir.path)
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

	// Keys: the hub's, and the lock list lock up gave the hub.
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
			fail("hub lock list: the hub knows %s, lockfamily.yaml declares %s: run lock up", strings.Join(have, ", "), strings.Join(c.Instances(), ", "))
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
			fail("slack tokens: %s: run lock add slack", strings.Join(bad, "; "))
		} else {
			ok("slack tokens present, 0600")
		}
	}
	if c != nil && c.Hub.Telegram != nil {
		if _, err := chatconf.ReadSecret(filepath.Join(hubData, chatconf.TelegramToken)); err != nil {
			fail("telegram token: %v: run lock add telegram", err)
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
	}

	if c != nil && engine {
		d.stack(ctx, c, ok, fail)
	}
	d.accounts(warn)
	return fails
}

// routing checks that the hub applies the routing lockfamily.yaml
// declares (lock up writes routing.json; the hub reads it at start).
func (d *Doctor) routing(c *Config, ok, fail func(string, ...any)) {
	p := filepath.Join(d.State, "hub", "routing.json")
	b, err := os.ReadFile(p)
	if err != nil {
		fail("hub routing: %v (without it the hub runs every facade: run lock up)", err)
		return
	}
	var r route.Rules
	if err := json.Unmarshal(b, &r); err != nil {
		fail("hub routing %s: %v", p, err)
		return
	}
	want := route.Rules{Enabled: c.Hub.Facades, Only: c.Hub.Routing}
	if !sameSet(r.Enabled, want.Enabled) || len(r.Only) != len(want.Only) {
		fail("hub routing %s differs from lockfamily.yaml: run lock up", p)
		return
	}
	for inst, fs := range want.Only {
		if got, has := r.Only[inst]; !has || !sameSet(got, fs) {
			fail("hub routing %s: %s differs from lockfamily.yaml: run lock up", p, inst)
			return
		}
	}
	ok("hub routing: facades %s", strings.Join(r.Enabled, ","))
}

// applied warns when lockfamily.yaml no longer matches what the last
// confirmed lock up applied (keys aside: they are the locks' to report).
func (d *Doctor) applied(c *Config, warn func(string, ...any)) {
	b, err := os.ReadFile(filepath.Join(d.State, "applied.json"))
	if err != nil {
		warn("lockfamily.yaml never applied: run lock up")
		return
	}
	var a Applied
	if json.Unmarshal(b, &a) != nil {
		warn("applied.json unreadable: run lock up")
		return
	}
	noKeys := func(s []string) []string {
		return slices.DeleteFunc(slices.Clone(s), func(l string) bool { return strings.Contains(l, " key ") })
	}
	if ch := diff(noKeys(a.Summary), noKeys(Summary(c, "", nil))); len(ch) > 0 {
		warn("lockfamily.yaml changed since the last lock up (run lock up to review it): %s", strings.Join(ch, "; "))
	}
}

// stack checks the compose project's containers and its internal network.
func (d *Doctor) stack(ctx context.Context, c *Config, ok, fail func(string, ...any)) {
	ws, _ := filepath.Abs(filepath.Dir(d.File))
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
			fail("%s not created: run lock up", s)
		default:
			fail("%s %s: docker compose -p %s -f %s logs %s", s, st, project, compose, s)
		}
	}
	// I2: no route out of the hub's network.
	net := project + "_lockhub"
	if out, err := d.Run.Run(ctx, nil, "docker", "network", "inspect", "--format", "{{.Internal}}", net); err != nil {
		fail("network %s: %v", net, err)
	} else if strings.TrimSpace(string(out)) != "true" {
		fail("network %s is not internal: the hub must have no route out (run lock up)", net)
	} else {
		ok("network %s internal", net)
	}
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
	fi, err := os.Lstat(d)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory (a link?)", d)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: owned by uid %d, not by you", d, st.Uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: mode %v, want 0700", d, fi.Mode().Perm())
	}
	return nil
}
