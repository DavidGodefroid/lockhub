package family

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/chatconf"
	"github.com/DavidGodefroid/lockhub/internal/keys"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// Runner runs a command (docker, cosign) and returns its stdout.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// Exec runs real commands.
type Exec struct{ Stderr io.Writer }

// Run implements Runner.
func (e Exec) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Nothing of the user's compose settings (COMPOSE_PROFILES would
	// start the setup services, COMPOSE_FILE add a file): lock up passes
	// everything compose needs.
	cmd.Env = slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "COMPOSE_") })
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	cmd.Stderr = e.Stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// Up is one `lock up`.
type Up struct {
	// File is lockfamily.yaml; its directory is the workspace.
	File string
	// State is the host directory lock up keeps per workspace
	// ($XDG_STATE_HOME/lockfamily/<id>), outside the projects directory.
	State string
	// Runtime is $XDG_RUNTIME_DIR (the facade socket's parent).
	Runtime string
	// Facades is the host-only directory of the host facades' keys
	// (FacadeKeysDir); empty: "facades" next to State.
	Facades string
	// User is the uid:gid the hub runs as (see Paths.User).
	User   string
	Run    Runner
	In     *bufio.Reader
	Out    io.Writer
	DryRun bool
	// Pin sets the hub image by digest (lock up --pin: a previous version
	// restored); lockfamily.yaml takes it once applied.
	Pin string
	// Rotate names the keys lock up --rotate replaces: "hub", lock
	// instances, "all".
	Rotate []string
	// Now is the clock (nil: time.Now).
	Now func() time.Time
}

// Project is the compose project of a workspace: one per workspace.
func Project(workspace string) string {
	s := sha256.Sum256([]byte(workspace))
	return "lockfamily-" + hex.EncodeToString(s[:4])
}

// Applied is what the last confirmed lock up applied.
type Applied struct {
	Fingerprint string   `json:"fingerprint"`
	Summary     []string `json:"summary"`
}

// Summary is the reviewable form of a configuration and its keys: every
// line that can change what the hub or a lock accepts.
// facadePubs are the keys of the host facades the locks pin, by facade
// (nil: none listed).
func Summary(c *Config, hubPub string, lockPubs map[string]string, facadePubs map[string]string) []string {
	var s []string
	s = append(s, "hub image "+c.Hub.Image, "hub key "+hubPub, "hub facades "+strings.Join(c.Hub.Facades, ","))
	for _, f := range HostFacades {
		if k, ok := facadePubs[f]; ok {
			s = append(s, fmt.Sprintf("facade %s key %s", f, k))
		}
	}
	if sl := c.Hub.Slack; sl != nil {
		s = append(s, fmt.Sprintf("hub slack team %s channel %s users %s", sl.Team, sl.Channel, strings.Join(sl.Users, ",")))
	}
	if tg := c.Hub.Telegram; tg != nil {
		for _, ch := range tg.Chats {
			s = append(s, fmt.Sprintf("hub telegram chat %d user %d", ch.Chat, ch.From))
		}
	}
	if m := c.Hub.Mobile; m != nil {
		s = append(s, fmt.Sprintf("hub mobile origin %s on 127.0.0.1:%d", m.Origin, m.Port))
		if m.Push {
			s = append(s, "hub mobile push on: the hub gets a route out (egress-hub) and POSTs payload-less pushes to "+PushServices)
		}
	}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		s = append(s, fmt.Sprintf("lock %s type %s", n, l.Type), fmt.Sprintf("lock %s image %s", n, l.Image),
			fmt.Sprintf("lock %s key %s", n, lockPubs[n]))
		if l.Profile != "" {
			s = append(s, fmt.Sprintf("lock %s profile %s", n, l.Profile))
		}
		if l.Reveal {
			s = append(s, fmt.Sprintf("lock %s pins the host facades' keys: Ctrl-O reveals its clear screen", n))
		}
		if m := c.Hub.Mobile; m != nil {
			if !l.Devices {
				s = append(s, fmt.Sprintf("lock %s pins no device: not answered on mobile", n))
			} else {
				s = append(s, fmt.Sprintf("lock %s pins the paired devices", n))
				if m.SealClear {
					s = append(s, fmt.Sprintf("lock %s seals its clear screens to them", n))
				}
				if len(m.RequireDevice) > 0 {
					s = append(s, fmt.Sprintf("lock %s accepts only device-signed approvals of %s", n, strings.Join(m.RequireDevice, ",")))
				}
			}
		}
		if fs, ok := c.Hub.Routing[n]; ok {
			s = append(s, fmt.Sprintf("lock %s routed only to %s", n, strings.Join(fs, ",")))
		}
	}
	return s
}

// PushServices are the push services the hub reaches with mobile push
// (the mobile facade refuses any other endpoint).
const PushServices = "fcm.googleapis.com, updates.push.services.mozilla.com, *.push.apple.com, wns2-*.notify.windows.com"

func fingerprint(lines []string) string {
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

// diff lists removed (-) and added (+) lines.
func diff(old, new []string) []string {
	var out []string
	for _, l := range old {
		if !slices.Contains(new, l) {
			out = append(out, "- "+l)
		}
	}
	for _, l := range new {
		if !slices.Contains(old, l) {
			out = append(out, "+ "+l)
		}
	}
	return out
}

// ErrNotConfirmed is the human declining the review.
var ErrNotConfirmed = errors.New("not applied: the change was not confirmed")

// Do runs lock up.
func (u *Up) Do(ctx context.Context) error {
	// Read once: what is reviewed is what a legacy file is adopted as.
	raw, err := readConfig(u.File)
	if err != nil {
		return err
	}
	c, err := decode(raw, u.File, true)
	if err != nil {
		return err
	}
	// --pin: the configuration reviewed and applied is the file with the
	// pinned hub image, written back once applied.
	pinned := false
	if u.Pin != "" {
		ref, err := PinRef(u.Pin)
		if err != nil {
			return err
		}
		if ref == c.Hub.Image {
			fmt.Fprintf(u.Out, "--pin: %s is the hub image already\n", ref)
		} else {
			old := c.Hub.Image
			if raw, err = setHubImage(raw, ref); err != nil {
				return fmt.Errorf("--pin: %s: %w", u.File, err)
			}
			if c, err = decode(raw, u.File, true); err != nil {
				return err
			}
			pinned = true
			fmt.Fprintf(u.Out, "--pin: the hub image becomes %s (was %s); %s takes it once applied\n", ref, old, u.File)
		}
		if !slices.Contains(hubImages(u.State), ref) {
			fmt.Fprintf(u.Out, "note: %s never ran in this workspace (see %s); cosign still checks it is a lockhub release\n", ref, filepath.Join(u.State, HubImagesFile))
		}
	}
	rot, err := parseRotate(c, u.Rotate)
	if err != nil {
		return err
	}
	// The workspace's canonical path (links resolved), as lea sees it:
	// the project, the consoles' working directory and the socket names
	// derive from it.
	ws, err := filepath.Abs(Workspace(Canonical(u.File)))
	if err != nil {
		return err
	}
	project := Project(ws)
	// Each lock's console reads its own profile, from the workspace: a
	// copy, reviewed below (profile.go).
	profiles := map[string]*Profile{}
	for _, t := range types(c) {
		k := Kinds[t]
		uid, _ := strconv.Atoi(k.UID)
		gid, _ := strconv.Atoi(k.GID)
		pr, err := ReadProfile(profileDir(ws, t), uid, gid)
		if err != nil {
			return fmt.Errorf("profile of the %s locks: %w (make it with %s's own tools, then lock up)", t, err, t)
		}
		if t == "locksql" && !pr.Has("pii/", ".toml") {
			// The copy is read-only: a console that must write its first
			// PII rule set there would not start.
			return fmt.Errorf("profile of the locksql locks: no PII rule set in %s: start the console once with locksql's own launcher (it writes .locksql/pii/<set>.toml after your review), then lock up",
				filepath.Join(profileDir(ws, t), "pii"))
		}
		profiles[t] = pr
	}
	hubData := filepath.Join(u.State, "hub")
	facadeDir := filepath.Join(u.Runtime, "lockhub")
	// Everything lock up writes and runs from lives in host-only
	// directories it owns: never in the workspace, which agents can write.
	facadeKeys := u.Facades
	if facadeKeys == "" {
		facadeKeys = filepath.Join(filepath.Dir(u.State), "facades")
	}
	for _, d := range []string{u.State, hubData, facadeDir, facadeKeys} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	composePath := filepath.Join(u.State, "compose.yaml")
	hubPubPath := filepath.Join(u.State, "hub.pub")
	appliedPath := filepath.Join(u.State, "applied.json")
	// The new hub key, made before the review (lockhub keygen) and kept
	// until it is the hub's.
	stage := filepath.Join(hubData, "rotate")
	attempted := filepath.Join(stage, "attempted")
	if _, err := os.Stat(attempted); err == nil && !rot.hub {
		return errors.New("a hub key rotation did not finish (the hub stays stopped): run lock up --rotate hub again to finish it")
	}
	if rot.any() {
		if _, err := os.Stat(appliedPath); err != nil {
			return errors.New("--rotate: nothing to rotate before the first lock up of this workspace")
		}
	}
	facadesPath := filepath.Join(u.State, FacadesFile)
	paths := Paths{Workspace: ws, HubData: hubData, FacadeDir: facadeDir, Facades: facadesPath, User: u.User, Rotate: rot.locks}
	devices, err := ReadDevices(u.State)
	if err != nil {
		return fmt.Errorf("paired devices: %w", err)
	}
	// Every lock carries the paired devices' identity: a device paired or
	// revoked recreates them (they read the file at start).
	paths.DevicesID = fingerprint(append([]string{"devices"}, devicesSummary(devices)...))
	snapPath, snapContent, err := devicesSnapshot(u.State, devices)
	if err != nil {
		return err
	}
	// The snapshot exists only once the human said yes: the compose files
	// before (keygen, hub-key) mount no devices.
	if len(devices) == 0 {
		snapPath = ""
		if m := c.Hub.Mobile; m != nil && len(m.RequireDevice) > 0 && c.anyDevices() {
			// Fail closed: without a device, the locks would take the hub's
			// approvals of these risk classes again.
			return fmt.Errorf("hub.mobile.require_device needs a paired device: lock up without it, lock mobile pair, then set it again")
		} else if m != nil && m.SealClear {
			fmt.Fprintln(u.Out, "note: hub.mobile.seal_clear takes effect once a device is paired (lock mobile pair, then lock up)")
		}
	}
	// The compose file goes to docker on stdin: nothing on disk to swap
	// before the human said yes. A copy is kept for reference afterwards.
	composeYAML := []byte(Compose(c, paths))
	// Pinned to the private state directory, with no env file: nothing in
	// the workspace or the current directory can feed compose.
	compose := func(args ...string) []string {
		return append([]string{"compose", "-p", project, "--project-directory", u.State, "--env-file", os.DevNull, "-f", "-"}, args...)
	}

	// 1. Images: every distinct pinned digest, signed by its own
	// repository's release workflow.
	type img struct{ repo, ref string }
	images := []img{{"lockhub", c.Hub.Image}}
	for _, n := range c.Instances() {
		images = append(images, img{c.Locks[n].Type, c.Locks[n].Image})
	}
	slices.SortFunc(images, func(a, b img) int { return strings.Compare(a.ref, b.ref) })
	images = slices.Compact(images)
	for _, im := range images {
		if _, err := u.Run.Run(ctx, nil, "cosign", "verify", "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
			"--certificate-identity-regexp", "^"+regexp.QuoteMeta("https://github.com/DavidGodefroid/"+im.repo+"/.github/workflows/release.yml@refs/tags/v"), im.ref); err != nil {
			return fmt.Errorf("image %s is not signed by its release: %w", im.ref, err)
		}
	}

	// 2. Keys: the hub's (created once in its data dir) and each lock's.
	hubPub, err := os.ReadFile(hubPubPath)
	if errors.Is(err, os.ErrNotExist) {
		out, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lockhub", "keygen", "--data", "/var/lib/lockhub")...)
		if err != nil {
			return fmt.Errorf("hub key: %w", err)
		}
		hubPub = out
		if err := os.WriteFile(hubPubPath, []byte(strings.TrimSpace(string(out))+"\n"), 0o644); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	hp := strings.TrimSpace(string(hubPub))
	if !validPub(hp) {
		return fmt.Errorf("hub key %s: not a base64 Ed25519 public key", hubPubPath)
	}
	oldHP := hp
	// Until the human's yes, a key made for --rotate is dropped when lock
	// up stops (declined, dry run, error): nothing of it is applied.
	confirmed := false
	defer func() {
		if confirmed {
			return
		}
		if rot.hub {
			if _, err := os.Stat(attempted); err != nil {
				os.RemoveAll(stage)
			}
		}
		for _, n := range rot.locks {
			u.Run.Run(context.WithoutCancel(ctx), composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "rotkey-"+n, "clear")...)
		}
	}()
	// A hub image without rotate-key cannot rotate, and refuses a log
	// whose key was rotated: found out now, not with the hub stopped.
	if hk, _ := readHubKeys(u.State); rot.hub || (pinned && len(hk) > 1) {
		help, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lockhub", "help")...)
		if err != nil || !strings.Contains(string(help), "rotate-key") || !strings.Contains(string(help), "pubkey") {
			if rot.hub {
				why := ""
				if err != nil {
					why = fmt.Sprintf(" (%v)", err)
				}
				return fmt.Errorf("--rotate hub: the hub image %s has no lockhub rotate-key%s: lock up --pin a newer lockhub first", c.Hub.Image, why)
			}
			return fmt.Errorf("--pin: %s predates hub key rotation and would refuse this hub's audit log (its key was rotated)", c.Hub.Image)
		}
	}
	hubRotated := false // a rotation that stopped after the hub took the key
	if rot.hub {
		nk, done, err := u.stageHubKey(ctx, composeYAML, compose, stage)
		if err != nil {
			return fmt.Errorf("new hub key: %w", err)
		}
		if nk == hp && !done {
			return errors.New("new hub key: lockhub keygen made the current key")
		}
		if done {
			// Ask the hub which key it holds, rather than trust the
			// stage's markers.
			out, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lockhub", "pubkey", "--data", "/var/lib/lockhub")...)
			if err != nil {
				return fmt.Errorf("hub key rotation: reading the hub's key: %w", err)
			}
			if got := strings.TrimSpace(string(out)); got != nk {
				return fmt.Errorf("hub key rotation: the hub holds %q, not the staged key %s (the hub stays stopped; look at %s)", got, nk, stage)
			}
		}
		hp, hubRotated = nk, done
	}
	// The host facades' keys (created once, host-only): the locks pin
	// their public halves, reviewed below like every other key. Until
	// the first apply, the locks' file pins none.
	facadePubs, err := EnsureFacadeKeys(facadeKeys)
	if err != nil {
		return err
	}
	if _, err := os.Stat(facadesPath); errors.Is(err, os.ErrNotExist) {
		if err := writeFacadeSet(facadesPath, nil); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	lockPubs := map[string]string{}
	for _, n := range c.Instances() {
		var out []byte
		var err error
		if Kinds[c.Locks[n].Type].Gate {
			// lockhttp: the gate's key, in the gate's own volume.
			if _, err = u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "gatehome-"+n)...); err == nil {
				out, err = u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "gatekey-"+n)...)
			}
		} else {
			out, err = u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lock-"+n, "hub-key", "--instance", n)...)
		}
		if err != nil {
			return fmt.Errorf("key of %s: %w", n, err)
		}
		k := strings.TrimSpace(string(out))
		if !validPub(k) {
			return fmt.Errorf("key of %s: not a base64 Ed25519 public key", n)
		}
		if slices.Contains(rot.locks, n) {
			nk, err := u.stageLockKey(ctx, c, n, composeYAML, compose)
			if err != nil {
				return fmt.Errorf("new key of %s: %w", n, err)
			}
			if nk == k {
				return fmt.Errorf("new key of %s: the lock gave its current key (its image does not make one under %s)", n, rotateDir)
			}
			k = nk
		}
		lockPubs[n] = k
	}

	// 3. Review with the human: everything on the first run, the change
	// afterwards. Nothing is applied without a yes.
	sum := append(Summary(c, hp, lockPubs, facadePubs), chatTokens(c, hubData)...)
	for _, t := range types(c) {
		sum = append(sum, fmt.Sprintf("profile %s %s %s", t, profileDir(ws, t), profiles[t].Fingerprint))
		for _, l := range profiles[t].Lines {
			sum = append(sum, fmt.Sprintf("profile %s %s", t, l))
		}
	}
	sum = append(sum, devicesSummary(devices)...)
	fp := fingerprint(sum)
	if rot.any() {
		var what []string
		if rot.hub {
			what = append(what, "the hub")
		}
		what = append(what, rot.locks...)
		fmt.Fprintf(u.Out, "--rotate: new keys for %s, made now and applied only on yes (the old private keys are deleted).\n", strings.Join(what, ", "))
		if rot.hub {
			fmt.Fprintln(u.Out, "  The hub stops while it takes its new key (logged, signed by both keys); every lock restarts to pin it.")
		} else {
			fmt.Fprintln(u.Out, "  The rotated locks restart.")
		}
		fmt.Fprintln(u.Out, "  A restarted console asks again for the credentials it does not take from Vault (lock attach).")
	}
	var prev Applied
	b, err := os.ReadFile(appliedPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintln(u.Out, "First lock up of this workspace. Review the whole configuration:")
		for _, l := range sum {
			fmt.Fprintln(u.Out, "  "+l)
		}
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(b, &prev); err != nil {
			return fmt.Errorf("%s: %w", appliedPath, err)
		}
	}
	if prev.Fingerprint == fp {
		fmt.Fprintln(u.Out, "configuration unchanged since the last lock up")
	} else {
		if prev.Fingerprint != "" {
			fmt.Fprintln(u.Out, "The configuration changed since the last lock up:")
			for _, l := range diff(prev.Summary, sum) {
				fmt.Fprintln(u.Out, "  "+l)
			}
		}
		if u.DryRun {
			fmt.Fprintln(u.Out, "dry run: nothing applied")
			return nil
		}
		fmt.Fprint(u.Out, "Apply? [y/N] ")
		a, _ := u.In.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(a)) != "y" {
			return ErrNotConfirmed
		}
	}
	if u.DryRun {
		return nil
	}
	confirmed = true
	if err := u.applyRotation(ctx, c, rot, composeYAML, compose, stage, attempted, oldHP, hp, hubRotated); err != nil {
		return err
	}

	// 4. Apply: the hub's lock list, then the stack.
	lj := map[string]map[string]map[string]string{"locks": {}}
	for n, k := range lockPubs {
		lj["locks"][n] = map[string]string{"public_key": k}
	}
	lb, _ := json.MarshalIndent(lj, "", "  ")
	if err := os.WriteFile(filepath.Join(hubData, "locks.json"), append(lb, '\n'), 0o600); err != nil {
		return err
	}
	rb, _ := json.MarshalIndent(Routes(c), "", "  ")
	if err := os.WriteFile(filepath.Join(hubData, "routing.json"), append(rb, '\n'), 0o600); err != nil {
		return err
	}
	cb, _ := json.MarshalIndent(chatconf.Settings{Slack: c.Hub.Slack, Telegram: c.Hub.Telegram}, "", "  ")
	if err := os.WriteFile(filepath.Join(hubData, chatconf.File), append(cb, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeFacadeSet(facadesPath, facadePubs); err != nil {
		return err
	}
	// The lock keys, for host facades to check what a lock sealed to
	// them (a revealed clear screen).
	warns, err := pinLockKeys(facadeKeys, project, ws, lockPubs)
	if err != nil {
		return err
	}
	for _, w := range warns {
		fmt.Fprintln(u.Out, "warning: lock keys:", w)
	}
	if snapPath != "" {
		// 0644 whatever the umask: the locks' console accounts read it
		// through a read-only bind mount.
		if err := writeAtomic(snapPath, snapContent, 0o644); err != nil {
			return err
		}
		paths.Devices = snapPath
	}
	paths.Config = fp
	paths.Profiles = map[string]string{}
	for t, pr := range profiles {
		paths.Profiles[t] = pr.Fingerprint
	}
	composeYAML = []byte(Compose(c, paths))
	// The profiles go on the setup service's stdin (they can hold
	// secrets; a process's arguments are public): compose reads this
	// confirmed file from the private state directory meanwhile.
	if err := u.copyProfiles(ctx, c, project, composeYAML, profiles); err != nil {
		return err
	}
	if _, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "hubkey", hp)...); err != nil {
		return fmt.Errorf("hub key for the locks: %w", err)
	}
	if _, err := u.Run.Run(ctx, composeYAML, "docker", compose("up", "-d", "--remove-orphans")...); err != nil {
		return err
	}
	// The consoles read their keys and the hub's at start: the ones whose
	// keys changed start again.
	if rot.any() {
		var svcs []string
		for _, n := range c.Instances() {
			if !Kinds[c.Locks[n].Type].Gate && (rot.hub || slices.Contains(rot.locks, n)) {
				svcs = append(svcs, "lock-"+n)
			}
		}
		if len(svcs) > 0 {
			if _, err := u.Run.Run(ctx, composeYAML, "docker", compose(append([]string{"up", "-d", "--no-deps", "--force-recreate"}, svcs...)...)...); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(composePath, composeYAML, 0o600); err != nil {
		return err
	}
	// Snapshots the locks no longer mount.
	if old, _ := filepath.Glob(filepath.Join(u.State, "devices-*.json")); len(old) > 0 {
		for _, f := range old {
			if f != snapPath {
				os.Remove(f)
			}
		}
	}
	ab, _ := json.MarshalIndent(Applied{Fingerprint: fp, Summary: sum}, "", "  ")
	if err := os.WriteFile(appliedPath, append(ab, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeHubKeys(u.State, hp); err != nil {
		return err
	}
	now := time.Now
	if u.Now != nil {
		now = u.Now
	}
	if err := recordHubImage(u.State, c.Hub.Image, now()); err != nil {
		return err
	}
	// --pin: lockfamily.yaml says what runs.
	if pinned {
		if err := writeFile(u.File, raw); err != nil {
			return fmt.Errorf("%s: the hub runs %s, but the file was not updated: %w", u.File, c.Hub.Image, err)
		}
	}
	// A legacy root lockfamily.yaml is copied into .lockfamily (lea's
	// agents only read it there), exactly what the human reviewed; the
	// human removes the root one.
	if Legacy(u.File) {
		nf := filepath.Join(ws, Dir, FileName)
		if err := ensureDir(nf); err != nil {
			return err
		}
		if _, err := os.Lstat(nf); errors.Is(err, os.ErrNotExist) {
			if err := writeFileMode(nf, raw, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(u.Out, "%s now lives in %s (lea's agents only read it there); remove %s\n", FileName, nf, u.File)
		}
	}
	st := NewUpState(c, project, ws, hp, devices)
	fs := facadeSet(facadePubs)
	st.FacadeKeys = &fs
	// The authoritative copy is lock up's own (host only); lea reads the
	// workspace's, checks it is the user's and that no one else can write
	// it, and checks every volume's labels with docker before mounting it.
	sb, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(filepath.Join(u.State, UpFile), append(sb, '\n'), 0o600); err != nil {
		return err
	}
	if err := writeUpState(ws, st); err != nil {
		return err
	}
	fmt.Fprintf(u.Out, "up: project %s, hub and %d lock(s)\n", project, len(lockPubs))
	if rot.hub {
		fmt.Fprintf(u.Out, "hub key rotated: lock audit verify takes --hub-key-file %s (every hub key, oldest first)\n", filepath.Join(u.State, HubKeysFile))
	}
	for _, n := range c.Instances() {
		if Kinds[c.Locks[n].Type].Gate && (rot.hub || slices.Contains(rot.locks, n)) {
			fmt.Fprintf(u.Out, "lea's gate for %s reads its keys at its start: restart it (lea) to take the new key\n", n)
		}
	}
	fmt.Fprintln(u.Out, "Each lock's console asks at its terminal for its policy (first start, or loosened) and the credentials it does not take from Vault:")
	for _, n := range c.Instances() {
		fmt.Fprintf(u.Out, "  lock attach %s\n", n)
	}
	return nil
}

// privateDir creates d (0700) if needed and refuses it unless it is a
// real directory (not a link) owned by this user with no access for
// group or others.
func privateDir(d string) error {
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	return checkPrivate(d)
}

// Routes is the hub's routing for c: hub.routing, and a lock that pins no
// device narrowed away from mobile (it would refuse every decision taken
// there).
func Routes(c *Config) route.Rules {
	r := route.Rules{Enabled: c.Hub.Facades, Only: map[string][]string{}}
	for inst, fs := range c.Hub.Routing {
		r.Only[inst] = slices.Clone(fs)
	}
	if slices.Contains(c.Hub.Facades, route.Mobile) {
		for _, n := range c.Instances() {
			if c.Locks[n].Devices {
				continue
			}
			fs, ok := r.Only[n]
			if !ok {
				fs = slices.Clone(c.Hub.Facades)
			}
			r.Only[n] = slices.DeleteFunc(fs, func(f string) bool { return f == route.Mobile })
		}
	}
	if len(r.Only) == 0 {
		r.Only = nil
	}
	return r
}

// anyDevices reports whether a lock pins the paired devices: a console
// lock up runs (--devices-file), or a lockhttp lock, whose gate (lea's,
// from up.json's devices; lockhttp v0.4.0 or later) pins them, since its
// console only serves the policy.
func (c *Config) anyDevices() bool {
	for _, l := range c.Locks {
		if l.Devices {
			return true
		}
	}
	return false
}

func validPub(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && keys.Public(b) == s
}

// copyProfiles copies each reviewed profile into its volume, the archive
// on the stdin of the setup service profile-<type>.
func (u *Up) copyProfiles(ctx context.Context, c *Config, project string, composeYAML []byte, profiles map[string]*Profile) error {
	f, err := os.CreateTemp(u.State, ".compose-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(composeYAML)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	for _, t := range types(c) {
		args := []string{"compose", "-p", project, "--project-directory", u.State, "--env-file", os.DevNull, "-f", f.Name(),
			"run", "--rm", "-T", "--no-deps", "profile-" + t}
		if _, err := u.Run.Run(ctx, profiles[t].Tar, "docker", args...); err != nil {
			return fmt.Errorf("profile of the %s locks: %w", t, err)
		}
	}
	return nil
}
