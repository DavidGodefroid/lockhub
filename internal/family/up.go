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
	"strings"

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
	// User is the uid:gid the hub runs as (see Paths.User).
	User   string
	Run    Runner
	In     *bufio.Reader
	Out    io.Writer
	DryRun bool
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
func Summary(c *Config, hubPub string, lockPubs map[string]string) []string {
	var s []string
	s = append(s, "hub image "+c.Hub.Image, "hub key "+hubPub, "hub facades "+strings.Join(c.Hub.Facades, ","))
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
		if m.SealClear {
			s = append(s, "locks seal clear screens to the paired devices")
		}
		if len(m.RequireDevice) > 0 {
			s = append(s, "locks accept only device-signed approvals of "+strings.Join(m.RequireDevice, ","))
		}
	}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		s = append(s, fmt.Sprintf("lock %s type %s", n, l.Type), fmt.Sprintf("lock %s image %s", n, l.Image),
			fmt.Sprintf("lock %s key %s", n, lockPubs[n]))
		if fs, ok := c.Hub.Routing[n]; ok {
			s = append(s, fmt.Sprintf("lock %s routed only to %s", n, strings.Join(fs, ",")))
		}
	}
	return s
}

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
	c, err := Load(u.File)
	if err != nil {
		return err
	}
	ws, _ := filepath.Abs(filepath.Dir(u.File))
	project := Project(ws)
	hubData := filepath.Join(u.State, "hub")
	facadeDir := filepath.Join(u.Runtime, "lockhub")
	// Everything lock up writes and runs from lives in host-only
	// directories it owns: never in the workspace, which agents can write.
	for _, d := range []string{u.State, hubData, facadeDir} {
		if err := privateDir(d); err != nil {
			return err
		}
	}
	composePath := filepath.Join(u.State, "compose.yaml")
	hubPubPath := filepath.Join(u.State, "hub.pub")
	paths := Paths{HubData: hubData, FacadeDir: facadeDir, HubPub: hubPubPath, User: u.User}
	devices, err := ReadDevices(u.State)
	if err != nil {
		return fmt.Errorf("paired devices: %w", err)
	}
	if len(devices) > 0 {
		paths.Devices = DevicesFile(u.State)
	} else if m := c.Hub.Mobile; m != nil && (m.SealClear || len(m.RequireDevice) > 0) {
		fmt.Fprintln(u.Out, "note: hub.mobile seal_clear and require_device take effect once a device is paired (lock mobile pair, then lock up)")
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
	lockPubs := map[string]string{}
	for _, n := range c.Instances() {
		out, err := u.Run.Run(ctx, composeYAML, "docker", compose("run", "--rm", "-T", "--no-deps", "lock-"+n, "hub-key", "--instance", n)...)
		if err != nil {
			return fmt.Errorf("key of %s: %w", n, err)
		}
		k := strings.TrimSpace(string(out))
		if !validPub(k) {
			return fmt.Errorf("key of %s: not a base64 Ed25519 public key", n)
		}
		lockPubs[n] = k
	}

	// 3. Review with the human: everything on the first run, the change
	// afterwards. Nothing is applied without a yes.
	sum := append(Summary(c, hp, lockPubs), chatTokens(c, hubData)...)
	sum = append(sum, devicesSummary(devices)...)
	fp := fingerprint(sum)
	appliedPath := filepath.Join(u.State, "applied.json")
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

	// 4. Apply: the hub's lock list, then the stack.
	lj := map[string]map[string]map[string]string{"locks": {}}
	for n, k := range lockPubs {
		lj["locks"][n] = map[string]string{"public_key": k}
	}
	lb, _ := json.MarshalIndent(lj, "", "  ")
	if err := os.WriteFile(filepath.Join(hubData, "locks.json"), append(lb, '\n'), 0o600); err != nil {
		return err
	}
	rb, _ := json.MarshalIndent(route.Rules{Enabled: c.Hub.Facades, Only: c.Hub.Routing}, "", "  ")
	if err := os.WriteFile(filepath.Join(hubData, "routing.json"), append(rb, '\n'), 0o600); err != nil {
		return err
	}
	cb, _ := json.MarshalIndent(chatconf.Settings{Slack: c.Hub.Slack, Telegram: c.Hub.Telegram}, "", "  ")
	if err := os.WriteFile(filepath.Join(hubData, chatconf.File), append(cb, '\n'), 0o600); err != nil {
		return err
	}
	paths.Config = fp
	composeYAML = []byte(Compose(c, paths))
	if _, err := u.Run.Run(ctx, composeYAML, "docker", compose("up", "-d", "--remove-orphans")...); err != nil {
		return err
	}
	if err := os.WriteFile(composePath, composeYAML, 0o600); err != nil {
		return err
	}
	ab, _ := json.MarshalIndent(Applied{Fingerprint: fp, Summary: sum}, "", "  ")
	if err := os.WriteFile(appliedPath, append(ab, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(u.Out, "up: project %s, hub and %d lock(s)\n", project, len(lockPubs))
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

func validPub(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && keys.Public(b) == s
}
